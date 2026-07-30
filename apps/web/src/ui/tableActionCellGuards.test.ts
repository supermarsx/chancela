/**
 * Structural guards on the shared table action cell (t64 → t121).
 *
 * ## What this protects
 *
 * A `<td>` whose content is per-row controls must stay a **table cell**. The helper this lane
 * deleted did not: it set `display: flex` on the `<td>` itself, which makes a row's geometry a
 * property of whichever action that row happens to render. Rows switch between icon-only actions,
 * worded confirm/pending actions, a two-button confirm pair, an em dash, and — on the caller's own
 * session — no control at all, so the column went ragged in exactly the way that was reported.
 *
 * `.rbac-action-cell`/`.rbac-actions` (t64) fixed one table and got a feature-scoped name, so the
 * next six tables read it as somebody else's and reached for the users-page helper instead. That
 * is the recurrence mechanism `docs/ui-spacing.md` names: **two class names for one affordance**.
 * `c21d8dcb` generalised the pair into `.table-action-cell` / `.table-actions`; this lane migrated
 * the last thirteen call sites across twelve tables and **deleted** the helper rather than
 * deprecating it, because while a rule exists it can be reached for again — and a per-surface
 * helper always outranks the shared one exactly where somebody already complained.
 *
 * Measured in headless Chromium against the real sheet, in both colour schemes (a margin- and
 * layout-only change, so light and dark are identical throughout). The defect is the SPREAD of the
 * control's right edge within one table: signing invites measured 534 / 225 / 380px across its
 * three row states, delegations 400 / 285 / 298px, api keys 540 / 230 / 345px. Every migrated cell
 * now measures a single 9.59px, and `.btn` heights converge on the 2.25rem control step
 * (35px/30.78px → 36px, icon actions 30.78px → a 36px square).
 *
 * ## What it asserts
 *
 *  1. the two retired helper names **declare nothing** in ANY stylesheet, comments stripped;
 *  2. **no component** puts a retired name in a `className` — read from the TypeScript AST, since
 *     both names survive in explanatory prose and a text search cannot tell a comment from code;
 *  3. the shared rules exist at their frozen steps, including the ≤720px block;
 *  4. the real invariant, and the one that would have caught the original defect: **no rule whose
 *     subject is a class the component tree puts on a `<td>`/`<th>` takes that cell out of table
 *     layout**, beyond a frozen, named inventory of two pre-existing ones.
 *
 * ## Why source analysis rather than a rendered assertion
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting a row and
 * reading the cell's `display` passes whether or not any rule exists — it would have passed on the
 * defect this file exists to prevent. Both populations are therefore read from the two sources
 * that actually decide the outcome, the stylesheets and the component tree, and the last section
 * proves every predicate goes red against copies of those sources with the fix undone.
 */
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';

// --- the two retired names -----------------------------------------------------------------

/**
 * Deleted, not deprecated. `users-actions` was the flex-ified `<td>` helper; `rbac-actions` and
 * `rbac-action-cell` are what the shared pair was renamed from (t64), and `entities-table__actions`
 * was a modifier that only ever existed to adjust the flex helper it was paired with — measured at
 * the real 6.5rem `--ec-actions` column, its `flex-wrap: nowrap` computed `wrap` either way
 * (it lost the source-order tie at equal specificity) and its `justify-content: flex-end` is what
 * `.table-actions` already declares.
 */
const RETIRED_HELPERS = [
  'users-actions',
  'entities-table__actions',
  'rbac-actions',
  'rbac-action-cell',
] as const;

/**
 * The `<td>`/`<th>` classes that a stylesheet rule takes out of table layout, frozen by name.
 *
 * **Neither is an action cell**, which is why this lane left them and registered them instead —
 * the same treatment `docs/ui-spacing.md` gave `.data-status-table`'s margin, so that a third one
 * is a decision rather than drift:
 *
 * - `.data-status-table__tags` is a content cell of tag spans whose `> span + span` separators are
 *   themselves guarded by `DataManagementSection.test.tsx` (adjacent tags must not read as one).
 * - `.pdf-validator-actions-cell` IS an action cell and is the same shape as the deleted helper,
 *   at `display: inline-flex`. It has exactly one call site with exactly one row state, so it has
 *   no ragged column to show; migrating it was not in this lane's brief and is the obvious
 *   follow-up. Registered here so it cannot be forgotten and a fourth cannot appear quietly.
 */
const KNOWN_NON_TABLE_CELL_CLASSES = ['data-status-table__tags', 'pdf-validator-actions-cell'];

/** Declarations that stop a `<td>` behaving as a table cell. */
const NON_TABLE_DISPLAYS = ['flex', 'inline-flex', 'grid', 'inline-grid', 'block', 'inline-block'];

// --- CSS ------------------------------------------------------------------------------------

interface CssRule {
  sheet: string;
  selector: string;
  body: string;
}

/** Brace-depth tokeniser, descending into `@media`/`@supports` — a flat regex mis-parses those. */
function parseRules(css: string, sheet: string): CssRule[] {
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
      } else if (ch === '}') prelude = '';
      else prelude += ch;
      continue;
    }
    if (ch === '{') depth += 1;
    if (ch === '}') {
      depth -= 1;
      if (depth === 0) {
        const selector = prelude.trim();
        prelude = '';
        if (selector.startsWith('@')) rules.push(...parseRules(block, sheet));
        else if (selector) rules.push({ sheet, selector, body: block });
        continue;
      }
    }
    block += ch;
  }
  return rules;
}

const selectorList = (rule: CssRule): string[] =>
  rule.selector
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

/**
 * The classes on a selector's **subject** — the rightmost compound, which is the element the
 * declarations land on. Functional pseudo-classes are stripped first: `:not(…)`/`:has(…)` carry
 * class names that are not the subject, and reading them as one is the mistake Pass 5's guard had
 * to learn by going red.
 */
function subjectClasses(selector: string): string[] {
  const stripped = selector.replace(/:(?:not|is|where|has|matches)\([^)]*\)/gu, '');
  const last =
    stripped
      .trim()
      .split(/[\s>+~]+/u)
      .filter(Boolean)
      .pop() ?? '';
  return [...last.matchAll(/\.([\w-]+)/gu)].map((m) => m[1]);
}

/**
 * The body of the `@media` block with the given prelude that contains `needle`, brace-matched.
 * The sheet carries several blocks per breakpoint, so "the one at this breakpoint" is ambiguous
 * and a non-greedy slice silently picks the wrong one.
 */
function mediaBlock(prelude: string, needle: string): string {
  const marker = `@media ${prelude}`;
  for (let at = THEME.indexOf(marker); at !== -1; at = THEME.indexOf(marker, at + 1)) {
    const open = THEME.indexOf('{', at);
    let depth = 0;
    for (let i = open; i < THEME.length; i += 1) {
      if (THEME[i] === '{') depth += 1;
      else if (THEME[i] === '}') {
        depth -= 1;
        if (depth === 0) {
          const body = THEME.slice(open + 1, i);
          if (body.includes(needle)) return body;
          break;
        }
      }
    }
  }
  return '';
}

const declaredDisplay = (body: string): string | null =>
  /(?:^|;)\s*display\s*:\s*([\w-]+)/u.exec(body)?.[1] ?? null;

/** Every class name any rule in any sheet declares anything for. */
function declaredClasses(rules: CssRule[]): Set<string> {
  const out = new Set<string>();
  for (const rule of rules) for (const m of rule.selector.matchAll(/\.([\w-]+)/gu)) out.add(m[1]);
  return out;
}

/**
 * EVERY stylesheet, not just `theme.css`, and read through `node:fs` rather than
 * `import.meta.glob(…, { query: '?raw' })` — measured, the glob resolves the paths but Vite's CSS
 * pipeline claims the modules first and every value comes back empty, so the sweep would parse
 * zero rules and pass vacuously. The indirection through a variable is the suite's existing idiom
 * for reaching `node:fs` from a project with no `@types/node`.
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

// --- the component tree ----------------------------------------------------------------------

interface ClassUse {
  file: string;
  tag: string;
  classes: string[];
}

/**
 * Every `className` in the tree, with the tag it sits on, read from the AST.
 *
 * Not grepped, and the reason is this file's own subject matter: both retired names still appear
 * in explanatory prose — in this file, in `theme.css`'s section comment, in `EditUserPage`'s
 * diagnosis of t103, and in two negative assertions in the feature suites. A text search reports
 * all of them and cannot tell a live `className` from a sentence about one.
 *
 * Template literals contribute their static chunks and are descended into, so a computed
 * `` `btn ${x}` `` still yields `btn`; `cx('a', cond ? 'b' : 'c')` yields all three.
 */
function scanClassNames(sources: Record<string, string>): ClassUse[] {
  const uses: ClassUse[] = [];
  for (const [file, text] of Object.entries(sources)) {
    const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxOpeningLikeElement(node)) {
        const tag = node.tagName.getText(source);
        for (const attr of node.attributes.properties) {
          if (!ts.isJsxAttribute(attr) || attr.name.getText(source) !== 'className') continue;
          const literals: string[] = [];
          const collect = (n: ts.Node): void => {
            if (ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n))
              literals.push(n.text);
            else if (ts.isTemplateExpression(n)) {
              literals.push(n.head.text, ...n.templateSpans.map((s) => s.literal.text));
              n.templateSpans.forEach((s) => collect(s.expression));
            } else n.forEachChild(collect);
          };
          if (attr.initializer) collect(attr.initializer);
          const classes = literals.flatMap((l) => l.split(/\s+/u).filter(Boolean));
          if (classes.length) uses.push({ file, tag, classes });
        }
      }
      node.forEachChild(visit);
    };
    visit(source);
  }
  return uses;
}

const PRODUCTION_SOURCES = Object.fromEntries(
  Object.entries(
    import.meta.glob('../**/*.tsx', { eager: true, import: 'default', query: '?raw' }) as Record<
      string,
      string
    >,
  ).filter(([path]) => !path.includes('.test.')),
);

const CLASS_USES = scanClassNames(PRODUCTION_SOURCES);
const CELL_USES = CLASS_USES.filter((u) => u.tag === 'td' || u.tag === 'th');
/** Every class the tree ever puts on a table cell. This is the population clause 4 sweeps. */
const CELL_CLASSES = [...new Set(CELL_USES.flatMap((u) => u.classes))].sort();
const ACTION_ROWS = CLASS_USES.filter((u) => u.classes.includes('table-actions'));
const ACTION_CELLS = CELL_USES.filter((u) => u.classes.includes('table-action-cell'));

let STYLESHEETS: Record<string, string> = {};
let ALL_RULES: CssRule[] = [];
let THEME = '';

beforeAll(async () => {
  STYLESHEETS = await readStylesheets();
  ALL_RULES = Object.entries(STYLESHEETS).flatMap(([sheet, css]) => parseRules(css, sheet));
  THEME = STYLESHEETS['src/theme.css'] ?? '';
});

// --- predicates, shared with the red-proof at the bottom --------------------------------------

const retiredHelpersStillDeclared = (rules: CssRule[]): string[] => {
  const declared = declaredClasses(rules);
  return RETIRED_HELPERS.filter((name) => declared.has(name));
};

const componentsUsingRetiredHelpers = (uses: ClassUse[]): string[] =>
  uses
    .filter((u) => u.classes.some((c) => (RETIRED_HELPERS as readonly string[]).includes(c)))
    .map((u) => `${u.file} <${u.tag} class="${u.classes.join(' ')}">`)
    .sort();

const cellsTakenOutOfTableLayout = (rules: CssRule[], cellClasses: string[]): string[] => {
  const out: string[] = [];
  for (const rule of rules) {
    const display = declaredDisplay(rule.body);
    if (!display || !NON_TABLE_DISPLAYS.includes(display)) continue;
    for (const selector of selectorList(rule)) {
      const hits = subjectClasses(selector).filter((c) => cellClasses.includes(c));
      for (const hit of hits)
        out.push(`${hit} (${rule.sheet}: ${selector} { display: ${display} })`);
    }
  }
  return [...new Set(out)].sort();
};

// --- 1. the retired helpers are gone ----------------------------------------------------------

describe('the retired per-row action helpers are deleted, not deprecated', () => {
  it('declares nothing for either name in any stylesheet', () => {
    expect(retiredHelpersStillDeclared(ALL_RULES)).toEqual([]);
  });

  it('sweeps every stylesheet, not just the shared one', () => {
    // Non-vacuity: a sweep that found no sheets, or parsed no rules out of them, would pass the
    // assertion above while proving nothing. This is the Pass 5 lesson, kept.
    expect(Object.keys(STYLESHEETS)).toContain('src/theme.css');
    expect(Object.keys(STYLESHEETS).length).toBeGreaterThanOrEqual(2);
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(1000);
  });

  it('has no component reaching for a retired name', () => {
    expect(componentsUsingRetiredHelpers(CLASS_USES)).toEqual([]);
  });

  it('walked a real component tree', () => {
    // The bound that makes the clause above mean something: `menuItemGuards`' transferable
    // finding is that a recogniser used as a filter cannot see what it fails to recognise, and a
    // className scan that silently matched nothing would report an empty offender list too.
    expect(Object.keys(PRODUCTION_SOURCES).length).toBeGreaterThanOrEqual(100);
    expect(CLASS_USES.length).toBeGreaterThanOrEqual(500);
    expect(CELL_CLASSES.length).toBeGreaterThanOrEqual(20);
  });
});

// --- 2. the shared affordance exists, at its frozen steps --------------------------------------

describe('the shared table action cell', () => {
  const ruleFor = (selector: string): CssRule | undefined =>
    ALL_RULES.find((r) => selectorList(r).includes(selector));

  it('keeps the cell a real table cell and right-aligns it', () => {
    const cell = ruleFor('.table-action-cell');
    expect(cell?.body).toMatch(/text-align:\s*right;/u);
    // The one declaration it must NOT have: the defect was a `display` on the `<td>`.
    expect(declaredDisplay(cell?.body ?? '')).toBeNull();
  });

  it('lays the controls out in a dedicated inner row', () => {
    const row = ruleFor('.table-actions');
    expect(row?.body).toMatch(/display:\s*flex;/u);
    expect(row?.body).toMatch(/flex-wrap:\s*wrap;/u);
    expect(row?.body).toMatch(/align-items:\s*center;/u);
    expect(row?.body).toMatch(/justify-content:\s*flex-end;/u);
    expect(row?.body).toMatch(/gap:\s*0\.4rem;/u);
    // Without this a long worded action stretches the column instead of wrapping inside it.
    expect(row?.body).toMatch(/min-width:\s*0;/u);
  });

  it('gives every control the one 2.25rem step, square for icon-only actions', () => {
    // This is what makes an icon-only row and a worded row the same height: measured, the
    // migration moved `.btn` 35px → 36px and icon actions 30.78px → a 36px square.
    expect(ruleFor('.table-actions .btn')?.body).toMatch(/min-height:\s*2\.25rem;/u);
    expect(ruleFor('.table-actions .btn')?.body).toMatch(/max-width:\s*100%;/u);
    const iconOnly = ruleFor('.table-actions .btn--iconOnly');
    expect(iconOnly?.body).toMatch(/width:\s*2\.25rem;/u);
    expect(iconOnly?.body).toMatch(/min-width:\s*2\.25rem;/u);
    // An `IconButton` renders inside a `<span class="tooltip">`, so the flex item is the wrapper
    // and not the button; without this the wrapper grows and the square stops being square.
    expect(ruleFor('.table-actions .tooltip')?.body).toMatch(/flex:\s*0 0 auto;/u);
  });

  it('flips to a left-aligned, wrapping row below 720px', () => {
    // Measured at 700px: the migrated cells resolve `text-align: left` and `flex-start`.
    //
    // Brace-matched, not regex-sliced. This sheet has SEVEN `@media (max-width: 720px)` blocks
    // and a `[\s\S]*?\n\}` slice stops at the first `}` in column zero — which is the end of the
    // FIRST block, so the assertions ran against an unrelated one and reported `undefined`.
    const scoped = parseRules(mediaBlock('(max-width: 720px)', '.table-action-cell'), 'media');
    expect(scoped.find((r) => r.selector === '.table-action-cell')?.body).toMatch(
      /text-align:\s*left;/u,
    );
    expect(scoped.find((r) => r.selector === '.table-actions')?.body).toMatch(
      /justify-content:\s*flex-start;/u,
    );
    expect(
      scoped.find((r) => r.selector === '.table-actions .btn:not(.btn--iconOnly)')?.body,
    ).toMatch(/overflow-wrap:\s*anywhere;/u);
  });

  it('is the affordance the tables actually use', () => {
    // The non-vacuity bound, at today's exact counts so a silent shrink fails rather than
    // passing quietly: 18 inner action rows — the six the shared classes already had (four in
    // `RolesSection`, one in `RoleAssignmentManager`, the sessions cell in `EditUserPage`) plus
    // the twelve this migration converted — and 13 cells carrying the class. The two numbers
    // differ deliberately: the entities cell keeps its own column-system class instead, and the
    // retention-execution cell omits the right-alignment half on purpose (see its comment).
    expect(ACTION_ROWS.length).toBeGreaterThanOrEqual(18);
    expect(ACTION_CELLS.length).toBeGreaterThanOrEqual(13);
    // Every `.table-action-cell` is on a `<td>` — the class names the cell, so putting it on a
    // wrapper would silently move the right-alignment off the column.
    expect(ACTION_CELLS.every((u) => u.tag === 'td')).toBe(true);
  });
});

// --- 3. the invariant: a table cell stays a table cell -----------------------------------------

describe('no stylesheet takes a table cell out of table layout', () => {
  it('freezes the inventory at the two known non-action cells', () => {
    const offenders = cellsTakenOutOfTableLayout(ALL_RULES, CELL_CLASSES);
    expect(offenders.map((o) => o.split(' ')[0])).toEqual(KNOWN_NON_TABLE_CELL_CLASSES.sort());
  });

  it('would see a rule in any sheet, at any nesting', () => {
    // The population is the classes the TREE puts on a cell, not a list of names typed here —
    // which is what makes this clause able to catch a helper nobody has invented yet. It is also
    // why it is walked rather than grepped: `.chronology-analytics` was missed by a by-hand sweep
    // of call sites in Pass 4 and found only by the walk.
    expect(CELL_CLASSES).toContain('table-action-cell');
    expect(CELL_CLASSES.length).toBeGreaterThanOrEqual(20);
    expect(CELL_CLASSES).not.toContain('users-actions');
  });
});

// --- 4. red-proof, and the non-vacuity bounds --------------------------------------------------

describe('the guards go red when the fix is undone', () => {
  it('reports the deleted helper if its rule is put back', () => {
    const revived = [
      ...ALL_RULES,
      { sheet: 'src/theme.css', selector: '.users-actions', body: 'display:flex;gap:0.4rem;' },
    ];
    expect(retiredHelpersStillDeclared(revived)).toEqual(['users-actions']);
    // …and the paired entities modifier, which is the one a "tidy-up" would most plausibly leave.
    const halfRevived = [
      ...ALL_RULES,
      { sheet: 'src/theme.css', selector: '.entities-table__actions', body: 'flex-wrap:nowrap;' },
    ];
    expect(retiredHelpersStillDeclared(halfRevived)).toEqual(['entities-table__actions']);
  });

  it('reports a component that reaches for the deleted helper again', () => {
    const regressed: ClassUse[] = [
      ...CLASS_USES,
      { file: 'src/features/x/XPage.tsx', tag: 'td', classes: ['users-actions'] },
    ];
    expect(componentsUsingRetiredHelpers(regressed)).toEqual([
      'src/features/x/XPage.tsx <td class="users-actions">',
    ]);
  });

  it('reports a NEW flex-ified cell under a name nobody has used yet', () => {
    // The point of clause 3: it is not a list of forbidden names. A fresh helper on a cell the
    // tree already renders fails immediately.
    const invented = [
      ...ALL_RULES,
      { sheet: 'src/theme.css', selector: '.table-action-cell', body: 'display: flex;' },
    ];
    const offenders = cellsTakenOutOfTableLayout(invented, CELL_CLASSES);
    expect(offenders.some((o) => o.startsWith('table-action-cell'))).toBe(true);
  });

  it('does not mistake a `:has()` or `:not()` argument for the selector subject', () => {
    // Pass 5's guard had to learn this by going red: the class inside a functional pseudo-class is
    // not the element the declarations land on, and reading it as one reports the rule whose whole
    // purpose is to avoid a regression.
    const decoy = [
      {
        sheet: 'src/theme.css',
        selector: '.panel:has(.table-action-cell) .stack',
        body: 'display: flex;',
      },
    ];
    expect(cellsTakenOutOfTableLayout(decoy, CELL_CLASSES)).toEqual([]);
  });

  it('sees a rule nested inside a media query', () => {
    const nested = parseRules(
      '@media (max-width: 720px) { .table-action-cell { display: flex; } }',
      's',
    );
    expect(cellsTakenOutOfTableLayout(nested, CELL_CLASSES).length).toBe(1);
  });
});
