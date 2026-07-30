/**
 * Structural guards on the multi-line control (t89, textarea pass).
 *
 * ## What went wrong, and why nothing caught it
 *
 * `TextArea` rendered `<textarea className="control control--textarea" {...props} />`. JSX spread
 * is last-wins, so a caller passing its own `className` did not add a class — it **replaced both
 * shared ones**, and the element rendered as an unthemed native textarea: no border, no fill, no
 * `width: 100%`, no radius, no padding, no focus ring, no disabled treatment. Three production
 * call sites were in that state, and a fourth had already worked around it by restating
 * `control control--textarea` by hand, which is the tell. `Input` and `Select` have always merged.
 *
 * Nothing failed, because a class attribute is invisible to this suite's usual assertions and
 * jsdom does not apply stylesheet declarations to `getComputedStyle` — so mounting the component
 * and reading its border passes whether or not any rule reaches it. The guards below therefore
 * assert against the two sources that actually decide the outcome: the rendered class attribute
 * (which jsdom DOES model), and the stylesheet text.
 *
 * The last describe proves each predicate goes red with the fix taken back out — the same shape as
 * `bannerMarginGuards.test.ts` and `containerRhythmGuards.test.ts`, for the same reason.
 */
import { render } from '@testing-library/react';
import { createElement } from 'react';
import ts from 'typescript';
import { beforeAll, describe, expect, it } from 'vitest';
import { TextArea } from './index';

async function readTheme(): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
}

/** The body of one top-level rule, by exact selector. `undefined` when the rule is gone. */
function ruleBody(css: string, selector: string): string | undefined {
  const source = css.replace(/\/\*[\s\S]*?\*\//gu, '');
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  return new RegExp(`(?:^|\\})\\s*${escaped}\\s*\\{([^}]*)\\}`, 'u').exec(source)?.[1];
}

/** Every `<textarea>`/`<TextArea>` in production TSX, with the class expression it was given. */
function scanTextareas(sources: Record<string, string>): {
  total: number;
  files: number;
  /** Raw `<textarea>` elements that do not spell both shared classes themselves. */
  unclassedRaw: string[];
  /** Call sites still restating a class the component now supplies. */
  restated: string[];
} {
  let total = 0;
  let files = 0;
  const unclassedRaw: string[] = [];
  const restated: string[] = [];
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
      if (ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) {
        const tag = node.tagName.getText(parsed);
        if (tag === 'textarea' || tag === 'TextArea') {
          total += 1;
          const attr = node.attributes.properties.find(
            (p): p is ts.JsxAttribute =>
              ts.isJsxAttribute(p) && ts.isIdentifier(p.name) && p.name.text === 'className',
          );
          const text = attr?.initializer?.getText(parsed) ?? '';
          // Split on everything a class name cannot contain, so `operations-code-control` stays
          // one token rather than reading as the shared `control` with a prefix.
          const classes = new Set(text.split(/[^\w-]+/u));
          const where = `${file}:${tag}`;
          if (tag === 'textarea' && !/control control--textarea/u.test(text))
            unclassedRaw.push(where);
          if (tag === 'TextArea' && (classes.has('control') || classes.has('control--textarea'))) {
            restated.push(where);
          }
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(parsed);
  }
  return { total, files, unclassedRaw, restated };
}

const PRODUCTION_SOURCES = import.meta.glob('../**/*.tsx', {
  eager: true,
  import: 'default',
  query: '?raw',
}) as Record<string, string>;

const TEXTAREAS = scanTextareas(PRODUCTION_SOURCES);

let THEME = '';

beforeAll(async () => {
  THEME = await readTheme();
});

describe('the multi-line control — structural guards', () => {
  it('sweeps a population rather than passing over nothing', () => {
    // The bound that would have caught a recogniser silently dropping the call sites it cannot
    // parse — the transferable lesson from `menuItemGuards.test.ts`.
    expect(TEXTAREAS.total).toBeGreaterThanOrEqual(50);
    expect(TEXTAREAS.files).toBeGreaterThan(150);
  });

  it('merges a caller’s className instead of replacing the shared classes', () => {
    const { container } = render(createElement(TextArea, { className: 'mono', readOnly: true }));
    const el = container.querySelector('textarea');
    expect(el).not.toBeNull();
    expect(
      [...(el?.classList ?? [])].sort(),
      'A caller’s class replaced `control control--textarea`, so this textarea renders with no ' +
        'border, fill, width, radius, padding, focus ring or disabled treatment. Merge the ' +
        'className the way `Input` and `Select` do; do not ask call sites to restate both.',
    ).toEqual(['control', 'control--textarea', 'mono']);
  });

  it('gives a textarea a default height when the caller asks for none', () => {
    const { container } = render(createElement(TextArea, { readOnly: true }));
    expect(container.querySelector('textarea')?.getAttribute('rows')).toBe('3');
  });

  it('lets a caller that specifies rows keep exactly what it asked for', () => {
    for (const rows of [2, 6, 16]) {
      const { container } = render(createElement(TextArea, { rows, readOnly: true }));
      expect(container.querySelector('textarea')?.getAttribute('rows')).toBe(String(rows));
    }
  });

  it('leaves no call site restating a class the component supplies', () => {
    expect(
      TEXTAREAS.restated,
      'A call site spelling `control`/`control--textarea` on a `<TextArea>` is working around a ' +
        'component that drops its classes — the workaround that hid this defect the first time. ' +
        'Pass only the extra class.',
    ).toEqual([]);
  });

  it('keeps the two raw textareas carrying the shared classes themselves', () => {
    // Two call sites render a native textarea rather than the component (one needs a ref for JS
    // auto-resize, one a computed `rows`). They opt out of the component, not out of the theme.
    expect(TEXTAREAS.unclassedRaw).toEqual([]);
  });

  it('keeps the height floor derived from the line box and the control’s own padding', () => {
    expect(
      ruleBody(THEME, '.control--textarea'),
      '`.control--textarea` is gone; a textarea would fall back to the UA’s monospace face.',
    ).toMatch(/resize:\s*vertical;/u);
    expect(
      ruleBody(THEME, ':where(.control--textarea)'),
      'The height floor must stay expressed in `lh` plus the control’s own padding token, not a ' +
        'pixel constant: it is exactly two lines of text plus this control’s chrome, which is the ' +
        'smallest `rows` any call site asks for. A larger floor would override those callers, and ' +
        'a constant would drift the moment `.control`’s padding moves.',
    ).toMatch(/min-height:\s*calc\(2lh \+ var\(--control-padding-block\) \* 2 \+ 2px\);/u);
  });

  it('keeps the floor at zero specificity, so a caller’s own size always wins', () => {
    // A floor that can outrank a caller is a mandate. At (0,1,0) this rule would TIE
    // `.operations-code-control { min-height: 14rem }` and be decided by Vite's chunk order.
    expect(ruleBody(THEME, '.control--textarea') ?? '').not.toMatch(/min-height/u);
    expect(ruleBody(THEME, ':where(.control--textarea)')).toBeDefined();
  });

  it('keeps the padding token reachable, and every consumer consuming it', () => {
    // At `:root`, not on `.control`: `.menu-item` takes its row metric from `.control`'s padding
    // by design (7bb5dcd8) and is not inside a control, so a token scoped to `.control` would
    // resolve to nothing there and collapse every hand-built menu row to zero padding.
    expect(
      ruleBody(THEME, ':root'),
      'The token moved out of `:root`; `.menu-item` cannot reach a token scoped to `.control`.',
    ).toMatch(/--control-padding-block:\s*0\.55rem;/u);
    expect(
      ruleBody(THEME, '.control'),
      '`.control` stopped consuming the token its textarea floor is derived from, so the two can ' +
        'now disagree silently.',
    ).toMatch(/padding:\s*var\(--control-padding-block\) /u);
    expect(
      ruleBody(THEME, '.menu-item'),
      '`.menu-item` stopped tracking `.control`; see menuItemGuards.test.ts for why it must.',
    ).toMatch(/padding:\s*var\(--control-padding-block\) /u);
  });

  it('does not let the textarea restate what `.control` already owns', () => {
    // A textarea and the input beside it must read as one component. Anything here that also
    // appears on `.control` is a second copy that can drift.
    const body = ruleBody(THEME, '.control--textarea') ?? '';
    for (const property of ['width', 'color', 'background', 'border', 'border-radius', 'padding']) {
      expect(
        body,
        `.control--textarea restates \`${property}\`, which is \`.control\`'s.`,
      ).not.toMatch(new RegExp(`(?:^|[;{\\s])${property}\\s*:`, 'u'));
    }
  });

  it('gives the mono variant a real monospace face', () => {
    // `.mono` alone loses: it is declared above `.control`, both are (0,1,0), so `.control`'s
    // `font-family` wins on source order and a "monospace" textarea renders in the body serif.
    expect(
      ruleBody(THEME, '.control.mono'),
      'Without a two-class rule, `.mono` on a control is inert and the mono textareas ' +
        '(EntityChronologyPanel, TemplateBlocksEditor) silently render in the body face.',
    ).toMatch(/font-family:\s*var\(--font-mono\);/u);
  });

  it('does not adopt `field-sizing`, which is Chromium-only and breaks the JS auto-resize', () => {
    expect(
      THEME.replace(/\/\*[\s\S]*?\*\//gu, ''),
      '`field-sizing: content` is unimplemented in Firefox and WebKit — both of which the app ' +
        'ships to through Tauri — so it makes the same screen a different height per platform. It ' +
        'also freezes `TemplateBlocksEditor`’s auto-resize: once the box fits its content, ' +
        '`scrollHeight` stops exceeding `clientHeight`.',
    ).not.toMatch(/field-sizing/u);
  });
});

describe('the multi-line control — the guards go red without the fix', () => {
  it('reports a component that replaces the caller’s class instead of merging', () => {
    // The exact shape the component had: className before the spread, so a caller's class wins.
    function Broken({ className }: { className?: string }) {
      return createElement('textarea', { className, readOnly: true });
    }
    const { container } = render(createElement(Broken, { className: 'mono' }));
    expect([...(container.querySelector('textarea')?.classList ?? [])].sort()).not.toEqual([
      'control',
      'control--textarea',
      'mono',
    ]);
  });

  it('reports the height floor being deleted or turned into a pixel constant', () => {
    const bare = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    for (const broken of [
      bare.replace(/\s*min-height:\s*calc\(2lh[^;]*\);/u, ''),
      bare.replace(/min-height:\s*calc\(2lh[^;]*\);/u, 'min-height: 68px;'),
    ]) {
      expect(broken).not.toBe(bare);
      // Non-vacuity: the predicate must PASS on the real sheet and fail only on these copies.
      expect(ruleBody(bare, ':where(.control--textarea)')).toMatch(
        /min-height:\s*calc\(2lh \+ var\(--control-padding-block\) \* 2 \+ 2px\);/u,
      );
      expect(ruleBody(broken, ':where(.control--textarea)') ?? '').not.toMatch(
        /min-height:\s*calc\(2lh \+ var\(--control-padding-block\) \* 2 \+ 2px\);/u,
      );
    }
  });

  it('reports the padding token being inlined again', () => {
    const bare = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    const inlined = bare.replace(
      /padding:\s*var\(--control-padding-block\) /u,
      'padding: 0.55rem ',
    );
    expect(inlined).not.toBe(bare);
    expect(ruleBody(inlined, '.control')).not.toMatch(
      /padding:\s*var\(--control-padding-block\) /u,
    );
  });

  it('reports the mono rule being dropped back to a single class', () => {
    const bare = THEME.replace(/\/\*[\s\S]*?\*\//gu, '');
    const dropped = bare.replace(/\.control\.mono \{[^}]*\}/u, '');
    expect(dropped).not.toBe(bare);
    expect(ruleBody(dropped, '.control.mono')).toBeUndefined();
  });

  it('reports `field-sizing` being introduced', () => {
    expect(`${THEME}\n.control--textarea { field-sizing: content; }\n`).toMatch(/field-sizing/u);
  });

  it('reports a raw textarea that forgot the shared classes', () => {
    const scanned = scanTextareas({
      '../features/x/Y.tsx': '<textarea className="mono" />;',
      '../features/x/Z.tsx': '<TextArea className="control control--textarea mono" />;',
    });
    expect(scanned.unclassedRaw).toEqual(['../features/x/Y.tsx:textarea']);
    expect(scanned.restated).toEqual(['../features/x/Z.tsx:TextArea']);
  });

  it('reports an empty sweep rather than passing over nothing', () => {
    const empty = scanTextareas({});
    expect(empty.total).toBe(0);
    expect(empty.files).toBe(0);
    expect(ruleBody('', '.control')).toBeUndefined();
  });
});
