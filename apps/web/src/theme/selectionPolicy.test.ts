/**
 * The global text-selection policy (t100) — a regression gate for the "stuck pointer" defect.
 *
 * ## The defect
 *
 * Choosing an option from any dropdown left the pointer behaving as though it were still held
 * down; moving the mouse afterwards swept a text highlight across the value that had just been
 * chosen. It was not a custom component and not an unbalanced handler of ours — every dropdown in
 * the app is the shared `Select` primitive, a native `<select class="control control--select">`,
 * and the only `mousedown`/pointer handlers in `apps/web` are the seal designer's drag and the
 * sub-nav's scroll edge. The cause was in this stylesheet:
 *
 * 1. `body` sets `user-select: none` — chrome is not selectable by default.
 * 2. A `:where(…)` block re-enables `user-select: text` across `.app *` wholesale, so that every
 *    value an operator may legitimately want to copy (an NIPC, a fingerprint, a digest) is
 *    selectable without opting each component in one at a time. That reaches the `<select>` too.
 * 3. `.control--select` sets `appearance: none` to draw the gilt chevron, so the select's value
 *    lays out as ordinary text rather than as UA button chrome — and with `user-select: text` a
 *    mousedown on it seeds a selection anchor.
 * 4. That same mousedown opens the UA option popup, which swallows the matching `mouseup`. The
 *    document therefore never ends the drag it just started, and the next pointer move extends
 *    the selection from the anchor.
 *
 * The fix is at step 2/3: a `<select>` is a control, so it belongs in the block that carves chrome
 * back out to non-selectable. With no anchor ever seeded there is nothing for the swallowed
 * `mouseup` to leave behind — as opposed to blanket-disabling selection on the page, which would
 * have hidden the highlight while taking the copyable values with it.
 *
 * ## What this gate asserts
 *
 * That the carve-out is still there, that it comes AFTER the `.app *` opt-in (all these blocks are
 * `:where(…)`, i.e. zero specificity, so source order is the whole mechanism — moving the rule up
 * would silently restore the defect), and that the opt-in for genuinely copyable text is still
 * present. It reads the stylesheet with `node:fs` for the reason `settingsRows.test.ts` records:
 * Vite owns `.css`, so a `?raw` import resolves to an empty string under vitest and every
 * assertion would pass vacuously.
 */
import { describe, expect, it } from 'vitest';

async function stylesheet(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
}

/** The `:where(…) { … }` blocks of the global selection policy, in source order. */
function selectionBlocks(css: string): { selector: string; body: string }[] {
  return [...css.matchAll(/:where\(([^)]*(?:\([^)]*\)[^)]*)*)\)\s*\{([^}]*)\}/gu)]
    .map((match) => ({ selector: match[1], body: match[2] }))
    .filter(({ body }) => /user-select/u.test(body));
}

describe('global text-selection policy', () => {
  it('carves the native select out of the selectable surface, after the .app opt-in', async () => {
    const blocks = selectionBlocks(await stylesheet());

    const appOptIn = blocks.findIndex(
      ({ selector, body }) =>
        /(^|,)\s*\.app \*/mu.test(selector) && /user-select:\s*text/u.test(body),
    );
    expect(appOptIn, 'the .app * text-selection opt-in is gone').toBeGreaterThanOrEqual(0);

    const selectCarveOut = blocks.findIndex(
      ({ selector, body }) =>
        /(^|,)\s*select\s*,/mu.test(selector) && /user-select:\s*none/u.test(body),
    );
    expect(
      selectCarveOut,
      'a `select` must be non-selectable: without it a mousedown seeds a selection anchor and ' +
        'the popup swallows the mouseup that would end the drag',
    ).toBeGreaterThanOrEqual(0);

    // Zero-specificity `:where()` throughout, so ORDER is what makes the carve-out win.
    expect(
      selectCarveOut,
      'the select carve-out must come after the .app * opt-in',
    ).toBeGreaterThan(appOptIn);
  });

  it('keeps genuinely copyable text selectable', async () => {
    const blocks = selectionBlocks(await stylesheet());
    const selectable = blocks
      .filter(({ body }) => /user-select:\s*text/u.test(body))
      .map(({ selector }) => selector)
      .join(',');

    // The values an operator copies — digests, monospaced identifiers, table cells, the main
    // content region — and the controls they type into. The fix must not have taken these with it.
    for (const surface of ['.app', '.digest', '.mono', 'table', 'textarea', 'input']) {
      expect(selectable, `${surface} lost text selection`).toMatch(
        new RegExp(`(^|,)\\s*${surface.replace('.', '\\.')}[\\s,)*:]`, 'mu'),
      );
    }
  });
});
