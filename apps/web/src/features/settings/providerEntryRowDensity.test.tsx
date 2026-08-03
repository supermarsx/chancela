/**
 * Structural guards on the density of a signing-provider entry row.
 *
 * Two things in that row were spending width on characters nobody needed to read, and both fixes
 * carry the same hazard: shrinking what is SHOWN must not shrink what is AVAILABLE. Each guard
 * below therefore pins the compact rendering AND the full value it must not have destroyed.
 *
 * ## 1. The entry id
 *
 * A provider entry id is a 36-character GUID that dominated the row. The row's LABEL is what
 * names the entry; the id only has to be recognisable. It is therefore shortened by **CSS
 * clipping**, never by slicing the string in the component — an operator correlating a row
 * against an API call or a log line needs the entire id, and clipping keeps every character in
 * the DOM, so it stays selectable, copyable, findable by browser find-in-page, and announced in
 * full by a screen reader. `entry_id.slice(0, 8) + '…'` would put the hidden half out of reach of
 * all four, leaving hover as the only way to obtain it.
 *
 * ## 2. The priority badge
 *
 * The badge read "Prioridade N" in a column whose header — and whose responsive `data-label` —
 * already says "Prioridade". The word is now dropped from the VISIBLE badge only; the full
 * statement stays in the accessibility tree, because a badge announced as a context-free "1",
 * stripped of the visual column that gave it meaning, is worse than a verbose one.
 *
 * ## Why the styling assertions read source rather than render
 *
 * jsdom does not apply stylesheet declarations to `getComputedStyle`, so mounting the row and
 * reading a width or a `text-overflow` passes whether or not any rule exists — a test that could
 * only ever pass. Those assertions read `theme.css` itself and carry a red-proof against an
 * in-memory copy of the real sheet with the rule removed. (In-memory: red-proofs must never
 * mutate the shared working tree.)
 *
 * Translated prose is never asserted literally; where copy is unavoidable it is resolved through
 * the catalog, so these tests pin structure and keys rather than pt-PT grammar.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import { ptPT } from '../../i18n/locales/pt-PT';
import type { ProviderCredentialsListView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';

/** Clearly-synthetic ids — never a real operator's entry. Both are full 36-char GUIDs. */
const LABELLED_ID = '00000000-0000-4000-8000-0000000000ab';
const UNLABELLED_ID = '11111111-1111-4111-8111-1111111111cd';
const LABEL = 'Primária';
const PRIORITY = 3;

const list: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [
    {
      mode: 'csc',
      provider_id: 'encosto qtsp',
      entries: [
        {
          entry_id: LABELLED_ID,
          label: LABEL,
          priority: PRIORITY,
          enabled: true,
          endpoint: 'https://qtsp.example/csc',
          selectors: {},
          fields: [],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
        {
          entry_id: UNLABELLED_ID,
          label: '',
          priority: PRIORITY + 1,
          enabled: false,
          selectors: {},
          fields: [],
          created_at: '2026-07-01T11:00:00Z',
          updated_at: '2026-07-01T11:00:00Z',
        },
      ],
    },
  ],
};

function stubFetch() {
  return vi.fn(() =>
    Promise.resolve(
      new Response(JSON.stringify(list), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  ) as unknown as typeof fetch;
}

function renderSection() {
  return renderWithProviders(
    <Routes>
      <Route path="/admin/signing/providers" element={<ProviderCredentialsSection />} />
    </Routes>,
    ['/admin/signing/providers'],
  );
}

async function readTheme(): Promise<string> {
  // The app project has no `@types/node`; this indirection is the suite's existing idiom.
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8').replace(/\r\n/gu, '\n');
}

/** Comments stripped, so prose ABOUT a declaration never satisfies a match. */
function rules(sheet: string): string {
  return sheet.replace(/\/\*[\s\S]*?\*\//gu, '');
}

/** The cap under test, as it must appear in the sheet. */
const CAP_RULE =
  /\.provider-entries-table__cell--id > \.truncate\s*\{[^}]*max-width:\s*([\d.]+)ch/u;

/** The shared single-line-clip primitive the cap rides on. */
const TRUNCATE_RULE = /(?:^|\n)\.truncate\s*\{(?<body>[^}]*)\}/u;

/** The key whose worded form the compact badge hands to assistive tech. */
const PRIORITY_KEY = 'settings.providerCredentials.entry.priority';

let THEME = '';
let RULES = '';
beforeAll(async () => {
  THEME = await readTheme();
  RULES = rules(THEME);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('provider entry id: shortened visually, whole in the DOM', () => {
  it('renders the complete 36-char id and wires it to the clipping classes', async () => {
    vi.stubGlobal('fetch', stubFetch());
    renderSection();

    const id = await screen.findByText(LABELLED_ID);

    // Not sliced: the exact, entire value — no ellipsis character, no shortened prefix.
    expect(id.textContent).toBe(LABELLED_ID);
    expect(id.textContent).toHaveLength(36);
    expect(id.textContent).not.toContain('…');

    // …and the classes that make `theme.css` shorten it visually.
    expect(id.tagName).toBe('CODE');
    expect(id.className.split(/\s+/u)).toContain('truncate');
    const cell = id.closest('td');
    expect(cell).not.toBeNull();
    expect(cell!.className.split(/\s+/u)).toContain('provider-entries-table__cell--id');
  });

  it('keeps the full id as the row name for an entry with no label', async () => {
    vi.stubGlobal('fetch', stubFetch());
    renderSection();

    // An unlabelled entry has nothing BUT its id to identify it, so the row's accessible name
    // must still be the whole thing — clipping the display must never reach the aria-label.
    expect(await screen.findByRole('group', { name: UNLABELLED_ID })).toBeTruthy();
  });

  it('caps the id at a fixed count of monospace characters', () => {
    const cap = RULES.match(CAP_RULE);
    expect(cap, 'the entry-id cap rule must exist in theme.css').not.toBeNull();

    // `ch` against the mono font, so the visible portion is a predictable hex-character count
    // rather than a pixel width. Roughly a UUID's first group and a bit: long enough to
    // recognise a row, short enough that the id stops dominating it.
    const chars = Number(cap![1]);
    expect(chars).toBeGreaterThan(6);
    expect(chars).toBeLessThan(24);
  });

  it('rides the shared .truncate primitive, which must still ellipsise', () => {
    // The cap declares only a width. Without these three on `.truncate`, a narrower box would
    // wrap to a second line or cut a glyph in half with no ellipsis at all.
    const base = RULES.match(TRUNCATE_RULE)?.groups?.body ?? '';
    expect(base).toContain('overflow: hidden;');
    expect(base).toContain('text-overflow: ellipsis;');
    expect(base).toContain('white-space: nowrap;');
  });

  it('scopes the cap so it outranks the primitive it overrides', () => {
    // `.truncate` itself sets `max-width: 100%`. A single-class cap would tie on specificity and
    // be decided by source order — a rule that silently stops working when the sheet is
    // reordered. The compound descendant form is (0,2,0) and wins wherever it sits.
    expect(RULES).toMatch(/\.provider-entries-table__cell--id > \.truncate\s*\{/u);
    expect(RULES).not.toMatch(/(?:^|\n)\.provider-entries-table__cell--id\s*\{/u);
    expect(RULES.match(TRUNCATE_RULE)?.groups?.body ?? '').toContain('max-width: 100%;');
  });

  it('the assertions fail against a sheet with the rules removed', () => {
    // Red-proof, in memory — the shared tree is never mutated to prove a guard.
    const withoutCap = RULES.replace(
      /\.provider-entries-table__cell--id > \.truncate\s*\{[^}]*\}/u,
      '/* removed */',
    );
    expect(withoutCap).not.toBe(RULES);
    expect(withoutCap).not.toMatch(CAP_RULE);

    const withoutEllipsis = RULES.replace(TRUNCATE_RULE, '\n.truncate {\n  display: block;\n}\n');
    expect(withoutEllipsis).not.toBe(RULES);
    expect(withoutEllipsis.match(TRUNCATE_RULE)?.groups?.body ?? '').not.toContain(
      'text-overflow: ellipsis;',
    );
  });
});

describe('provider entry priority: bare number shown, full statement announced', () => {
  /** The priority `<td>`, found by the responsive label the compact badge relies on. */
  async function priorityCell(): Promise<HTMLElement> {
    const row = await screen.findByRole('group', { name: LABEL });
    const label = ptPT['settings.providerCredentials.table.priority'];
    const cell = row.querySelector<HTMLElement>(`td[data-label="${label}"]`);
    expect(cell, 'the priority cell must still carry its responsive data-label').not.toBeNull();
    return cell!;
  }

  it('shows the rank and nothing else', async () => {
    vi.stubGlobal('fetch', stubFetch());
    renderSection();

    const visible = (await priorityCell()).querySelector('[aria-hidden="true"]');
    expect(visible, 'the badge must have a visually-shown, a11y-hidden part').not.toBeNull();

    // Digits only. This is the assertion the user asked for: no word, no punctuation, no
    // separator — just the rank. It also fails if the worded form is ever put back on screen,
    // in ANY locale, because no locale's wording is digits alone.
    expect(visible!.textContent).toBe(String(PRIORITY));
    expect(visible!.textContent).toMatch(/^\d+$/u);
  });

  it('still announces the worded statement to assistive tech', async () => {
    vi.stubGlobal('fetch', stubFetch());
    renderSection();

    const cell = await priorityCell();
    const spoken = cell.querySelector('.sr-only');
    expect(spoken, 'the compact badge must keep a screen-reader statement').not.toBeNull();

    // Resolved through the catalog rather than written out, so this pins the KEY and its
    // interpolation, not pt-PT grammar. A bare "3" reaching a screen reader fails here.
    const expected = ptPT[PRIORITY_KEY].replace('{priority}', String(PRIORITY));
    expect(spoken!.textContent).toBe(expected);
    expect(spoken!.textContent).not.toBe(String(PRIORITY));

    // The badge as a whole must not read the rank twice: the visible half is aria-hidden, so
    // the cell's accessible text is the statement alone.
    expect(cell.textContent).toBe(`${PRIORITY}${expected}`);
  });

  it('keeps the worded key, which the compact badge now depends on', () => {
    // Dropping the word from the badge makes this key look unused to a reader skimming the JSX
    // for visible copy. It is not: it is the only thing a screen reader gets. Deleting it (in
    // any of the 14 locales) would silently reduce the badge to a context-free number.
    expect(ptPT[PRIORITY_KEY]).toContain('{priority}');
    expect(ptPT[PRIORITY_KEY].replace('{priority}', '3')).not.toBe('3');
  });
});
