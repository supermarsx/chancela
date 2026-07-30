/**
 * The two read-only environment panes that name credential-bearing variables: Base de dados and
 * Redis.
 *
 * Both exist to explain variables whose VALUES are secrets — `DATABASE_URL` and `REDIS_URL` embed a
 * password in any authenticated deployment, and `CHANCELA_DB_KEY` is a SQLCipher passphrase. Each
 * pane's whole contract is therefore negative: it names the variable, says what it does, marks it as
 * a secret, and never fetches or renders a value. That is not something a reader of the file can
 * keep true by intention alone — one row gaining a "current value" column, or one `secret: true`
 * being dropped in an edit, would look like an improvement and would be a disclosure.
 *
 * So these tests assert exactly that: no request is made at all, every credential-bearing row
 * carries the secret note, and nothing that looks like a connection string or a passphrase reaches
 * the DOM.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { CacheSection } from './CacheSection';
import { DatabaseSection } from './DatabaseSection';
import { ptPT } from '../../i18n/locales/pt-PT';

/** The variables whose value is, or contains, a credential. */
const DATABASE_SECRETS = [
  'DATABASE_URL',
  'DATABASE_URL_FILE',
  'CHANCELA_DB_KEY',
  'CHANCELA_DB_KEY_FILE',
];
const CACHE_SECRETS = ['REDIS_URL', 'REDIS_URL_FILE'];

const SECRET_NOTE = ptPT['settings.env.secretNote'];

function renderPane(pane: 'database' | 'cache') {
  const fetchSpy = vi.fn(() => Promise.reject(new Error('this pane must issue no request')));
  vi.stubGlobal('fetch', fetchSpy as unknown as typeof fetch);
  const view = render(
    <MemoryRouter>{pane === 'database' ? <DatabaseSection /> : <CacheSection />}</MemoryRouter>,
  );
  return { ...view, fetchSpy };
}

/** The row whose first cell is exactly this variable name. */
function envRow(name: string): HTMLElement {
  const cell = screen
    .getAllByRole('cell')
    .find((candidate) => candidate.textContent?.trim() === name);
  if (!cell) throw new Error(`no environment row for ${name}`);
  const row = cell.closest('tr');
  if (!row) throw new Error(`${name} is not in a row`);
  return row;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe.each([['database', DATABASE_SECRETS] as const, ['cache', CACHE_SECRETS] as const])(
  'the %s environment pane',
  (pane, secrets) => {
    it('reads nothing from the server — there is no value to fetch', () => {
      const { fetchSpy, container } = renderPane(pane);

      expect(fetchSpy).not.toHaveBeenCalled();
      // No input either: the pane is documentation, and a writable box here would be a way to
      // repoint the store from a browser.
      expect(container.querySelectorAll('input, textarea, select')).toHaveLength(0);
    });

    it('marks every credential-bearing variable as a secret', () => {
      renderPane(pane);

      for (const name of secrets) {
        expect(
          within(envRow(name)).getByText(
            new RegExp(SECRET_NOTE.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&')),
          ),
          `${name} must carry the secret note`,
        ).toBeTruthy();
      }
    });

    it('shows an em dash as the default for a secret, never a sample value', () => {
      renderPane(pane);

      for (const name of secrets) {
        const cells = within(envRow(name)).getAllByRole('cell');
        // Three columns: variable, meaning, default. The default for a secret is always absent.
        expect(cells).toHaveLength(3);
        expect(cells[2].textContent?.trim()).toBe('—');
      }
    });

    it('never puts anything shaped like a URL or a passphrase in a VALUE cell', () => {
      renderPane(pane);

      // Prose may name a scheme while explaining what a variable is for; the default column is where
      // a real value would appear, and it may only ever hold a literal fallback or an em dash.
      for (const table of screen.getAllByRole('table')) {
        for (const row of within(table).getAllByRole('row')) {
          const cells = within(row).queryAllByRole('cell');
          if (cells.length !== 3) continue;
          const value = cells[2].textContent?.trim() ?? '';
          for (const shape of ['://', 'password', '@', ':6379', ':5432']) {
            expect(value.includes(shape), `${cells[0].textContent}: ${shape} in a value`).toBe(
              false,
            );
          }
        }
      }
    });
  },
);

describe('the database environment pane', () => {
  it('does not mark the non-secret classification variables as secrets', () => {
    renderPane('database');

    // These name a backend family and a key SOURCE class — publishing them discloses nothing, and
    // marking them secret would train the operator to ignore the note that matters.
    for (const name of ['CHANCELA_DB_BACKEND', 'CHANCELA_DB_KEY_SOURCE', 'CHANCELA_PG_SSLMODE']) {
      expect(envRow(name).textContent).not.toContain(SECRET_NOTE);
    }
  });

  it('points at the panes that DO own the live state, rather than restating it', () => {
    renderPane('database');

    const hrefs = screen.getAllByRole('link').map((link) => link.getAttribute('href'));
    // One writer per value: this pane cross-references, it does not duplicate a control.
    expect(hrefs).toContain('/settings/operations/data');
    expect(hrefs).toContain('/settings/operations/logs');
  });
});

describe('the cache environment pane', () => {
  it('keeps the cluster tunables in their own table, apart from the credential rows', () => {
    renderPane('cache');

    // The cluster intervals are not secrets and are not cache configuration: on Postgres the
    // shared-state backend is load-bearing, and flattening the two into one table would lose the
    // fail-open/fail-closed distinction the copy carries.
    const tables = screen.getAllByRole('table');
    expect(tables.length).toBeGreaterThanOrEqual(2);
    const clusterRow = envRow('CHANCELA_NODE_ROLE');
    const secretRow = envRow('REDIS_URL');
    expect(clusterRow.closest('table')).not.toBe(secretRow.closest('table'));
  });
});
