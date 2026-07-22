/**
 * Responsive top-bar collapse (t42).
 *
 * The header must reflow as the window narrows WITHOUT any control painting over another: the
 * primary tabs fold into a burger dropdown, the utility glyphs fold into a "more" dropdown, and the
 * brand is dropped at the tightest tier. jsdom has no layout, so pixel overlap can't be asserted
 * here — but the *structure* that guarantees no overlap can: at each tier exactly ONE representation
 * of each control is in the DOM (a single burger link set, never a hidden duplicate of the inline
 * strip), which is also what keeps the accessibility tree honest. The tier is chosen by
 * `useTopbarTier` from `matchMedia`, so each test installs a width-driven `matchMedia` stub (jsdom
 * ships none) and asserts what the shell renders at that width.
 *
 * The non-collapsed (wide) layout and its eight inline links are covered by `layout.test.tsx`, which
 * runs with no stub — `useTopbarTier` fails open to `wide` there.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Layout } from './layout';
import { renderWithDataRouter, fetchTable } from '../test/utils';
import { DEFAULT_SETTINGS, type Dashboard } from '../api/types';

const shellDashboard: Dashboard = {
  entities: 0,
  books_open: 0,
  books_total: 0,
  acts_total: 0,
  acts_draft: 0,
  acts_awaiting_signature: 0,
  acts_sealed: 0,
  unresolved_compliance: 0,
  failed_sync_jobs: 0,
  pending_backup_jobs: 0,
  ledger_length: 0,
  ledger_valid: true,
  current_work: {
    open_books: [],
    act_counts_by_state: {
      Draft: 0,
      Review: 0,
      Convened: 0,
      Deliberated: 0,
      TextApproved: 0,
      Signing: 0,
      Sealed: 0,
      Archived: 0,
    },
  },
  alerts: [],
  reminders: [],
  recent_events: [],
};

function stubSignedInShellFetch() {
  vi.stubGlobal(
    'fetch',
    fetchTable([
      { match: '/v1/session/roster', body: { onboarding_required: false, users: [] } },
      { match: '/v1/settings', body: DEFAULT_SETTINGS },
      {
        match: '/v1/session',
        body: {
          user: {
            id: 'u1',
            username: 'operador',
            display_name: 'Operador',
            created_at: '2026-07-08T00:00:00Z',
            active: true,
            has_secret: false,
            has_attestation_key: false,
          },
        },
      },
      { match: '/v1/dashboard', body: shellDashboard },
      { match: '/v1', body: [] },
    ]),
  );
}

/**
 * Install a width-driven `matchMedia`: a `(max-width: N)` query matches when the simulated viewport
 * is ≤ N. This mirrors what a real browser reports and lets `useTopbarTier` pick the tier for the
 * width under test.
 */
function installViewport(width: number) {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string) => {
      const max = query.match(/max-width:\s*(\d+)/);
      const matches = max ? width <= Number(max[1]) : false;
      return {
        matches,
        media: query,
        onchange: null,
        addEventListener: () => {},
        removeEventListener: () => {},
        addListener: () => {},
        removeListener: () => {},
        dispatchEvent: () => true,
      };
    },
  });
}

function renderShell(entry = '/') {
  stubSignedInShellFetch();
  return renderWithDataRouter(
    [
      {
        path: '/',
        element: <Layout />,
        children: [
          { index: true, element: <div>painel</div> },
          { path: 'entities', element: <div>entidades</div> },
          { path: 'settings/:sec?', element: <div>config</div> },
        ],
      },
    ],
    [entry],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  Reflect.deleteProperty(window, 'matchMedia');
});

describe('Top bar — medium tier (tabs collapse to a burger)', () => {
  it('folds the tab strip into a burger while keeping the brand and utility glyphs inline', async () => {
    installViewport(800);
    renderShell();
    await screen.findByText('painel');

    // The brand still shows at this tier; the inline tab strip does not exist.
    expect(screen.getByText('Chancela')).toBeTruthy();
    expect(screen.queryByTestId('tab-bar')).toBeNull();

    // The burger is present and closed, and — because the inline strip is gone — no tab link is in
    // the DOM yet (no hidden duplicate that would overlap or double the a11y tree).
    const burger = screen.getByTestId('topbar-tabs-menu');
    expect(burger.getAttribute('aria-haspopup')).toBe('menu');
    expect(burger.getAttribute('aria-expanded')).toBe('false');
    expect(screen.queryByRole('link', { name: 'Entidades' })).toBeNull();

    // The utility glyphs are still inline at medium (they only fold at the narrow tier), so there is
    // no "more" overflow yet.
    expect(screen.getByRole('link', { name: 'Arquivo' }).classList.contains('topbar__icon')).toBe(
      true,
    );
    expect(screen.queryByTestId('topbar-utility-menu')).toBeNull();
  });

  it('opens the burger to the primary tabs, each a single link', async () => {
    installViewport(800);
    renderShell();
    await screen.findByText('painel');

    fireEvent.click(screen.getByTestId('topbar-tabs-menu'));

    expect(screen.getByTestId('topbar-tabs-menu').getAttribute('aria-expanded')).toBe('true');
    const menu = screen.getByRole('menu');
    for (const name of ['Painel', 'Entidades', 'Livros', 'Minutas', 'Operações']) {
      // Exactly one representation per tab (the menuitem) — the inline strip is not also mounted, so
      // there is no hidden duplicate to overlap or to double the a11y tree.
      expect(within(menu).getByRole('menuitem', { name })).toBeTruthy();
      expect(screen.getAllByRole('menuitem', { name })).toHaveLength(1);
    }
  });

  it('marks the current tab active inside the burger', async () => {
    installViewport(800);
    renderShell('/entities');
    await screen.findByText('entidades');

    fireEvent.click(screen.getByTestId('topbar-tabs-menu'));
    const active = within(screen.getByRole('menu')).getByRole('menuitem', { name: 'Entidades' });
    expect(active.getAttribute('aria-current')).toBe('page');
    // The burger trigger itself lights when a tab behind it is current.
    expect(screen.getByTestId('topbar-tabs-menu').classList.contains('is-active')).toBe(true);
  });
});

describe('Top bar — narrow tier (utilities collapse too, brand dropped)', () => {
  it('folds the utility glyphs into a "more" menu, drops the brand, keeps bell + picker', async () => {
    installViewport(480);
    renderShell();
    await screen.findByText('painel');

    // Brand dropped; both overflow triggers present.
    expect(screen.queryByText('Chancela')).toBeNull();
    expect(screen.getByTestId('topbar-tabs-menu')).toBeTruthy();
    const more = screen.getByTestId('topbar-utility-menu');
    expect(more.getAttribute('aria-haspopup')).toBe('menu');

    // The utility glyphs are folded away (no inline duplicate), and the always-visible essentials
    // remain: the alerts bell and the user picker. (Asserted structurally to stay locale-agnostic.)
    expect(screen.queryByRole('link', { name: 'Arquivo' })).toBeNull();
    expect(document.querySelector('.notification-bell')).not.toBeNull();
    expect(screen.getByTestId('session-trigger')).toBeTruthy();

    // Opening "more" reveals the utility surfaces as menu items with their glyphs.
    fireEvent.click(more);
    const menu = screen.getByRole('menu');
    for (const name of ['Arquivo', 'Ferramentas', 'Configurações']) {
      expect(within(menu).getByRole('menuitem', { name })).toBeTruthy();
    }
  });

  it('lights the "more" trigger when a utility surface behind it is current', async () => {
    installViewport(480);
    renderShell('/settings/users');
    await screen.findByText('config');

    expect(screen.getByTestId('topbar-utility-menu').classList.contains('is-active')).toBe(true);
  });
});

describe('Top bar — dropdown accessibility', () => {
  it('closes on Escape and returns focus to the trigger', async () => {
    installViewport(800);
    renderShell();
    await screen.findByText('painel');

    const burger = screen.getByTestId('topbar-tabs-menu');
    fireEvent.click(burger);
    expect(screen.getByRole('menu')).toBeTruthy();

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
    expect(burger.getAttribute('aria-expanded')).toBe('false');
    expect(document.activeElement).toBe(burger);
  });

  it('closes on an outside click via the backdrop', async () => {
    installViewport(800);
    const { container } = renderShell();
    await screen.findByText('painel');

    fireEvent.click(screen.getByTestId('topbar-tabs-menu'));
    const backdrop = container.querySelector('.topbar__menu-backdrop') as HTMLElement;
    expect(backdrop).not.toBeNull();

    fireEvent.click(backdrop);
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull());
  });

  it('moves focus into the menu on open and roves with arrow keys', async () => {
    installViewport(800);
    renderShell();
    await screen.findByText('painel');

    fireEvent.click(screen.getByTestId('topbar-tabs-menu'));
    const items = within(screen.getByRole('menu')).getAllByRole('menuitem');
    // Focus lands on the first item on open (no tab is active at '/'’s… actually '/' IS active).
    await waitFor(() => expect(items.includes(document.activeElement as HTMLElement)).toBe(true));

    const start = items.indexOf(document.activeElement as HTMLElement);
    fireEvent.keyDown(screen.getByRole('menu'), { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[(start + 1) % items.length]);

    fireEvent.keyDown(screen.getByRole('menu'), { key: 'End' });
    expect(document.activeElement).toBe(items[items.length - 1]);
  });
});
