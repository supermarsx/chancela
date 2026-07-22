import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useState } from 'react';
import { Layout } from './layout';
import { EntitiesPage } from '../features/entities/EntitiesPage';
import { renderWithDataRouter, renderWithProviders, fetchTable } from '../test/utils';
import { DEFAULT_SETTINGS, type Dashboard } from '../api/types';
import { UI_VERSION, displayVersion } from '../api/versionCheck';

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
 * A stand-in for a sub-tabbed page that HOLDS unsaved state — Configurações' working copy is
 * exactly this shape. The draft lives in component state, so it survives precisely as long as
 * the component is not remounted, which is what the route key decides.
 */
function SectionProbe() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [draft, setDraft] = useState('');

  return (
    <div>
      <p>{`aqui: ${pathname}`}</p>
      <label>
        rascunho
        <input value={draft} onChange={(e) => setDraft(e.target.value)} />
      </label>
      <button type="button" onClick={() => navigate('/settings/data')}>
        Dados
      </button>
      <button type="button" onClick={() => navigate('/entities/ent-1')}>
        Entidade 1
      </button>
      <button type="button" onClick={() => navigate('/entities/ent-2')}>
        Entidade 2
      </button>
    </div>
  );
}

function CrashingRoute(): never {
  throw new Error('rota rebentou');
}

function SamePathControls() {
  const navigate = useNavigate();
  const { search, hash } = useLocation();

  return (
    <div>
      <button type="button" onClick={() => navigate('/?view=detalhe#secao')}>
        Ajustar vista
      </button>
      <p>{search || hash ? `${search}${hash}` : 'sem parametros'}</p>
    </div>
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Layout', () => {
  it('renders the fixed tab bar brand and the pinned PT-PT navigation', async () => {
    // The chrome is behind the AuthGate now, so the layout renders it only when signed in:
    // an active session + a non-onboarding roster. (Order matters — the roster substring is
    // matched before the bare `/v1/session`.)
    stubSignedInShellFetch();
    renderWithDataRouter(
      [{ path: '/', element: <Layout />, children: [{ index: true, element: <div>painel</div> }] }],
      ['/'],
    );

    // The masthead is gone; the brand now lives in the fixed secondary tab bar (rendered
    // once the AuthGate resolves the active session).
    expect(await screen.findByText('Chancela')).toBeTruthy();
    // Eight pinned tabs, including the task-focused Operações surface.
    for (const label of [
      'Painel',
      'Entidades',
      'Livros',
      'Minutas',
      'Arquivo',
      'Ferramentas',
      'Operações',
      'Configurações',
    ]) {
      expect(screen.getByRole('link', { name: label })).toBeTruthy();
    }
  });

  it('brands the footer with the product, the instrument and the real build version', async () => {
    // The version is derived from the build global via displayVersion(), never hard-coded, so
    // the assertion computes the expected label the same way the footer does.
    stubSignedInShellFetch();
    renderWithDataRouter(
      [{ path: '/', element: <Layout />, children: [{ index: true, element: <div>painel</div> }] }],
      ['/'],
    );

    await screen.findByText('painel');
    const footer = screen.getByRole('contentinfo');

    expect(footer.textContent).toBe(
      `Chancela · Livro de atas digital · v${displayVersion(UI_VERSION)}`,
    );
    // No conformity claim: the footer describes the product, it does not assert legal outcomes.
    expect(footer.textContent).not.toMatch(/conforme|CSC|RGPD|GDPR|eIDAS|prot[oó]tipo/i);
  });

  it('keeps the skip-link target mounted when routed content crashes', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubSignedInShellFetch();

    renderWithDataRouter(
      [{ path: '/', element: <Layout />, children: [{ index: true, element: <CrashingRoute /> }] }],
      ['/'],
    );

    const crashHeading = await screen.findByRole('heading', { name: 'Ocorreu um erro' });
    const skipLink = screen.getByRole('link', { name: 'Saltar para o conteúdo' });
    const main = screen.getByRole('main');

    expect(skipLink.getAttribute('href')).toBe('#main-content');
    expect(main.id).toBe('main-content');
    expect(document.getElementById('main-content')).toBe(main);
    expect(main.contains(crashHeading)).toBe(true);
  });

  it('re-keys the route-transition wrapper on navigation and gates it via the class', async () => {
    // The page-enter motion is a single CSS animation on `.route-transition`; both
    // kill-switches (prefers-reduced-motion + [data-safe-mode]) zero `animation` on that
    // class, so asserting the class + the per-route re-key proves the structure without
    // touching pixels: navigation swaps the keyed node (fresh mount ⇒ the enter replays),
    // and the collapse is CSS-governed off the same class.
    stubSignedInShellFetch();
    const { container } = renderWithDataRouter(
      [
        {
          path: '/',
          element: <Layout />,
          children: [
            { index: true, element: <div>painel</div> },
            { path: 'entities', element: <div>entidades</div> },
          ],
        },
      ],
      ['/'],
    );

    await screen.findByText('painel');
    const before = container.querySelector('.route-transition');
    expect(before).not.toBeNull();
    // The wrapper is keyed on the route (exposed as data-route-key for this assertion).
    expect(before?.getAttribute('data-route-key')).toBe('/');

    fireEvent.click(screen.getByRole('link', { name: 'Entidades' }));
    await screen.findByText('entidades');

    const after = container.querySelector('.route-transition');
    // Same class (the gating hook survives), new key ⇒ a fresh node that replays the enter.
    expect(after?.classList.contains('route-transition')).toBe(true);
    expect(after?.getAttribute('data-route-key')).toBe('/entities');
    expect(after).not.toBe(before);
  });

  /** The shell around a sub-tabbed settings page and a record page with its own sub-tabs. */
  function renderSectionShell(entry: string) {
    return renderWithDataRouter(
      [
        {
          path: '/',
          element: <Layout />,
          children: [
            { index: true, element: <div>painel</div> },
            {
              path: 'settings/:sec?',
              handle: { navDepth: 1 },
              element: <SectionProbe />,
            },
            {
              path: 'entities/:id/:sec?',
              handle: { navDepth: 2 },
              element: <SectionProbe />,
            },
          ],
        },
      ],
      [entry],
    );
  }

  it('keeps page state across a sub-tab switch inside the same page', async () => {
    // t97 moved sub-tabs into the path, which would otherwise make every sub-tab switch look
    // like a route change and remount the page — silently throwing away Configurações' unsaved
    // working copy the moment an operator clicked a tab. `handle.navDepth` says how many
    // segments name the PAGE, and the key stops there.
    stubSignedInShellFetch();
    const { container } = renderSectionShell('/settings');

    await screen.findByText('aqui: /settings');
    const before = container.querySelector('.route-transition');
    expect(before?.getAttribute('data-route-key')).toBe('/settings');
    fireEvent.change(screen.getByLabelText('rascunho'), { target: { value: 'por guardar' } });

    fireEvent.click(screen.getByRole('button', { name: 'Dados' }));
    await screen.findByText('aqui: /settings/data');

    // The unsaved draft is still there — the page was never remounted.
    expect((screen.getByLabelText('rascunho') as HTMLInputElement).value).toBe('por guardar');
    const after = container.querySelector('.route-transition');
    expect(after?.getAttribute('data-route-key')).toBe('/settings');
    expect(after).toBe(before);
  });

  it("still remounts when the RECORD changes, so one entity never shows another's state", async () => {
    // The other direction, and the one that fails silently: a key that never changes is as
    // wrong as one that changes too often. Moving between two entities is a different page,
    // so the state must NOT survive — otherwise entity 2 renders entity 1's draft.
    stubSignedInShellFetch();
    const { container } = renderSectionShell('/entities/ent-1');

    await screen.findByText('aqui: /entities/ent-1');
    const before = container.querySelector('.route-transition');
    expect(before?.getAttribute('data-route-key')).toBe('/entities/ent-1');
    fireEvent.change(screen.getByLabelText('rascunho'), { target: { value: 'da ent-1' } });

    fireEvent.click(screen.getByRole('button', { name: 'Entidade 2' }));
    await screen.findByText('aqui: /entities/ent-2');

    expect((screen.getByLabelText('rascunho') as HTMLInputElement).value).toBe('');
    const after = container.querySelector('.route-transition');
    expect(after?.getAttribute('data-route-key')).toBe('/entities/ent-2');
    expect(after).not.toBe(before);
  });

  it('focuses the main landmark after pathname navigation', async () => {
    stubSignedInShellFetch();
    renderWithDataRouter(
      [
        {
          path: '/',
          element: <Layout />,
          children: [
            { index: true, element: <div>painel</div> },
            { path: 'entities', element: <div>entidades</div> },
          ],
        },
      ],
      ['/'],
    );

    await screen.findByText('painel');

    fireEvent.click(screen.getByRole('link', { name: 'Entidades' }));
    await screen.findByText('entidades');

    const main = screen.getByRole('main');
    await waitFor(() => expect(document.activeElement).toBe(main));
  });

  it('does not steal focus on same-path query and hash navigation', async () => {
    stubSignedInShellFetch();
    renderWithDataRouter(
      [
        {
          path: '/',
          element: <Layout />,
          children: [{ index: true, element: <SamePathControls /> }],
        },
      ],
      ['/'],
    );

    await screen.findByText('sem parametros');
    const control = screen.getByRole('button', { name: 'Ajustar vista' });
    control.focus();
    expect(document.activeElement).toBe(control);

    fireEvent.click(control);
    await screen.findByText('?view=detalhe#secao');

    expect(document.activeElement).toBe(control);
  });
});

describe('EntitiesPage', () => {
  it('lists entities returned by the API', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        {
          match: '/v1/entities',
          body: [
            {
              id: 'ent-1',
              name: 'Encosto Estratégico, Lda.',
              nipc: '500000000',
              seat: 'Lisboa',
              family: 'CommercialCompany',
              kind: 'SociedadePorQuotas',
            },
          ],
        },
      ]),
    );

    renderWithProviders(<EntitiesPage />, ['/entities']);

    expect(await screen.findByText('Encosto Estratégico, Lda.')).toBeTruthy();
    expect(screen.getByText('500000000')).toBeTruthy();
    // Creating an entity now lives behind neat buttons that open dedicated routes; the
    // form is no longer inline on the list page.
    expect(screen.getByRole('link', { name: /nova entidade/i })).toBeTruthy();
    expect(screen.getByRole('link', { name: /importar do registo/i })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /criar entidade/i })).toBeNull();
  });
});

// --- Top-bar utility glyphs (t103, t31) -----------------------------------------------
describe('Layout — Arquivo, Ferramentas and Configurações as top-bar icons', () => {
  function renderShell() {
    stubSignedInShellFetch();
    return renderWithDataRouter(
      [{ path: '/', element: <Layout />, children: [{ index: true, element: <div>painel</div> }] }],
      ['/'],
    );
  }

  it('orders them archive → tools → cog → divider → alerts', async () => {
    renderShell();
    await screen.findByText('painel');

    const session = document.querySelector('.topbar__session') as HTMLElement;
    expect(session).not.toBeNull();

    // Read the rendered order rather than trusting the source order. Arquivo sits first, just
    // before the tools glyph (t31), so the archive reference surface groups with the utilities.
    const order = [
      ...session.querySelectorAll('.topbar__icon, .topbar__divider, .notification-bell'),
    ].map((el) =>
      el.classList.contains('topbar__divider')
        ? 'divider'
        : el.classList.contains('notification-bell')
          ? 'alerts'
          : el.getAttribute('aria-label'),
    );
    expect(order).toEqual(['Arquivo', 'Ferramentas', 'Configurações', 'divider', 'alerts']);
  });

  it('gives each glyph a real accessible name, not just a tooltip', async () => {
    renderShell();
    await screen.findByText('painel');

    // A tooltip is a hover/focus affordance, not an accessible name. These must resolve by
    // role+name, which is what a screen reader and `getByRole` both use.
    for (const name of ['Ferramentas', 'Configurações']) {
      const link = screen.getByRole('link', { name });
      expect(link.classList.contains('topbar__icon')).toBe(true);
      // The glyph itself stays decorative so it cannot contribute a second, competing name.
      expect(link.querySelector('svg')?.getAttribute('aria-hidden')).toBe('true');
    }
  });

  it('renders two VISUALLY DISTINCT glyphs', async () => {
    // Verified in the rendered DOM, not by reading the source: a peer found two different
    // notification actions rendering the identical check glyph, which no amount of reading the
    // call sites would have caught — both looked correct, they just resolved to the same icon.
    renderShell();
    await screen.findByText('painel');

    const geometry = (name: string) => {
      const svg = screen.getByRole('link', { name }).querySelector('svg');
      return [...(svg?.querySelectorAll('path, circle, rect, line') ?? [])]
        .map((node) => node.outerHTML)
        .join('');
    };

    const wrench = geometry('Ferramentas');
    const cog = geometry('Configurações');

    expect(wrench.length).toBeGreaterThan(0);
    expect(cog.length).toBeGreaterThan(0);
    expect(cog).not.toBe(wrench);
  });

  it('does not announce the divider as content', async () => {
    renderShell();
    await screen.findByText('painel');

    const divider = document.querySelector('.topbar__divider') as HTMLElement;
    expect(divider.getAttribute('aria-hidden')).toBe('true');
    // No text content either — an aria-hidden element carrying text is still a copy hazard.
    expect(divider.textContent).toBe('');
  });

  it('keeps them keyboard-reachable and in DOM order, and marks the current surface', async () => {
    stubSignedInShellFetch();
    renderWithDataRouter(
      [
        {
          path: '/',
          element: <Layout />,
          children: [
            { index: true, element: <div>painel</div> },
            { path: 'settings/:sec?', element: <div>config</div> },
          ],
        },
      ],
      ['/settings/users'],
    );
    await screen.findByText('config');

    // Anchors with href are natively focusable — the reorder moved them, it did not turn them
    // into divs with click handlers, which is the usual way a reorder loses keyboard access.
    for (const name of ['Ferramentas', 'Configurações']) {
      expect(screen.getByRole('link', { name }).getAttribute('href')).toBeTruthy();
    }
    // The cog lights for a sub-tab deep inside Configurações, not only for the bare address.
    expect(screen.getByRole('link', { name: 'Configurações' }).getAttribute('aria-current')).toBe(
      'page',
    );
    expect(
      screen.getByRole('link', { name: 'Ferramentas' }).getAttribute('aria-current'),
    ).toBeNull();
  });
});
