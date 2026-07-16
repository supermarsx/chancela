import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { Layout } from './layout';
import { EntitiesPage } from '../features/entities/EntitiesPage';
import { renderWithProviders, fetchTable } from '../test/utils';
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
    renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<div>painel</div>} />
        </Route>
      </Routes>,
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

  it('keeps the skip-link target mounted when routed content crashes', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubSignedInShellFetch();

    renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<CrashingRoute />} />
        </Route>
      </Routes>,
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
    const { container } = renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<div>painel</div>} />
          <Route path="entidades" element={<div>entidades</div>} />
        </Route>
      </Routes>,
      ['/'],
    );

    await screen.findByText('painel');
    const before = container.querySelector('.route-transition');
    expect(before).not.toBeNull();
    // The wrapper is keyed on the pathname (exposed as data-route-key for this assertion).
    expect(before?.getAttribute('data-route-key')).toBe('/');

    fireEvent.click(screen.getByRole('link', { name: 'Entidades' }));
    await screen.findByText('entidades');

    const after = container.querySelector('.route-transition');
    // Same class (the gating hook survives), new key ⇒ a fresh node that replays the enter.
    expect(after?.classList.contains('route-transition')).toBe(true);
    expect(after?.getAttribute('data-route-key')).toBe('/entidades');
    expect(after).not.toBe(before);
  });

  it('focuses the main landmark after pathname navigation', async () => {
    stubSignedInShellFetch();
    renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<div>painel</div>} />
          <Route path="entidades" element={<div>entidades</div>} />
        </Route>
      </Routes>,
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
    renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<SamePathControls />} />
        </Route>
      </Routes>,
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

    renderWithProviders(<EntitiesPage />, ['/entidades']);

    expect(await screen.findByText('Encosto Estratégico, Lda.')).toBeTruthy();
    expect(screen.getByText('500000000')).toBeTruthy();
    // Creating an entity now lives behind neat buttons that open dedicated routes; the
    // form is no longer inline on the list page.
    expect(screen.getByRole('link', { name: /nova entidade/i })).toBeTruthy();
    expect(screen.getByRole('link', { name: /importar do registo/i })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /criar entidade/i })).toBeNull();
  });
});
