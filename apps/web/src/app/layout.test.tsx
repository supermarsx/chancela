import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { Layout } from './layout';
import { EntitiesPage } from '../features/entities/EntitiesPage';
import { renderWithProviders, fetchTable } from '../test/utils';
import { DEFAULT_SETTINGS } from '../api/types';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Layout', () => {
  it('renders the fixed tab bar brand and the pinned PT-PT navigation', async () => {
    // The chrome is behind the AuthGate now, so the layout renders it only when signed in:
    // an active session + a non-onboarding roster. (Order matters — the roster substring is
    // matched before the bare `/v1/session`.)
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
        { match: '/v1', body: [] },
      ]),
    );
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
    // Six pinned tabs, including the Ferramentas tools surface (t22-web).
    for (const label of [
      'Painel',
      'Entidades',
      'Livros',
      'Arquivo',
      'Ferramentas',
      'Configurações',
    ]) {
      expect(screen.getByRole('link', { name: label })).toBeTruthy();
    }
  });

  it('re-keys the route-transition wrapper on navigation and gates it via the class', async () => {
    // The page-enter motion is a single CSS animation on `.route-transition`; both
    // kill-switches (prefers-reduced-motion + [data-safe-mode]) zero `animation` on that
    // class, so asserting the class + the per-route re-key proves the structure without
    // touching pixels: navigation swaps the keyed node (fresh mount ⇒ the enter replays),
    // and the collapse is CSS-governed off the same class.
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
        { match: '/v1', body: [] },
      ]),
    );
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
