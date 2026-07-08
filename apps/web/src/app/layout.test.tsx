import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
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
