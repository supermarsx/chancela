import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { Layout } from './layout';
import { EntitiesPage } from '../features/entities/EntitiesPage';
import { renderWithProviders, fetchTable } from '../test/utils';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Layout', () => {
  it('renders the fixed tab bar brand and the pinned PT-PT navigation', () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1', body: [] }]));
    renderWithProviders(
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<div>painel</div>} />
        </Route>
      </Routes>,
      ['/'],
    );

    // The masthead is gone; the brand now lives in the fixed secondary tab bar.
    expect(screen.getByText('Chancela')).toBeTruthy();
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
