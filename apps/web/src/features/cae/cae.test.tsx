import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { CaeRefList } from './CaeRefList';
import { CaePage } from './CaePage';
import { CaeCatalogPanel } from './CaeCatalogPanel';
import { FerramentasPage } from '../ferramentas/FerramentasPage';
import type { CaeCatalogView, CaeRefView, CaeRefreshResult } from '../../api/types';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const ZERO = { seccao: 0, divisao: 0, grupo: 0, classe: 0, subclasse: 0 };
const CATALOG: CaeCatalogView = {
  origin: 'Embedded',
  schema_version: 1,
  generated_at: '2026-01-01',
  source_note: '',
  digest: 'abc',
  counts: { rev3: ZERO, rev4: ZERO },
};

describe('CaeCatalogPanel — refresh toast', () => {
  it('toasts "updated" when the refresh brings a new dataset', async () => {
    const refreshed: CaeRefreshResult = {
      updated: true,
      metadata: CATALOG,
      note: 'Novo conjunto de dados.',
      source: 'DR',
      failures: [],
    };
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const body = url.includes('/refresh') && method === 'POST' ? refreshed : CATALOG;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<CaeCatalogPanel />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Catálogo CAE atualizado.')).toBeTruthy();
  });

  it('toasts "up to date" when the refresh is a no-op', async () => {
    const noop: CaeRefreshResult = {
      updated: false,
      metadata: CATALOG,
      note: '',
      source: null,
      failures: [],
    };
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const body = url.includes('/refresh') && method === 'POST' ? noop : CATALOG;
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<CaeCatalogPanel />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    await waitFor(() =>
      expect(screen.getByText('O catálogo CAE já está atualizado.')).toBeTruthy(),
    );
  });
});

describe('CaeRefList', () => {
  it('renders Principal with the accent badge and a catalogued designation', () => {
    const refs: CaeRefView[] = [
      {
        code: '68110',
        role: 'Principal',
        designation: 'Compra e venda de bens imobiliários.',
        level: 'Subclasse',
        revision: 'Rev4',
      },
    ];
    const { container } = renderWithProviders(<CaeRefList refs={refs} />);

    expect(screen.getByText('68110')).toBeTruthy();
    // The Principal badge takes the gold accent tone.
    const badge = screen.getByText('Principal');
    expect(badge.className).toContain('badge--accent');
    expect(screen.getByText('Compra e venda de bens imobiliários.')).toBeTruthy();
    // Level + revision read subtly as "Subclasse · Rev.4".
    expect(container.textContent).toContain('Subclasse · Rev.4');
  });

  it('renders a Secundário with a neutral badge and an honest fallback when uncatalogued', () => {
    const refs: CaeRefView[] = [
      { code: '82990', role: 'Secundario', designation: null, level: null, revision: null },
    ];
    renderWithProviders(<CaeRefList refs={refs} />);

    const badge = screen.getByText('Secundário');
    expect(badge.className).toContain('badge--neutral');
    // Null designation → the "não catalogado" note, not a blank.
    expect(screen.getByText(/Não catalogado/)).toBeTruthy();
  });
});

describe('CaePage redirect', () => {
  it('redirects the former /cae route into Ferramentas, preserving the query string', async () => {
    // A minimal fetch stub so the Ferramentas surface can mount after the redirect.
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url.includes('/v1/cae/')) {
          return Promise.resolve(
            new Response(
              JSON.stringify({
                code: '68110',
                designation: 'Compra e venda de bens imobiliários.',
                level: 'Subclasse',
                revision: 'Rev4',
                hierarchy: [
                  { code: 'L', designation: 'Imobiliárias', level: 'Seccao', revision: 'Rev4' },
                  {
                    code: '68110',
                    designation: 'Compra e venda de bens imobiliários.',
                    level: 'Subclasse',
                    revision: 'Rev4',
                  },
                ],
              }),
              { status: 200, headers: { 'Content-Type': 'application/json' } },
            ),
          );
        }
        // Catalog metadata (no-search /v1/cae).
        return Promise.resolve(
          new Response(
            JSON.stringify({
              origin: 'Embedded',
              schema_version: 1,
              generated_at: '2026-07-07T00:00:00Z',
              source_note: '',
              digest: 'a'.repeat(64),
              counts: {
                rev3: { seccao: 21, divisao: 88, grupo: 272, classe: 616, subclasse: 850 },
                rev4: { seccao: 22, divisao: 87, grupo: 287, classe: 651, subclasse: 915 },
              },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          ),
        );
      }),
    );

    renderWithProviders(
      <Routes>
        <Route path="/cae" element={<CaePage />} />
        <Route path="/ferramentas" element={<FerramentasPage />} />
      </Routes>,
      ['/cae?code=68110&rev=Rev4'],
    );

    // The Ferramentas explorer mounts and the deep-linked code resolves in the detail pane.
    expect(await screen.findByText('Explorador do catálogo CAE')).toBeTruthy();
    expect(await screen.findByText('Compra e venda de bens imobiliários.')).toBeTruthy();
  });
});
