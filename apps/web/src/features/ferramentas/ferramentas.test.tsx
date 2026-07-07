import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { FerramentasPage } from './FerramentasPage';
import { CaeExplorer } from '../cae/CaeExplorer';
import type { CaeCatalogView, CaeEntryView, CaeNode } from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const CATALOG: CaeCatalogView = {
  origin: 'Embedded',
  schema_version: 1,
  generated_at: '2026-07-07T00:00:00Z',
  source_note: 'Tabela oficial DL 9/2025.',
  digest: 'a'.repeat(64),
  counts: {
    rev3: { seccao: 21, divisao: 88, grupo: 272, classe: 616, subclasse: 850 },
    rev4: { seccao: 22, divisao: 87, grupo: 287, classe: 651, subclasse: 915 },
  },
};

// A subclasse and a divisão with full ancestor chains, for the lookup endpoint.
const SUBCLASSE: CaeEntryView = {
  code: '68110',
  designation: 'Compra e venda de bens imobiliários.',
  level: 'Subclasse',
  revision: 'Rev4',
  hierarchy: [
    { code: 'L', designation: 'Atividades imobiliárias', level: 'Seccao', revision: 'Rev4' },
    { code: '68', designation: 'Atividades imobiliárias', level: 'Divisao', revision: 'Rev4' },
    { code: '681', designation: 'Compra e venda de imóveis', level: 'Grupo', revision: 'Rev4' },
    { code: '6811', designation: 'Compra e venda de imóveis', level: 'Classe', revision: 'Rev4' },
    {
      code: '68110',
      designation: 'Compra e venda de bens imobiliários.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
  ],
};

const DIVISAO: CaeEntryView = {
  code: '68',
  designation: 'Atividades imobiliárias',
  level: 'Divisao',
  revision: 'Rev4',
  hierarchy: [
    { code: 'L', designation: 'Atividades imobiliárias', level: 'Seccao', revision: 'Rev4' },
    { code: '68', designation: 'Atividades imobiliárias', level: 'Divisao', revision: 'Rev4' },
  ],
};

const LOOKUPS: Record<string, CaeEntryView> = { '68110': SUBCLASSE, '68': DIVISAO };

// The search endpoint (also used for children-by-prefix). Keyed by the search term.
const SEARCHES: Record<string, CaeNode[]> = {
  imobili: [
    {
      code: '68110',
      designation: 'Compra e venda de bens imobiliários.',
      level: 'Subclasse',
      revision: 'Rev4',
    },
  ],
  // Children pool for divisão "68": two grupos (kept) + noise the filter must drop
  // (a deeper classe by length; an unrelated code that only matched by designation).
  '68': [
    { code: '681', designation: 'Compra e venda de imóveis', level: 'Grupo', revision: 'Rev4' },
    { code: '682', designation: 'Arrendamento de imóveis', level: 'Grupo', revision: 'Rev4' },
    { code: '6811', designation: 'Compra e venda de imóveis', level: 'Classe', revision: 'Rev4' },
    { code: '55', designation: 'Referência a imóvel 68', level: 'Divisao', revision: 'Rev4' },
  ],
};

/**
 * A branching fetch stub for the Ferramentas surface. Order matters: refresh (POST) →
 * single-code lookup (`/v1/cae/<code>`) → search (`?search=`) → catalog metadata.
 */
function ferramentasFetch(
  refresh: () => Response = () => jsonResponse({ updated: false }),
): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/v1/cae/refresh') && method === 'POST') return Promise.resolve(refresh());
    const lookup = url.match(/\/v1\/cae\/([^?]+)/);
    if (lookup) {
      const code = decodeURIComponent(lookup[1]);
      const entry = LOOKUPS[code];
      return Promise.resolve(entry ? jsonResponse(entry) : jsonResponse({ error: 'unknown' }, 404));
    }
    const search = new URL(url, 'http://x').searchParams.get('search');
    if (search !== null) {
      return Promise.resolve(jsonResponse(SEARCHES[search] ?? []));
    }
    if (url.includes('/v1/cae')) return Promise.resolve(jsonResponse(CATALOG));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Ferramentas — CAE catalog panel', () => {
  it('shows catalog metadata (origin + per-revision totals)', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    expect(await screen.findByText('Incorporado')).toBeTruthy();
    // Rev.4 total = sum of the five level counts.
    expect(screen.getByText('1962')).toBeTruthy();
  });

  it('reports a successful refresh distinctly', async () => {
    vi.stubGlobal(
      'fetch',
      ferramentasFetch(() =>
        jsonResponse({
          updated: true,
          metadata: { ...CATALOG, origin: 'Cache' },
          note: 'cache atualizada para a versão gerada em 2026-08-01.',
        }),
      ),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Catálogo atualizado')).toBeTruthy();
  });

  it('routes a 422 "not configured" to Configurações (contract F1b)', async () => {
    vi.stubGlobal(
      'fetch',
      ferramentasFetch(() =>
        jsonResponse(
          {
            error:
              'URL de atualização do catálogo não configurado — defina-o em Configurações (Documentos → Catálogo CAE) ou na variável de ambiente CHANCELA_CAE_URL.',
          },
          422,
        ),
      ),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Configuração em falta')).toBeTruthy();
    // The copy links to Configurações, not the env var.
    const link = screen.getByRole('link', { name: /Configurações/i });
    expect(link.getAttribute('href')).toBe('/configuracoes');
    // The server's friendly message is rendered verbatim.
    expect(screen.getByText(/não configurado/)).toBeTruthy();
  });

  it('reports a 502 upstream failure distinctly from the 422 config state', async () => {
    vi.stubGlobal(
      'fetch',
      ferramentasFetch(() => jsonResponse({ error: 'cae source failed: connection refused' }, 502)),
    );
    renderWithProviders(<FerramentasPage />, ['/ferramentas']);

    fireEvent.click(await screen.findByRole('button', { name: /atualizar catálogo/i }));
    expect(await screen.findByText('Fonte do catálogo indisponível')).toBeTruthy();
    expect(screen.queryByText('Configuração em falta')).toBeNull();
  });
});

describe('Ferramentas — CAE explorer', () => {
  it('searches, and selecting a hit resolves its detail with a hierarchy breadcrumb', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    renderWithProviders(<CaeExplorer />, ['/ferramentas']);

    fireEvent.change(screen.getByLabelText('Procurar no catálogo CAE'), {
      target: { value: 'imobili' },
    });
    // The search hit appears; click it to open the detail pane.
    const hit = await screen.findByText('Compra e venda de bens imobiliários.');
    fireEvent.click(hit);

    // The detail resolves: designation + a terminal-level note + the breadcrumb roots at
    // the secção. The breadcrumb renders each ancestor's code as a clickable crumb.
    expect(await screen.findByText(/Nível terminal/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'L' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '681' })).toBeTruthy();
  });

  it('drills DOWN a numeric node to its exact prefix children, dropping non-children', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    // Deep-link straight to the divisão so its subníveis load.
    renderWithProviders(<CaeExplorer />, ['/ferramentas?code=68&rev=Rev4']);

    // Direct grupos are listed…
    expect(await screen.findByRole('button', { name: /681/ })).toBeTruthy();
    expect(screen.getByRole('button', { name: /682/ })).toBeTruthy();
    // …while a deeper classe (wrong length) and a designation-only match (wrong prefix)
    // are filtered out.
    expect(screen.queryByRole('button', { name: /6811/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /^55/ })).toBeNull();
  });

  it('switches revision (Rev.3 / Rev.4) via the segmented control', async () => {
    vi.stubGlobal('fetch', ferramentasFetch());
    renderWithProviders(<CaeExplorer />, ['/ferramentas']);

    const rev3 = await screen.findByRole('button', { name: 'Rev.3' });
    const rev4 = screen.getByRole('button', { name: 'Rev.4' });
    // Rev.4 is the default active revision.
    expect(rev4.getAttribute('aria-pressed')).toBe('true');
    expect(rev3.getAttribute('aria-pressed')).toBe('false');

    fireEvent.click(rev3);
    expect(rev3.getAttribute('aria-pressed')).toBe('true');
    expect(rev4.getAttribute('aria-pressed')).toBe('false');
  });
});
