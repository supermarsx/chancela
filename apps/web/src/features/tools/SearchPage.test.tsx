import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { useLocation } from 'react-router-dom';
import type {
  SearchFacets,
  SearchHit,
  SearchResponse,
  SearchStatusResponse,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { SearchPage, searchHitRoute } from './SearchPage';
import { ToolsPage } from './ToolsPage';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const STATUS: SearchStatusResponse = {
  execution_mode: 'embedded',
  enabled: true,
  partial: false,
  stale: false,
  content_truncated: false,
  phase: 'idle',
  generation: 7,
  document_count: 2,
  truncated_document_count: 0,
  indexed_content_chars: 1_200,
  content_budget_chars: 25_000_000,
  content_budget_exhausted: false,
  processed: 2,
  total: 2,
  last_event_seq: 14,
  last_started_at: '2026-07-26T10:00:00Z',
  last_completed_at: '2026-07-26T10:01:00Z',
  details_redacted: true,
  updated_at: '2026-07-26T10:01:00Z',
};

const EMPTY_FACETS: SearchFacets = {
  kind: {},
  date: {},
  entity: {},
  book: {},
  author: {},
  law: {},
  status: {},
};

function hit(overrides: Partial<SearchHit> = {}): SearchHit {
  return {
    id: 'act:act-1',
    kind: 'act',
    title: 'Ata da assembleia geral',
    snippet: 'Deliberação aprovada por unanimidade.',
    content_truncated: false,
    score: 12,
    tenant_id: 'tenant-1',
    entity_id: 'entity-1',
    entity_name: 'Cooperativa Aurora',
    book_id: 'book-1',
    book_label: 'Livro 2026',
    act_id: 'act-1',
    author: 'Amélia Costa',
    law: 'CSC 63.º',
    status: 'Draft',
    occurred_at: '2026-07-25T11:30:00Z',
    ...overrides,
  };
}

function response({
  hits = [hit()],
  nextCursor = null,
  index = STATUS,
  facets = EMPTY_FACETS,
  offset = 0,
  total = hits.length,
  facetsTruncated = false,
  paginationTruncated = false,
}: {
  hits?: SearchHit[];
  nextCursor?: string | null;
  index?: SearchStatusResponse;
  facets?: SearchFacets;
  offset?: number;
  total?: number;
  facetsTruncated?: boolean;
  paginationTruncated?: boolean;
} = {}): SearchResponse {
  return {
    page: {
      total,
      offset,
      limit: 25,
      has_more: nextCursor !== null,
      facets_truncated: facetsTruncated,
      hits,
      facets,
    },
    next_cursor: nextCursor,
    pagination_truncated: paginationTruncated,
    index,
  };
}

function searchFetch(
  resolvePage: (url: URL) => SearchResponse = () => response(),
  status: SearchStatusResponse = STATUS,
) {
  return vi.fn((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input.toString();
    if (raw === '/v1/search/status') return Promise.resolve(json(status));
    if (raw.startsWith('/v1/search?')) {
      return Promise.resolve(json(resolvePage(new URL(raw, 'http://test.invalid'))));
    }
    return Promise.reject(new Error(`no stub for ${raw}`));
  });
}

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('Ferramentas — Pesquisa', () => {
  it('is the authorised default, exposes all kinds, and renders friendly stable-id facets in one column', async () => {
    const facets: SearchFacets = {
      ...EMPTY_FACETS,
      kind: { act: 1 },
      entity: { 'entity-1': { label: 'Cooperativa Aurora', count: 1 } },
      book: {
        'book-1': { label: 'Livro 2026', count: 1 },
        'Livro legado sem id': 3,
      },
      author: { 'Amélia Costa': 1 },
      law: { 'CSC 63.º': 1 },
      status: { Draft: 1 },
    };
    const fetchMock = searchFetch(() => response({ facets }));
    vi.stubGlobal('fetch', fetchMock);

    const { container } = renderWithProviders(<ToolsPage />, ['/tools']);

    expect(await screen.findByText('Pesquise em toda a Chancela')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Pesquisa' }).getAttribute('aria-pressed')).toBe(
      'true',
    );
    expect(fetchMock.mock.calls.some(([url]) => String(url).includes('/v1/cae'))).toBe(false);

    fireEvent.change(screen.getByRole('searchbox', { name: 'Pesquisar' }), {
      target: { value: 'assembleia geral' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Pesquisar' }));

    expect(await screen.findByRole('heading', { name: 'Ata da assembleia geral' })).toBeTruthy();
    const request = new URL(
      String(fetchMock.mock.calls.find(([url]) => String(url).startsWith('/v1/search?'))?.[0]),
      'http://test.invalid',
    );
    expect(request.searchParams.get('q')).toBe('assembleia geral');
    expect(request.searchParams.get('limit')).toBe('25');

    fireEvent.click(screen.getByText('Mais filtros'));
    expect(screen.getAllByRole('checkbox')).toHaveLength(12);
    expect(screen.getByRole('option', { name: 'Cooperativa Aurora (1)' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Livro 2026 (1)' })).toBeTruthy();
    expect(
      screen.getByRole('option', { name: 'Livro legado sem id (3)' }).hasAttribute('disabled'),
    ).toBe(true);

    const list = container.querySelector('.full-search__result-list');
    expect(list).toBeTruthy();
    expect(list?.children).toHaveLength(1);
    expect(container.querySelectorAll('.full-search-result')).toHaveLength(1);
  });

  it('keeps the cursor opaque, appends the next page, and never puts it in the URL', async () => {
    const fetchMock = searchFetch((url) =>
      url.searchParams.get('cursor') === 'opaque+/=page-2'
        ? response({
            hits: [
              hit({
                id: 'entity:entity-2',
                kind: 'entity',
                title: 'Associação Horizonte',
                entity_id: 'entity-2',
                act_id: null,
                book_id: null,
              }),
            ],
            offset: 1,
            total: 2,
          })
        : response({
            hits: [hit()],
            nextCursor: 'opaque+/=page-2',
            total: 2,
          }),
    );
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(
      <>
        <SearchPage />
        <LocationProbe />
      </>,
      ['/tools?q=assembleia'],
    );

    expect(await screen.findByRole('heading', { name: 'Ata da assembleia geral' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Carregar mais resultados' }));

    expect(await screen.findByRole('heading', { name: 'Associação Horizonte' })).toBeTruthy();
    expect(screen.getByText('2 resultados carregados')).toBeTruthy();
    const searchCalls = fetchMock.mock.calls
      .map(([url]) => String(url))
      .filter((url) => url.startsWith('/v1/search?'));
    expect(searchCalls).toHaveLength(2);
    expect(new URL(searchCalls[1], 'http://test.invalid').searchParams.get('cursor')).toBe(
      'opaque+/=page-2',
    );
    expect(screen.getByTestId('location').textContent).toBe('/tools?q=assembleia');
  });

  it('explains the bounded result window instead of claiming every match was loaded', async () => {
    vi.stubGlobal(
      'fetch',
      searchFetch(() => response({ total: 150_000, paginationTruncated: true })),
    );

    renderWithProviders(<SearchPage />, ['/tools?q=assembleia']);

    expect(await screen.findByText('A janela máxima de resultados foi atingida')).toBeTruthy();
    expect(screen.getByText(/Refine os termos ou filtros/)).toBeTruthy();
    expect(screen.queryByText('Todos os resultados foram carregados.')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Carregar mais resultados' })).toBeNull();
  });

  it('shows partial, stale and bounded-content notices without leaking manage-only diagnostics', async () => {
    const degraded: SearchStatusResponse = {
      ...STATUS,
      partial: true,
      stale: true,
      content_truncated: true,
      content_budget_exhausted: true,
      truncated_document_count: 4,
      indexed_content_chars: 25_000_000,
      content_budget_chars: undefined,
      last_error: 'raw storage path C:\\private\\search.idx',
      worker_thread: 'search-worker-secret',
    };
    vi.stubGlobal(
      'fetch',
      searchFetch(() => response({ index: degraded }), degraded),
    );

    renderWithProviders(<SearchPage />, ['/tools?q=assembleia']);

    expect(await screen.findByText('Resultados parciais durante a indexação')).toBeTruthy();
    expect(screen.getByText('Os resultados podem estar desatualizados')).toBeTruthy();
    expect(screen.getByText('Foi atingido o limite global de conteúdo')).toBeTruthy();
    expect(
      screen.getByText(/Alguns corpos foram limitados; os títulos e metadados continuam/),
    ).toBeTruthy();
    expect(document.body.textContent).not.toContain('C:\\private\\search.idx');
    expect(document.body.textContent).not.toContain('search-worker-secret');
  });

  it('explains when high-cardinality facet values are bounded while returned counts stay usable', async () => {
    const facets: SearchFacets = {
      ...EMPTY_FACETS,
      author: { 'Amélia Costa': 1 },
    };
    vi.stubGlobal(
      'fetch',
      searchFetch(() => response({ facets, facetsTruncated: true })),
    );

    renderWithProviders(<SearchPage />, ['/tools?q=assembleia']);

    expect(await screen.findByText('Alguns valores de filtro estão ocultos')).toBeTruthy();
    expect(screen.getByText(/As contagens apresentadas continuam exatas/)).toBeTruthy();
    fireEvent.click(screen.getByText('Mais filtros'));
    expect(screen.getByRole('option', { name: 'Amélia Costa (1)' })).toBeTruthy();
  });

  it('does not query results while the index is disabled', async () => {
    const disabled = { ...STATUS, enabled: false, phase: 'disabled' as const };
    const fetchMock = searchFetch(() => response(), disabled);
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<SearchPage />, ['/tools?q=assembleia']);

    expect(await screen.findByText('A pesquisa está desativada')).toBeTruthy();
    expect(fetchMock.mock.calls.map(([url]) => String(url))).toEqual(['/v1/search/status']);
  });

  it('fails closed without search.read: no tab, labels, facets, results or search requests', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const raw = typeof input === 'string' ? input : input.toString();
      if (raw.startsWith('/v1/cae')) {
        return Promise.resolve(
          json({
            origin: 'Embedded',
            schema_version: 1,
            generated_at: '2026-07-26T00:00:00Z',
            source_note: '',
            digest: 'a'.repeat(64),
            counts: {
              rev3: { seccao: 0, divisao: 0, grupo: 0, classe: 0, subclasse: 0 },
              rev4: { seccao: 0, divisao: 0, grupo: 0, classe: 0, subclasse: 0 },
            },
          }),
        );
      }
      return Promise.reject(new Error(`no stub for ${raw}`));
    });
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <ToolsPage />
      </StaticPermissionsProvider>,
      ['/tools?q=segredo'],
    );

    expect(await screen.findByRole('button', { name: 'Catálogo CAE' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Pesquisa' })).toBeNull();
    expect(screen.queryByRole('searchbox', { name: 'Pesquisar' })).toBeNull();
    expect(screen.queryByText('Tipos de resultado')).toBeNull();
    expect(document.body.textContent).not.toContain('segredo');
    expect(fetchMock.mock.calls.some(([url]) => String(url).startsWith('/v1/search'))).toBe(false);
  });

  it('renders result errors distinctly from an empty response', async () => {
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const raw = typeof input === 'string' ? input : input.toString();
      if (raw === '/v1/search/status') return Promise.resolve(json(STATUS));
      if (raw.startsWith('/v1/search?')) {
        return Promise.resolve(json({ error: 'search temporarily unavailable' }, 503));
      }
      return Promise.reject(new Error(`no stub for ${raw}`));
    });
    vi.stubGlobal('fetch', fetchMock);

    renderWithProviders(<SearchPage />, ['/tools?q=assembleia']);

    expect(await screen.findByText('search temporarily unavailable')).toBeTruthy();
    expect(screen.queryByText('Nenhum resultado encontrado')).toBeNull();
  });
});

describe('searchHitRoute', () => {
  const routeHit = (overrides: Partial<SearchHit>) =>
    hit({
      entity_id: null,
      book_id: null,
      act_id: null,
      ...overrides,
    });

  it.each([
    ['entity', routeHit({ kind: 'entity', id: 'entity:ent/1' }), '/entities/ent%2F1'],
    ['book', routeHit({ kind: 'book', id: 'book:book-1' }), '/books/book-1'],
    ['act', routeHit({ kind: 'act', id: 'act:act-1' }), '/acts/act-1'],
    [
      'template',
      routeHit({ kind: 'template', id: 'template:user:template-1' }),
      '/templates/template-1',
    ],
    [
      'law article',
      routeHit({ kind: 'law_article', id: 'law:CSC:63' }),
      '/tools/legislation?diploma=CSC&artigo=63',
    ],
    [
      'operational action',
      routeHit({ kind: 'operational_action', id: 'operational_action:op-1' }),
      '/dashboard/queue',
    ],
    ['ledger event', routeHit({ kind: 'ledger_event', id: 'ledger_event:9' }), '/archive'],
    [
      'follow-up',
      routeHit({ kind: 'follow_up', id: 'follow_up:f-1', act_id: 'act-2' }),
      '/acts/act-2',
    ],
    [
      'imported document',
      routeHit({
        kind: 'imported_document',
        id: 'imported_document:import-1',
        act_id: 'act-2',
      }),
      '/acts/act-2?focus=import-review&imported_document_id=import-1#imported-documents',
    ],
    [
      'paper book',
      routeHit({ kind: 'paper_book', id: 'paper_book:p-1', book_id: 'book-2' }),
      '/books/book-2/imports',
    ],
    [
      'OCR draft',
      routeHit({ kind: 'ocr_draft', id: 'ocr_draft:o-1', book_id: 'book-2' }),
      '/books/book-2/imports',
    ],
    [
      'generated document',
      routeHit({
        kind: 'generated_document',
        id: 'generated_document:g-1',
        act_id: 'act-2',
      }),
      '/acts/act-2?focus=dispatch-evidence&generated_document_id=g-1#generated-dispatch-evidence',
    ],
  ])('maps %s to its owning surface', (_label, input, expected) => {
    expect(searchHitRoute(input)).toBe(expected);
  });

  it('keeps library templates on the catalogue and omits unsafe actions without a parent', () => {
    expect(
      searchHitRoute(routeHit({ kind: 'template', id: 'template:library:official:ata' })),
    ).toBe('/templates');
    expect(
      searchHitRoute(routeHit({ kind: 'imported_document', id: 'imported_document:orphan' })),
    ).toBeNull();
  });
});
