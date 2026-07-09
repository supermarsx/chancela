import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders, fetchTable } from '../../test/utils';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn(
    (result: { filename: string }) =>
      `Transferência iniciada pelo navegador: ${result.filename}. A pasta é definida pelo browser.`,
  ),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { BookDetailPage } from './BookDetailPage';
import { BooksPage } from './BooksPage';
import { NewBookPage } from './NewBookPage';
import { OpenBookForm } from './OpenBookForm';
import {
  DEFAULT_SETTINGS,
  type BookLegalHoldView,
  type BookView,
  type Entity,
} from '../../api/types';

const ENTITY: Entity = {
  id: 'ent-1',
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
  nipc_validated: true,
  seat: 'Lisboa',
  family: 'CommercialCompany',
  kind: 'SociedadePorQuotas',
  profile: {
    family: 'CommercialCompany',
    rule_pack_id: 'csc-art63/v2',
    allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
    signature_policy: 'QualifiedPreferred',
    template_family: 'csc-commercial',
    calendar_presets: [],
  },
  statute: null,
};

const BOOK: BookView = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Atas da Assembleia',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 0,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

interface RecordedCall {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
  });
}

function bookDetailFetch(extra?: (url: string, method: string) => Response | null) {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    calls.push({ url, method, body });

    const custom = extra?.(url, method);
    if (custom) return Promise.resolve(custom);
    if (url === '/v1/books/book-1') return Promise.resolve(jsonResponse(BOOK));
    if (url === '/v1/books/book-1/acts') return Promise.resolve(jsonResponse([]));
    if (url === '/v1/books/book-1/legal-hold') {
      return Promise.resolve(
        jsonResponse({ legal_hold: false, reason: null, actor: null, set_at: null }),
      );
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

describe('BooksPage', () => {
  it('offers a neat button to the open-book route instead of an inline form', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/books', body: [] }]));
    renderWithProviders(<BooksPage />, ['/livros']);

    const abrir = await screen.findByRole('link', { name: /abrir livro/i });
    expect(abrir.getAttribute('href')).toBe('/livros/novo');
    // No inline open-book form on the list page.
    expect(screen.queryByLabelText('Tipo de livro')).toBeNull();
  });

  it('filters the books list by search, state and type, then clears back to all rows', async () => {
    const books: BookView[] = [
      { ...BOOK, id: 'book-ag', purpose: 'Atas da Assembleia', state: 'Open' },
      {
        ...BOOK,
        id: 'book-gerencia',
        kind: 'GerenciaAdministracao',
        state: 'Closed',
        purpose: 'Atas da Gerência',
        opening_date: '2025-01-01',
        closing_date: '2025-12-31',
        last_ata_number: 4,
      },
      {
        ...BOOK,
        id: 'book-condominio',
        kind: 'Condominio',
        state: 'Created',
        purpose: 'Administração do prédio',
        opening_date: '2026-06-01',
      },
    ];
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/books', body: books }]));
    renderWithProviders(<BooksPage />, ['/livros']);

    expect(await screen.findByText('Atas da Assembleia')).toBeTruthy();
    expect(screen.getByText('Atas da Gerência')).toBeTruthy();
    expect(screen.getByText('Administração do prédio')).toBeTruthy();
    expect(screen.getByLabelText('A mostrar 3 de 3 livros')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Pesquisar'), { target: { value: 'gerencia' } });
    await waitFor(() => expect(screen.queryByText('Atas da Assembleia')).toBeNull());
    expect(screen.getByText('Atas da Gerência')).toBeTruthy();
    expect(screen.queryByText('Administração do prédio')).toBeNull();
    expect(screen.getByLabelText('A mostrar 1 de 3 livros')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Limpar filtros de livros' }));
    await waitFor(() => expect(screen.getByText('Atas da Assembleia')).toBeTruthy());

    fireEvent.change(screen.getByLabelText('Estado'), { target: { value: 'Created' } });
    expect(await screen.findByText('Administração do prédio')).toBeTruthy();
    expect(screen.queryByText('Atas da Assembleia')).toBeNull();
    expect(screen.queryByText('Atas da Gerência')).toBeNull();

    fireEvent.change(screen.getByLabelText('Tipo'), { target: { value: 'Condominio' } });
    expect(screen.getByText('Administração do prédio')).toBeTruthy();
    expect(screen.getByLabelText('A mostrar 1 de 3 livros')).toBeTruthy();
  });

  it('keeps advanced book filters collapsed and filters by activity/date when expanded', async () => {
    const books: BookView[] = [
      { ...BOOK, id: 'book-empty', purpose: 'Sem atas ainda', opening_date: '2024-01-01' },
      {
        ...BOOK,
        id: 'book-active',
        purpose: 'Atas em curso',
        opening_date: '2026-02-01',
        last_ata_number: 7,
      },
      {
        ...BOOK,
        id: 'book-successor',
        purpose: 'Livro reiniciado',
        opening_date: '2026-03-01',
        predecessor: 'book-old',
      },
    ];
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/books', body: books }]));
    const { container } = renderWithProviders(<BooksPage />, ['/livros']);

    expect(await screen.findByText('Sem atas ainda')).toBeTruthy();
    const advanced = container.querySelector('details.filter-advanced') as HTMLDetailsElement;
    expect(advanced.open).toBe(false);

    fireEvent.click(screen.getByText('Filtros avançados'));
    expect(advanced.open).toBe(true);

    const advancedFilters = within(advanced);
    fireEvent.change(advancedFilters.getByLabelText('Atividade'), {
      target: { value: 'has-acts' },
    });
    expect(await screen.findByText('Atas em curso')).toBeTruthy();
    expect(screen.queryByText('Sem atas ainda')).toBeNull();
    expect(screen.queryByText('Livro reiniciado')).toBeNull();

    fireEvent.change(advancedFilters.getByLabelText('Atividade'), { target: { value: 'all' } });
    fireEvent.change(advancedFilters.getByLabelText('Aberto desde'), {
      target: { value: '2026-02-15' },
    });
    expect(await screen.findByText('Livro reiniciado')).toBeTruthy();
    expect(screen.queryByText('Atas em curso')).toBeNull();
    expect(screen.queryByText('Sem atas ainda')).toBeNull();
  });

  it('shows an empty filtered state without losing the clear action', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/books', body: [BOOK] }]));
    renderWithProviders(<BooksPage />, ['/livros']);

    expect(await screen.findByText('Atas da Assembleia')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Pesquisar'), {
      target: { value: 'nada disto existe' },
    });

    expect(await screen.findByText('Sem resultados')).toBeTruthy();
    expect(
      screen.getByText('Altere a pesquisa ou os filtros para voltar a ver livros.'),
    ).toBeTruthy();
    const clear = screen.getByRole('button', { name: 'Limpar filtros de livros' });
    expect((clear as HTMLButtonElement).disabled).toBe(false);

    fireEvent.click(clear);
    expect(await screen.findByText('Atas da Assembleia')).toBeTruthy();
  });
});

describe('BookDetailPage — preservation package download', () => {
  function renderAtBook() {
    renderWithProviders(
      <Routes>
        <Route path="/livros/:id" element={<BookDetailPage />} />
      </Routes>,
      ['/livros/book-1'],
    );
  }

  it('saves the Chancela internal preservation package through the shared helper', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'chancela-preservation-book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/book-1/archive/package' && method === 'GET') {
        return new Response('zipbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    fireEvent.click(await screen.findByRole('button', { name: 'Pacote de preservação Chancela' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as { blob: Blob; filename: string };
    expect(saved.filename).toBe('chancela-preservation-book-book-1.zip');
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/zip');
    expect(await blobText(saved.blob)).toBe('zipbytes');
    expect(calls).toContainEqual({
      url: '/v1/books/book-1/archive/package',
      method: 'GET',
      body: null,
    });
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-download',
      filename: 'chancela-preservation-book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
    expect(screen.queryByText(/DGLAB/i)).toBeNull();
    expect(
      await screen.findByText(
        'Transferência iniciada pelo navegador: chancela-preservation-book-book-1.zip. A pasta é definida pelo browser.',
      ),
    ).toBeTruthy();
  });

  it('toasts the server error and does not create a fake package download', async () => {
    const { fn } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/book-1/archive/package' && method === 'GET') {
        return jsonResponse({ error: 'sem documentos preservados para empacotar' }, 409);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    fireEvent.click(await screen.findByRole('button', { name: 'Pacote de preservação Chancela' }));

    expect(await screen.findByText('sem documentos preservados para empacotar')).toBeTruthy();
    expect(saveFileMock.saveBlobAs).not.toHaveBeenCalled();
  });
});

describe('BookDetailPage — legal hold', () => {
  function renderAtBook() {
    renderWithProviders(
      <Routes>
        <Route path="/livros/:id" element={<BookDetailPage />} />
      </Routes>,
      ['/livros/book-1'],
    );
  }

  it('sets and clears a legal hold for the current book', async () => {
    let hold: BookLegalHoldView = { legal_hold: false, reason: null, actor: null, set_at: null };
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/book-1/legal-hold' && method === 'GET') {
        return jsonResponse(hold);
      }
      if (url === '/v1/books/book-1/legal-hold' && method === 'PUT') {
        hold = {
          legal_hold: true,
          reason: 'litígio pendente',
          actor: 'operator',
          set_at: '2026-07-09T10:00:00Z',
        };
        return jsonResponse(hold);
      }
      if (url === '/v1/books/book-1/legal-hold' && method === 'DELETE') {
        hold = { legal_hold: false, reason: null, actor: null, set_at: null };
        return jsonResponse(hold);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('Sem retenção legal')).toBeTruthy();
    expect(screen.getByText(/bloqueia o descarte por regras de retenção/i)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Motivo da retenção legal'), {
      target: { value: 'litígio pendente' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Aplicar retenção legal' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url === '/v1/books/book-1/legal-hold' && c.method === 'PUT')).toBe(
        true,
      ),
    );
    const put = calls.find((c) => c.url === '/v1/books/book-1/legal-hold' && c.method === 'PUT');
    expect(put?.body).toMatchObject({ reason: 'litígio pendente' });
    expect(await screen.findByText('Retenção legal ativa')).toBeTruthy();
    expect(await screen.findByText('Retenção legal aplicada.')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Remover retenção' }));

    await waitFor(() =>
      expect(
        calls.some((c) => c.url === '/v1/books/book-1/legal-hold' && c.method === 'DELETE'),
      ).toBe(true),
    );
    expect(await screen.findByText('Retenção legal removida.')).toBeTruthy();
  });
});

describe('NewBookPage', () => {
  function renderAt(path: string) {
    return renderWithProviders(
      <Routes>
        <Route path="/livros/novo" element={<NewBookPage />} />
      </Routes>,
      [path],
    );
  }

  it('fixes the book to the entity from the ?entidade query param (no picker)', async () => {
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/entities', body: [ENTITY] },
      ]),
    );
    renderAt('/livros/novo?entidade=ent-1');

    // The open-book form renders with no entity picker; the entity is fixed.
    expect(await screen.findByLabelText('Tipo de livro')).toBeTruthy();
    expect(screen.queryByLabelText('Entidade')).toBeNull();
    expect(screen.getByRole('button', { name: /abrir livro/i })).toBeTruthy();
    // The manual audit-actor input is gone: attribution is the signed-in user
    // (topbar picker) via X-Chancela-Session, so the form sends no body actor (t22-web).
    expect(screen.queryByLabelText(/ator/i)).toBeNull();
  });

  it('shows an empty state when there are no entities to open a book against', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/entities', body: [] }]));
    renderAt('/livros/novo');

    expect(await screen.findByText('Sem entidades')).toBeTruthy();
  });
});

describe('OpenBookForm — book-open guidance (t60)', () => {
  it('shows the autonomy info panel and per-field help on kind and numbering', async () => {
    vi.stubGlobal('fetch', fetchTable([{ match: '/v1/settings', body: DEFAULT_SETTINGS }]));

    renderWithProviders(
      <Routes>
        <Route path="/entidades/ent-1" element={<OpenBookForm entityId="ent-1" />} />
      </Routes>,
      ['/entidades/ent-1'],
    );

    // The concise autonomy-oriented info panel sits at the top of the form.
    expect(await screen.findByText('Como escolher')).toBeTruthy();
    // A FieldHelp glyph accompanies the book-kind and numbering-scheme fields (≥2 "Ajuda").
    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThanOrEqual(2);
  });
});

describe('OpenBookForm — toast on success', () => {
  it('fires a success toast after opening a book (survives navigate-away)', async () => {
    const book = { id: 'book-9', entity_id: 'ent-1' };
    vi.stubGlobal(
      'fetch',
      fetchTable([
        { match: '/v1/settings', body: DEFAULT_SETTINGS },
        { match: '/v1/books', status: 201, body: book },
      ]),
    );

    renderWithProviders(
      <Routes>
        <Route path="/entidades/ent-1" element={<OpenBookForm entityId="ent-1" />} />
        <Route path="/livros/:id" element={<div>DETALHE DO LIVRO</div>} />
      </Routes>,
      ['/entidades/ent-1'],
    );

    fireEvent.change(await screen.findByLabelText('Finalidade'), {
      target: { value: 'Atas AG' },
    });
    fireEvent.change(screen.getByLabelText('Data de abertura'), {
      target: { value: '2026-01-01' },
    });
    fireEvent.click(screen.getByRole('button', { name: /abrir livro/i }));

    expect(await screen.findByText('DETALHE DO LIVRO')).toBeTruthy();
    // R6: the toast fired in onSuccess renders even though we navigated to the book.
    expect(await screen.findByText('Livro aberto.')).toBeTruthy();
  });
});
