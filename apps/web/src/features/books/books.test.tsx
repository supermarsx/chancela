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
  type PaperBookImportView,
  type PaperBookOcrDraftView,
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

function bookDetailFetch(
  extra?: (url: string, method: string, body: Record<string, unknown> | null) => Response | null,
) {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    calls.push({ url, method, body });

    const custom = extra?.(url, method, body);
    if (custom) return Promise.resolve(custom);
    if (url === '/v1/books/book-1') return Promise.resolve(jsonResponse(BOOK));
    if (url === '/v1/books/book-1/acts') return Promise.resolve(jsonResponse([]));
    if (url === '/v1/entities/ent-1') return Promise.resolve(jsonResponse(ENTITY));
    if (url === '/v1/books/paper-import?book_ref=book-1') return Promise.resolve(jsonResponse([]));
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

describe('BookDetailPage — paper-book preserved imports', () => {
  function renderAtBook() {
    renderWithProviders(
      <Routes>
        <Route path="/livros/:id" element={<BookDetailPage />} />
      </Routes>,
      ['/livros/book-1'],
    );
  }

  it('lists preserved paper-book import metadata and downloads retained package bytes', async () => {
    const preserved: PaperBookImportView = {
      import_id: '11111111-1111-4111-8111-111111111111',
      entity_ref: 'ent-legacy',
      entity_name: 'Encosto Estratégico, S.A.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_from: 12,
      page_to: 251,
      page_count: 240,
      sha256: 'ab'.repeat(32),
      size_bytes: 2048,
      content_type: 'application/pdf',
      source_filename: 'ag-1968-1971.pdf',
      notes: 'Digitalizado do livro encadernado.',
      imported_at: '2026-07-09T10:00:00Z',
      imported_by: 'paper.owner',
      ocr_status: 'not_run',
      ocr_status_notice:
        'OCR status is operator-visible metadata only. Chancela has not extracted, verified, or stored authoritative OCR text for this preserved paper-book package.',
      ocr_text_stored: false,
      authoritative_text_claimed: false,
      non_canonical: true,
      legal_validity_claimed: false,
      signature_validity_claimed: false,
      qualified_signature_claimed: false,
      manual_review_state: 'needs_review',
      legal_notice: 'Historical paper-book package preserved as non-canonical evidence only.',
      bytes_download: '/v1/books/paper-import/11111111-1111-4111-8111-111111111111/bytes',
    };
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'ag-1968-1971.pdf',
      contentType: 'application/pdf',
      bytes: 8,
    });
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (
        url === '/v1/books/paper-import/11111111-1111-4111-8111-111111111111/ocr-drafts' &&
        method === 'GET'
      ) {
        return jsonResponse([]);
      }
      if (
        url === '/v1/books/paper-import/11111111-1111-4111-8111-111111111111/bytes' &&
        method === 'GET'
      ) {
        return new Response('pdfbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/pdf' },
        });
      }
      if (
        url === '/v1/books/paper-import/11111111-1111-4111-8111-111111111111/ocr/enqueue' &&
        method === 'POST'
      ) {
        return jsonResponse({
          import_id: preserved.import_id,
          previous_ocr_status: 'not_run',
          ocr_status: 'queued',
          status_notice: preserved.ocr_status_notice,
          ocr_text_stored: false,
          authoritative_text_claimed: false,
          legal_validity_claimed: false,
          legal_notice: preserved.legal_notice,
        });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('Importações de livro em papel preservadas')).toBeTruthy();
    expect(await screen.findByText('ag-1968-1971.pdf')).toBeTruthy();
    expect(screen.getByText('1968-01-01 a 1971-12-31')).toBeTruthy();
    expect(screen.getByText('Intervalo: 12 a 251')).toBeTruthy();
    expect(screen.getByText('Revisão manual pendente')).toBeTruthy();
    expect(screen.getByText(/Âmbito de arquivo: paper-book-import:11111111/i)).toBeTruthy();
    expect(screen.getByText(/não declaram validade legal/i)).toBeTruthy();
    expect(screen.getByText('OCR não executado')).toBeTruthy();
    expect(screen.getByText(/OCR: metadado apenas; texto armazenado: não/i)).toBeTruthy();
    expect(await screen.findByText('Rascunhos OCR e revisão auxiliar')).toBeTruthy();
    expect(screen.getByText(/não criam texto legal, ata canónica/i)).toBeTruthy();
    expect(screen.getByText('Sem rascunhos OCR registados')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Descarregar pacote' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as { blob: Blob; filename: string };
    expect(saved.filename).toBe('ag-1968-1971.pdf');
    expect(await blobText(saved.blob)).toBe('pdfbytes');
    expect(calls).toContainEqual({
      url: '/v1/books/paper-import?book_ref=book-1',
      method: 'GET',
      body: null,
    });
    expect(calls).toContainEqual({
      url: '/v1/books/paper-import/11111111-1111-4111-8111-111111111111/bytes',
      method: 'GET',
      body: null,
    });

    fireEvent.click(screen.getByRole('button', { name: 'Colocar OCR em fila' }));
    await waitFor(() =>
      expect(calls).toContainEqual({
        url: '/v1/books/paper-import/11111111-1111-4111-8111-111111111111/ocr/enqueue',
        method: 'POST',
        body: null,
      }),
    );
  });

  it('creates and reviews OCR drafts as auxiliary non-canonical metadata only', async () => {
    const preserved: PaperBookImportView = {
      import_id: '33333333-3333-4333-8333-333333333333',
      entity_ref: 'ent-1',
      entity_name: 'Encosto Estratégico, Lda.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_count: 240,
      sha256: 'cd'.repeat(32),
      size_bytes: 4096,
      content_type: 'application/pdf',
      source_filename: 'ag-ocr.pdf',
      notes: null,
      imported_at: '2026-07-09T10:00:00Z',
      imported_by: 'paper.owner',
      ocr_status: 'completed',
      ocr_status_notice:
        'OCR status is operator-visible metadata only. Chancela has not extracted, verified, or stored authoritative OCR text for this preserved paper-book package.',
      ocr_text_stored: false,
      authoritative_text_claimed: false,
      non_canonical: true,
      legal_validity_claimed: false,
      signature_validity_claimed: false,
      qualified_signature_claimed: false,
      legal_notice: 'Historical paper-book package preserved as non-canonical evidence only.',
      bytes_download: '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/bytes',
    };
    const createdDraft: PaperBookOcrDraftView = {
      draft_id: '44444444-4444-4444-8444-444444444444',
      import_id: preserved.import_id,
      extracted_text: 'Livro de atas digitalizado.',
      text_digest: null,
      page_spans: [{ start_page: 1, end_page: 2 }],
      confidence: 0.87,
      engine: { name: 'operator-supplied-ocr', version: null },
      created_at: '2026-07-10T09:30:00Z',
      created_by: 'paper.owner',
      review_status: 'unreviewed',
      reviewed_at: null,
      reviewed_by: null,
      review_note: null,
      superseded_by: null,
      draft_notice:
        'OCR draft results are non-authoritative review aids linked to preserved paper-book imports. They are not canonical minutes, legal text, or a legal-validity claim.',
      non_canonical: true,
      authoritative_text_claimed: false,
      canonical_minutes_claimed: false,
      canonical_act_created: false,
      canonical_document_created: false,
      signature_created: false,
      legal_validity_claimed: false,
      legal_notice: 'Historical paper-book package preserved as non-canonical evidence only.',
    };
    let drafts: PaperBookOcrDraftView[] = [];
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (
        url === '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts' &&
        method === 'GET'
      ) {
        return jsonResponse(drafts);
      }
      if (
        url === '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts' &&
        method === 'POST'
      ) {
        drafts = [createdDraft];
        return jsonResponse(createdDraft, 201);
      }
      if (
        url ===
          '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts/44444444-4444-4444-8444-444444444444/review' &&
        method === 'PATCH'
      ) {
        const reviewed = {
          ...createdDraft,
          review_status: 'accepted',
          reviewed_at: '2026-07-10T10:00:00Z',
          reviewed_by: 'paper.reviewer',
          review_note: 'Conferido contra o pacote preservado.',
        } satisfies PaperBookOcrDraftView;
        drafts = [reviewed];
        return jsonResponse(reviewed);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('Rascunhos OCR e revisão auxiliar')).toBeTruthy();
    expect(await screen.findByText('Sem rascunhos OCR registados')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Texto OCR auxiliar'), {
      target: { value: 'Livro de atas digitalizado.' },
    });
    fireEvent.change(screen.getByLabelText('Página final'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Confiança'), { target: { value: '0.87' } });
    fireEvent.click(screen.getByLabelText(/Confirmo que este rascunho OCR é auxiliar/i));
    fireEvent.click(screen.getByRole('button', { name: 'Guardar rascunho OCR' }));

    expect(
      await screen.findByText('Rascunho OCR guardado como metadado auxiliar não canónico.'),
    ).toBeTruthy();
    expect(await screen.findByText('Livro de atas digitalizado.')).toBeTruthy();
    expect(screen.getAllByText(/Texto autoritativo: não/i).length).toBeGreaterThanOrEqual(1);
    const createCall = calls.find(
      (call) =>
        call.url === '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts' &&
        call.method === 'POST',
    );
    expect(createCall?.body).toMatchObject({
      extracted_text: 'Livro de atas digitalizado.',
      page_spans: [{ start_page: 1, end_page: 2 }],
      confidence: 0.87,
      engine_name: 'operator-supplied-ocr',
    });

    fireEvent.change(screen.getByLabelText('Estado da revisão OCR'), {
      target: { value: 'accepted' },
    });
    fireEvent.change(screen.getByLabelText('Nota da revisão OCR'), {
      target: { value: 'Conferido contra o pacote preservado.' },
    });
    fireEvent.click(screen.getByLabelText(/Confirmo que esta revisão é apenas metadado auxiliar/i));
    fireEvent.click(screen.getByRole('button', { name: 'Guardar revisão OCR' }));

    expect(
      await screen.findByText('Revisão OCR guardada como metadado auxiliar não canónico.'),
    ).toBeTruthy();
    expect((await screen.findAllByText('Aceite para referência auxiliar')).length).toBeGreaterThan(
      0,
    );
    const reviewCall = calls.find(
      (call) =>
        call.url ===
          '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts/44444444-4444-4444-8444-444444444444/review' &&
        call.method === 'PATCH',
    );
    expect(reviewCall?.body).toMatchObject({
      review_status: 'accepted',
      review_note: 'Conferido contra o pacote preservado.',
      superseded_by: null,
    });
  });

  it('validates and preserves a scanned paper-book package as non-canonical evidence', async () => {
    const digest = 'ab'.repeat(32);
    const selectedBytes = new Uint8Array([37, 80, 68, 70]);
    const preserved: PaperBookImportView = {
      import_id: '22222222-2222-4222-8222-222222222222',
      entity_ref: 'ent-1',
      entity_name: 'Encosto Estratégico, Lda.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_count: 240,
      sha256: digest,
      size_bytes: selectedBytes.byteLength,
      content_type: 'application/pdf',
      source_filename: 'ag-1968-1971.pdf',
      notes: 'Digitalizado do livro encadernado.',
      imported_at: '2026-07-09T10:00:00Z',
      imported_by: 'paper.owner',
      ocr_status: 'not_run',
      ocr_status_notice:
        'OCR status is operator-visible metadata only. Chancela has not extracted, verified, or stored authoritative OCR text for this preserved paper-book package.',
      ocr_text_stored: false,
      authoritative_text_claimed: false,
      non_canonical: true,
      legal_validity_claimed: false,
      signature_validity_claimed: false,
      qualified_signature_claimed: false,
      legal_notice: 'Historical paper-book package preserved as non-canonical evidence only.',
      bytes_download: '/v1/books/paper-import/22222222-2222-4222-8222-222222222222/bytes',
    };
    const validationReport = {
      report_kind: 'paper_book_import_validation',
      dry_run: true,
      legal_notice:
        'Historical paper-book scans are classified as non-canonical evidence only. This report does not preserve the package, replace canonical digital minutes, or claim PDF/A, legal, or qualified-signature validity.',
      identity: {
        entity_ref: 'ent-1',
        entity_name: 'Encosto Estratégico, Lda.',
        entity_nipc: '503004642',
        book_ref: 'book-1',
      },
      date_span: { from: '1968-01-01', to: '1971-12-31' },
      package: {
        page_count: 240,
        source_filename: 'ag-1968-1971.pdf',
        digest,
        notes_present: true,
        notes_truncated: false,
      },
      candidate_classification: {
        classification: 'historical_paper_book_non_canonical_evidence',
        non_canonical: true,
        historical_evidence: true,
        preservation_status: 'not_preserved_by_validation',
        canonical_minutes_claimed: false,
        legal_validity_claimed: false,
        signature_validity_claimed: false,
        qualified_signature_claimed: false,
      },
      can_accept_as_import_candidate: true,
      required_operator_actions: ['review_report'],
      findings: [],
    };
    const preservationReport = {
      ...validationReport,
      report_kind: 'paper_book_import_preservation',
      dry_run: false,
      import_id: preserved.import_id,
      legal_notice: preserved.legal_notice,
      preservation: {
        status: 'preserved_non_canonical_package',
        non_canonical: true,
        sha256: digest,
        size_bytes: selectedBytes.byteLength,
        content_type: 'application/pdf',
        imported_at: '2026-07-09T10:00:00Z',
        imported_by: 'paper.owner',
        ocr_status: 'not_run',
        bytes_in_ledger_event: false,
        legal_validity_claimed: false,
      },
      candidate_classification: {
        ...validationReport.candidate_classification,
        preservation_status: 'preserved_non_canonical_package',
      },
    };
    let rows: PaperBookImportView[] = [];
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse(rows);
      }
      if (
        url === '/v1/books/paper-import/22222222-2222-4222-8222-222222222222/ocr-drafts' &&
        method === 'GET'
      ) {
        return jsonResponse([]);
      }
      if (url === '/v1/books/paper-import/validate' && method === 'POST') {
        return jsonResponse(validationReport);
      }
      if (url === '/v1/books/paper-import' && method === 'POST') {
        rows = [preserved];
        return jsonResponse(preservationReport, 201);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    vi.stubGlobal('crypto', {
      subtle: {
        digest: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xab).buffer),
      },
    });

    renderAtBook();

    const file = new File([selectedBytes], 'ag-1968-1971.pdf', { type: 'application/pdf' });
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(selectedBytes.buffer),
    });
    fireEvent.change(await screen.findByLabelText('Pacote digitalizado'), {
      target: { files: [file] },
    });
    fireEvent.change(screen.getByLabelText('Data inicial'), { target: { value: '1968-01-01' } });
    fireEvent.change(screen.getByLabelText('Data final'), { target: { value: '1971-12-31' } });
    fireEvent.change(screen.getByLabelText('Páginas'), { target: { value: '240' } });
    fireEvent.change(screen.getByLabelText('Notas'), {
      target: { value: 'Digitalizado do livro encadernado.' },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Validar sem preservar' }));
    expect(await screen.findByText('Relatório não canónico')).toBeTruthy();
    expect(screen.getByText(/não substituem atas digitais canónicas/i)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Preservar pacote' }));

    expect(
      await screen.findByText('Pacote de livro em papel preservado como evidência não canónica.'),
    ).toBeTruthy();
    expect(await screen.findByText('ag-1968-1971.pdf')).toBeTruthy();
    expect(screen.getByText('Intervalo: Intervalo de páginas não exposto pela API')).toBeTruthy();
    expect(screen.getByText('Revisão manual não exposta pela API')).toBeTruthy();
    expect(await screen.findByText('Sem rascunhos OCR registados')).toBeTruthy();
    const preserveCall = calls.find(
      (call) => call.url === '/v1/books/paper-import' && call.method === 'POST',
    );
    expect(preserveCall?.body).toMatchObject({
      entity_ref: 'ent-1',
      entity_name: 'Encosto Estratégico, Lda.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      declared_sha256: digest,
      size_bytes: 4,
      content_type: 'application/pdf',
    });
    expect(preserveCall?.body?.content_base64).toBe('JVBERg==');
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
