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
import { CloseBookForm } from './CloseBookForm';
import { NewBookPage } from './NewBookPage';
import { OpenBookForm } from './OpenBookForm';
import {
  DEFAULT_SETTINGS,
  type BookLegalHoldView,
  type BookView,
  type Entity,
  type LocalDglabInterchangeManifest,
  type PaperBookImportView,
  type PaperBookOcrConversionDossierView,
  type PaperBookOcrConversionExecutionArtifactView,
  type PaperBookOcrDraftView,
  type PaperBookOcrRunView,
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

async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

function expectCssRule(css: string, selector: RegExp, declarations: string[]) {
  const match = css.match(selector);
  expect(match?.[1]).toBeTruthy();
  const body = match?.[1] ?? '';
  for (const declaration of declarations) {
    expect(body).toContain(declaration);
  }
}

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
    if (method === 'GET' && /^\/v1\/books\/paper-import\/[^/]+\/conversion-dossiers$/.test(url)) {
      return Promise.resolve(jsonResponse([]));
    }
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

  it('renders compact filter and table hooks for constrained books-list layout', async () => {
    const longPurpose =
      'Atas da Assembleia Geral com uma finalidade extensa que deve truncar sem alargar a tabela';
    vi.stubGlobal(
      'fetch',
      fetchTable([
        {
          match: '/v1/books',
          body: [
            { ...BOOK, purpose: longPurpose, last_ata_number: 12 },
            {
              ...BOOK,
              id: 'book-closed',
              kind: 'Condominio',
              state: 'Closed',
              purpose: 'Arquivo encerrado',
              opening_date: '2024-02-03',
              last_ata_number: 2,
            },
          ],
        },
      ]),
    );
    const { container } = renderWithProviders(<BooksPage />, ['/livros']);

    expect(await screen.findByText(longPurpose)).toBeTruthy();
    const searchRegion = screen.getByRole('search', { name: 'Pesquisar e filtrar livros' });
    expect(searchRegion.classList.contains('books-filters')).toBe(true);

    const primaryFilters = container.querySelector('.books-filterbar__primary') as HTMLElement;
    expect(primaryFilters).toBeTruthy();
    expect(within(primaryFilters).getByLabelText('Pesquisar')).toBeTruthy();
    expect(within(primaryFilters).getByLabelText('Estado')).toBeTruthy();
    expect(within(primaryFilters).getByLabelText('Tipo')).toBeTruthy();

    const clear = within(primaryFilters).getByRole('button', {
      name: 'Limpar filtros de livros',
    });
    expect(clear.classList.contains('books-filterbar__clear')).toBe(true);
    expect((clear as HTMLButtonElement).disabled).toBe(true);

    const advanced = container.querySelector(
      'details.books-advanced-filters.filter-advanced',
    ) as HTMLDetailsElement;
    expect(advanced).toBeTruthy();
    expect(advanced.open).toBe(false);
    expect(
      advanced.querySelector('.books-advanced-filters__body.filter-advanced__body'),
    ).toBeTruthy();

    const tableShell = container.querySelector('.books-table') as HTMLElement;
    expect(tableShell).toBeTruthy();
    expect(tableShell.querySelector('.table-wrap')).toBeTruthy();
    expect(tableShell.querySelector("th[data-book-column='Purpose']")?.textContent).toBe(
      'Finalidade',
    );
    const purposeCell = tableShell.querySelector(
      `td[data-book-column='Purpose'] .truncate[title='${longPurpose}']`,
    );
    expect(purposeCell?.textContent).toBe(longPurpose);
    const actionCell = tableShell.querySelector(
      "td[data-book-column='Actions'].books-table__cell--actions",
    ) as HTMLElement;
    expect(actionCell).toBeTruthy();
    expect(within(actionCell).getByRole('link', { name: `Abrir: ${longPurpose}` })).toBeTruthy();
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

  it('keeps books filter and table CSS from forcing horizontal scroll or wrapping rows', async () => {
    const css = await themeCss();

    expectCssRule(css, /\.books-filterbar__primary\s*\{([^}]*)\}/, [
      'display: flex;',
      'flex-wrap: wrap;',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.books-advanced-filters__body\s*\{([^}]*)\}/, [
      'display: grid;',
      'grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.books-table \.table-wrap\s*\{([^}]*)\}/, [
      'max-width: 100%;',
      'overflow-x: hidden;',
    ]);
    expectCssRule(css, /\.books-table \.table\s*\{([^}]*)\}/, [
      'table-layout: fixed;',
      'min-width: 0;',
    ]);
    expectCssRule(css, /\.books-table \.table th,\s*\.books-table \.table td\s*\{([^}]*)\}/, [
      'overflow: hidden;',
      'white-space: nowrap;',
    ]);
    expect(css).toContain('@media (max-width: 700px)');
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

  function localDglabManifest(
    overrides: Partial<LocalDglabInterchangeManifest> = {},
  ): LocalDglabInterchangeManifest {
    return {
      schema: 'chancela-local-dglab-interchange-manifest/v1',
      profile: 'chancela-local-dglab-interchange-manifest/v1',
      package_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      source_manifest_path: 'manifest.json',
      official_dglab_interchange: false,
      dglab_certification_claimed: false,
      external_dglab_approval_obtained: false,
      legal_archive_certified: false,
      destructive_disposal_performed: false,
      producer: { name: 'Chancela', system: 'chancela-archive' },
      package_type: 'chancela-internal-preservation-package',
      package_version: '1',
      preservation_level: 'Managed',
      local_classification: {
        scheme: null,
        code: null,
        title: null,
        sensitivity: null,
      },
      rights: { holder: null, license: null, access_note: null },
      languages: ['pt-PT'],
      retention: { schedule_id: null, review_after: null, legal_hold: false },
      file_fixity_summary: {
        algorithm: 'sha256',
        file_count: 1,
        total_byte_len: 12,
      },
      evidence_index_path: 'evidence/index.json',
      files: [
        {
          path: 'documents/doc-1.pdf',
          role: 'pdf_a',
          content_type: 'application/pdf',
          byte_len: 12,
          checksum: { algorithm: 'sha256', hex_digest: 'ab'.repeat(32) },
          act_id: 'act-1',
          document_id: 'doc-1',
        },
      ],
      ...overrides,
    };
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
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('chancela-preservation-book-book-1.zip');
    expect(saved.contentType).toBe('application/zip');
    expect(saved.preferBrowserSavePicker).toBe(true);
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
    expect(
      screen.getByRole('button', { name: 'Manifesto DGLAB local (metadados JSON)' }),
    ).toBeTruthy();
    expect(
      await screen.findByText(
        'Transferência iniciada pelo navegador: chancela-preservation-book-book-1.zip. A pasta é definida pelo browser.',
      ),
    ).toBeTruthy();
  });

  it('downloads the local DGLAB interchange manifest as local metadata-only JSON', async () => {
    const manifest = localDglabManifest();
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'chancela-local-dglab-interchange-manifest-book-book-1.json',
      contentType: 'application/json',
      bytes: 1234,
    });
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/book-1/archive/local-dglab-interchange-manifest' && method === 'GET') {
        return jsonResponse(manifest);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('Manifesto DGLAB local: só metadados')).toBeTruthy();
    expect(screen.getByText(/scaffold JSON derivado do pacote interno/i)).toBeTruthy();
    expect(screen.getByText(/Não é exportação oficial DGLAB/i)).toBeTruthy();
    expect(screen.getByText(/submissão governamental/i)).toBeTruthy();
    expect(screen.getByText(/certificação arquivística legal/i)).toBeTruthy();
    await screen.findByText('Sem retenção legal');
    await screen.findByText('Sem importações preservadas');

    const beforeClick = calls.length;
    fireEvent.click(screen.getByRole('button', { name: 'Manifesto DGLAB local (metadados JSON)' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    expect(calls.slice(beforeClick)).toEqual([
      {
        url: '/v1/books/book-1/archive/local-dglab-interchange-manifest',
        method: 'GET',
        body: null,
      },
    ]);

    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      filters: { name: string; extensions: string[] }[];
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('chancela-local-dglab-interchange-manifest-book-book-1.json');
    expect(saved.filename.endsWith('.json')).toBe(true);
    expect(saved.filename.endsWith('.zip')).toBe(false);
    expect(saved.contentType).toBe('application/json');
    expect(saved.filters).toEqual([{ name: 'JSON', extensions: ['json'] }]);
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/json');

    const savedJson = JSON.parse(await blobText(saved.blob)) as LocalDglabInterchangeManifest;
    expect(savedJson.schema).toBe('chancela-local-dglab-interchange-manifest/v1');
    expect(savedJson.official_dglab_interchange).toBe(false);
    expect(savedJson.dglab_certification_claimed).toBe(false);
    expect(savedJson.external_dglab_approval_obtained).toBe(false);
    expect(savedJson.legal_archive_certified).toBe(false);
    expect(savedJson.destructive_disposal_performed).toBe(false);
    expect(savedJson.files[0].path).toBe('documents/doc-1.pdf');

    expect(calls.some((call) => call.url === '/v1/books/book-1/archive/package')).toBe(false);
    expect(calls.some((call) => call.url === '/v1/books/book-1/export')).toBe(false);
    expect(
      calls.some(
        (call) =>
          call.method !== 'GET' && /\/(document|signature|seal|archive)(\/|$)/.test(call.url),
      ),
    ).toBe(false);
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-download',
      filename: 'chancela-local-dglab-interchange-manifest-book-book-1.json',
      contentType: 'application/json',
      bytes: 1234,
    });
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

describe('BookDetailPage — termo signatories', () => {
  it('displays structured opening and closing signatories with capacity and email', async () => {
    const closedBook: BookView = {
      ...BOOK,
      state: 'Closed',
      closing_date: '2026-12-31',
      closing_reason: 'BookFull',
      required_signatories_abertura: ['Legacy opening'],
      required_signatories_encerramento: ['Legacy closing'],
      required_signatory_records_abertura: [
        { name: 'Amélia Marques', capacity: 'Chair', email: 'amelia@example.pt' },
      ],
      required_signatory_records_encerramento: [
        { name: 'Rui Nunes', capacity: 'Administrator', email: 'rui@example.pt' },
      ],
    };
    const { fn } = bookDetailFetch((url) => {
      if (url === '/v1/books/book-1') return jsonResponse(closedBook);
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route path="/livros/:id" element={<BookDetailPage />} />
      </Routes>,
      ['/livros/book-1'],
    );

    expect(await screen.findByText(/Amélia Marques/)).toBeTruthy();
    expect(screen.getByText(/amelia@example.pt/)).toBeTruthy();
    expect(screen.getByText(/Rui Nunes/)).toBeTruthy();
    expect(screen.getByText(/rui@example.pt/)).toBeTruthy();
    expect(screen.queryByText('Legacy opening')).toBeNull();
    expect(screen.queryByText('Legacy closing')).toBeNull();
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

  function preservedPaperImport(overrides: Partial<PaperBookImportView> = {}): PaperBookImportView {
    return {
      import_id: '88888888-8888-4888-8888-888888888888',
      entity_ref: 'ent-1',
      entity_name: 'Encosto Estratégico, Lda.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_count: 240,
      sha256: '88'.repeat(32),
      size_bytes: 4096,
      content_type: 'application/pdf',
      source_filename: 'ag-dossier.pdf',
      notes: null,
      imported_at: '2026-07-10T10:00:00Z',
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
      bytes_download: '/v1/books/paper-import/88888888-8888-4888-8888-888888888888/bytes',
      ...overrides,
    };
  }

  function ocrDraft(
    importId: string,
    overrides: Partial<PaperBookOcrDraftView> = {},
  ): PaperBookOcrDraftView {
    return {
      draft_id: '99999999-9999-4999-8999-999999999999',
      import_id: importId,
      extracted_text: null,
      text_digest: '99'.repeat(32),
      page_spans: [{ start_page: 1, end_page: 3 }],
      confidence: 0.91,
      engine: { name: 'operator-supplied-ocr', version: '1.0' },
      created_at: '2026-07-10T09:30:00Z',
      created_by: 'paper.owner',
      review_status: 'accepted',
      reviewed_at: '2026-07-10T10:00:00Z',
      reviewed_by: 'paper.reviewer',
      review_note: 'Conferido contra o pacote preservado.',
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
      ...overrides,
    };
  }

  function conversionDossier(
    importId: string,
    draftId: string,
    overrides: Partial<PaperBookOcrConversionDossierView> = {},
  ): PaperBookOcrConversionDossierView {
    return {
      dossier_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      import_id: importId,
      draft_id: draftId,
      source_text_digest: '99'.repeat(32),
      source_page_spans: [{ start_page: 1, end_page: 3 }],
      source_review_status: 'accepted',
      source_reviewed_at: '2026-07-10T10:00:00Z',
      source_reviewed_by: 'paper.reviewer',
      created_at: '2026-07-10T11:00:00Z',
      created_by: 'paper.owner',
      dossier_notice:
        'This paper-book OCR conversion dossier is metadata-only, non-canonical, and non-legal-validity-conferring. It records accepted OCR draft review metadata only and does not create acts, documents, signed documents, archive packages, signatures, seals, PDF/A, or PDF/UA outputs.',
      metadata_only: true,
      non_canonical: true,
      act_created: false,
      canonical_act_created: false,
      canonical_minutes_claimed: false,
      canonical_document_created: false,
      signed_document_created: false,
      archive_package_created: false,
      pdfa_created: false,
      pdfua_created: false,
      signature_created: false,
      seal_created: false,
      legal_validity_claimed: false,
      source_extracted_text_in_response: false,
      source_extracted_text_in_ledger_event: false,
      legal_notice: 'Historical paper-book package preserved as non-canonical evidence only.',
      ...overrides,
    };
  }

  function conversionExecutionArtifact(
    importId: string,
    draftId: string,
    overrides: Partial<PaperBookOcrConversionExecutionArtifactView> = {},
  ): PaperBookOcrConversionExecutionArtifactView {
    return {
      artifact_id: 'abababab-abab-4aba-8aba-abababababab',
      import_id: importId,
      draft_id: draftId,
      dossier_id: null,
      source_text_digest: '99'.repeat(32),
      source_page_spans: [{ start_page: 1, end_page: 3 }],
      source_review_status: 'accepted',
      source_reviewed_at: '2026-07-10T10:00:00Z',
      source_reviewed_by: 'paper.reviewer',
      target_act_id: '77777777-7777-4777-8777-777777777777',
      target_act_state: 'Draft',
      mutable_draft_act_created: true,
      created_at: '2026-07-10T11:30:00Z',
      created_by: 'paper.owner',
      artifact_notice:
        'Reviewed OCR conversion execution evidence for mutable draft promotion only. It does not create canonical minutes, legal text, a canonical document, a signed document, an archive package, PDF/A, PDF/UA, signatures, seals, or archive certification.',
      reviewed_conversion_execution_artifact: true,
      non_canonical: true,
      canonical_conversion_claimed: false,
      canonical_minutes_claimed: false,
      canonical_act_created: false,
      canonical_document_created: false,
      signed_document_created: false,
      archive_package_created: false,
      archive_certification_claimed: false,
      pdfa_created: false,
      pdfua_created: false,
      signature_created: false,
      seal_created: false,
      legal_validity_claimed: false,
      source_extracted_text_in_artifact: false,
      source_extracted_text_in_ledger_event: false,
      legal_notice: 'Historical paper-book package preserved as non-canonical evidence only.',
      ...overrides,
    };
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
    expect(screen.getByText(/não criam ata canónica, documento canónico, PDF\/A/i)).toBeTruthy();
    expect(screen.getByText('Sem rascunhos OCR registados')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Descarregar pacote' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('ag-1968-1971.pdf');
    expect(saved.contentType).toBe('application/pdf');
    expect(saved.preferBrowserSavePicker).toBe(true);
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

  it('summarizes missing OCR draft metadata without creating a conversion dossier', async () => {
    const preserved = preservedPaperImport({
      import_id: '12121212-1212-4212-8212-121212121212',
      bytes_download: '/v1/books/paper-import/12121212-1212-4212-8212-121212121212/bytes',
    });
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (url === `/v1/books/paper-import/${preserved.import_id}/ocr-drafts` && method === 'GET') {
        return jsonResponse([]);
      }
      if (
        url === `/v1/books/paper-import/${preserved.import_id}/conversion-dossiers` &&
        method === 'GET'
      ) {
        return jsonResponse([]);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    const summary = await screen.findByRole('region', {
      name: 'Resumo de profundidade OCR e dossier do livro em papel',
    });
    expect(within(summary).getByText('Resumo OCR/dossier derivado')).toBeTruthy();
    expect(
      within(summary).getByText('Sem rascunho OCR revisto nos metadados carregados.'),
    ).toBeTruthy();
    expect(within(summary).getByText('Sem rascunho OCR aceite.')).toBeTruthy();
    expect(
      await within(summary).findByText('Sem dossier aplicável sem rascunho aceite.'),
    ).toBeTruthy();
    const preflight = await screen.findByRole('region', {
      name: /Preflight de conversão canónica OCR/i,
    });
    expect(within(preflight).getByText('Preflight canónico OCR read-only')).toBeTruthy();
    expect(within(preflight).getByText(/Metadata-only, read-only, non-canonical/i)).toBeTruthy();
    expect(within(preflight).getByText('bloqueado')).toBeTruthy();
    expect(within(preflight).getAllByText(/accepted_ocr_draft_required/i).length).toBeGreaterThan(
      0,
    );
    expect(
      within(preflight).getAllByText(/metadata_only_conversion_dossier_required/i).length,
    ).toBeGreaterThan(0);
    expect(
      within(preflight).getByText(/legal_acceptance_recorded_is_operator_evidence_only/i),
    ).toBeTruthy();
    expect(within(preflight).getByText(/raw_ocr_text_in_report: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/canonical_act_created: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/canonical_document_created: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/signature_created: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/signing_requested: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/legal_validity_claimed: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/PDF\/A: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/PDF\/UA: false/i)).toBeTruthy();
    expect(screen.getByText('Sem rascunhos OCR registados')).toBeTruthy();
    expect(
      calls.some((call) => call.url.endsWith('/conversion-dossier') && call.method === 'POST'),
    ).toBe(false);
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
    const rawArtifactText = 'raw OCR text from a malformed promotion artifact must stay hidden';
    const artifact = conversionExecutionArtifact(preserved.import_id, createdDraft.draft_id, {
      artifact_id: '66666666-6666-4666-8666-666666666666',
      target_act_id: '77777777-7777-4777-8777-777777777777',
      source_page_spans: [{ start_page: 1, end_page: 2 }],
    });
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
      if (
        url ===
          '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts/44444444-4444-4444-8444-444444444444/canonical-draft' &&
        method === 'POST'
      ) {
        return jsonResponse(
          {
            import_id: preserved.import_id,
            draft_id: createdDraft.draft_id,
            act: {
              id: '77777777-7777-4777-8777-777777777777',
              book_id: 'book-1',
              title: 'Rascunho de ata a partir de OCR do livro em papel (paginas 1-2)',
              channel: 'Physical',
              meeting_date: null,
              meeting_time: null,
              place: null,
              mesa: { chair: null, secretaries: [] },
              agenda: [],
              attendance_reference: null,
              members_present: null,
              members_represented: null,
              referenced_documents: [],
              deliberations: 'Livro de atas digitalizado.',
              deliberation_items: [],
              telematic_evidence: null,
              attachments: [],
              signatories: [],
              state: 'Draft',
              ata_number: null,
              payload_digest: null,
              seal_event_seq: null,
              seal_metadata: null,
              retifies: null,
            },
            conversion_execution_artifact: { ...artifact, extracted_text: rawArtifactText },
            draft_act_created: true,
            act_state: 'Draft',
            notice:
              'Accepted OCR draft text was copied into a new mutable draft act as a drafting aid only. No canonical document, PDF/A, signature, seal, or legal-validity acceptance was created.',
            ocr_text_copied_to_deliberations: true,
            ocr_text_in_ledger_event: false,
            non_canonical: true,
            authoritative_text_claimed: false,
            canonical_conversion_claimed: false,
            canonical_minutes_claimed: false,
            canonical_act_created: false,
            canonical_document_created: false,
            signed_document_created: false,
            archive_package_created: false,
            archive_certification_claimed: false,
            pdfa_created: false,
            signature_created: false,
            seal_created: false,
            legal_validity_claimed: false,
            legal_notice: preserved.legal_notice,
          },
          201,
        );
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
    expect(screen.queryByRole('button', { name: 'Criar rascunho de ata' })).toBeNull();
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
    expect(await screen.findByRole('button', { name: 'Criar rascunho de ata' })).toBeTruthy();
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

    fireEvent.click(screen.getByRole('button', { name: 'Criar rascunho de ata' }));

    expect(
      await screen.findByText(
        'Rascunho de ata criado sem documento canónico, PDF/A, assinatura ou selo.',
      ),
    ).toBeTruthy();
    expect(
      (await screen.findAllByRole('link', { name: 'abrir ata' })).some(
        (link) => link.getAttribute('href') === '/atas/77777777-7777-4777-8777-777777777777',
      ),
    ).toBe(true);
    const actDraftCall = calls.find(
      (call) =>
        call.url ===
          '/v1/books/paper-import/33333333-3333-4333-8333-333333333333/ocr-drafts/44444444-4444-4444-8444-444444444444/canonical-draft' &&
        call.method === 'POST',
    );
    expect(actDraftCall).toBeTruthy();
    const artifactRegion = await screen.findByRole('region', {
      name: 'Evidência de execução de conversão revista 66666666-6666-4666-8666-666666666666',
    });
    expect(
      within(artifactRegion).getByText('Evidência de promoção para rascunho mutável'),
    ).toBeTruthy();
    expect(within(artifactRegion).getByText('Promoção para rascunho mutável')).toBeTruthy();
    expect(within(artifactRegion).getByText(/ata mutável criada:\s*sim/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/conversão canónica:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/arquivo legal\/pacote:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/certificação de arquivo:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/PDF\/UA:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/No artefacto:\s*não/i)).toBeTruthy();
    expect(screen.queryByText(rawArtifactText)).toBeNull();
    expect(screen.getAllByText(/PDF\/A: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/assinatura: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/selo: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/validade legal: não/i).length).toBeGreaterThanOrEqual(1);
    expect(calls.some((call) => /\/(document|signature|seal|archive)(\/|$)/.test(call.url))).toBe(
      false,
    );
  });

  it('creates a metadata-only conversion dossier for an accepted OCR draft on operator action', async () => {
    const preserved = preservedPaperImport();
    const draft = ocrDraft(preserved.import_id);
    const rawOcrText = 'raw OCR text from a malformed dossier response must stay hidden';
    const createdDossier = conversionDossier(preserved.import_id, draft.draft_id);
    let dossiers: PaperBookOcrConversionDossierView[] = [];
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (url === `/v1/books/paper-import/${preserved.import_id}/ocr-drafts` && method === 'GET') {
        return jsonResponse([draft]);
      }
      if (
        url === `/v1/books/paper-import/${preserved.import_id}/conversion-dossiers` &&
        method === 'GET'
      ) {
        return jsonResponse(dossiers);
      }
      if (
        url ===
          `/v1/books/paper-import/${preserved.import_id}/ocr-drafts/${draft.draft_id}/conversion-dossier` &&
        method === 'POST'
      ) {
        dossiers = [createdDossier];
        return jsonResponse({ ...createdDossier, extracted_text: rawOcrText }, 201);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    const create = await screen.findByRole('button', {
      name: 'Criar dossier de conversão só de metadados',
    });
    const summary = await screen.findByRole('region', {
      name: 'Resumo de profundidade OCR e dossier do livro em papel',
    });
    expect(within(summary).getByText('Resumo OCR/dossier derivado')).toBeTruthy();
    expect(
      within(summary).getByText(/Aceite para referência auxiliar, sem conversão canónica/i),
    ).toBeTruthy();
    expect(within(summary).getByText('Dossier só de metadados ainda não registado.')).toBeTruthy();
    expect(within(summary).getByText(/Texto OCR bruto no dossier/i)).toBeTruthy();
    expect(within(summary).getByText(/^não$/i)).toBeTruthy();
    expect(within(summary).getByText(/Só metadados: sim/i)).toBeTruthy();
    expect(within(summary).getByText(/ata canónica: não/i)).toBeTruthy();
    expect(within(summary).getByText(/documento canónico: não/i)).toBeTruthy();
    expect(within(summary).getByText(/pacote de arquivo:\s* não/i)).toBeTruthy();
    expect(within(summary).getByText(/PDF\/A: não/i)).toBeTruthy();
    expect(within(summary).getByText(/PDF\/UA: não/i)).toBeTruthy();
    expect(within(summary).getByText(/validade legal: não/i)).toBeTruthy();
    expect(within(summary).queryByText(/dossier canónico/i)).toBeNull();
    expect(within(summary).queryByText(/assinatura válida/i)).toBeNull();
    expect(within(summary).queryByText(/PDF\/A certificado/i)).toBeNull();
    const preflight = await screen.findByRole('region', {
      name: /Preflight de conversão canónica OCR/i,
    });
    expect(within(preflight).getByText('Preflight canónico OCR read-only')).toBeTruthy();
    expect(
      within(preflight).getAllByText(/metadata_only_conversion_dossier_required/i).length,
    ).toBeGreaterThan(0);
    expect(within(preflight).getByText(draft.draft_id)).toBeTruthy();
    expect(within(preflight).getByText(/raw_ocr_text_in_report: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/signature_validity_claimed: false/i)).toBeTruthy();
    expect(within(preflight).getByText(/qualified_signature_claimed: false/i)).toBeTruthy();
    expect(
      calls.some((call) => call.url.endsWith('/conversion-dossier') && call.method === 'POST'),
    ).toBe(false);

    fireEvent.click(create);

    await waitFor(() =>
      expect(calls).toContainEqual({
        url: `/v1/books/paper-import/${preserved.import_id}/ocr-drafts/${draft.draft_id}/conversion-dossier`,
        method: 'POST',
        body: null,
      }),
    );
    expect(
      await screen.findByText(
        'Dossier de conversão só de metadados registado; não criou ata, documento, PDF/A, assinatura ou selo.',
      ),
    ).toBeTruthy();
    expect(await screen.findByText('Dossier já registado')).toBeTruthy();
    expect(
      within(summary).getByText(
        `Dossier só de metadados registado (${createdDossier.dossier_id}).`,
      ),
    ).toBeTruthy();
    expect(within(preflight).getByText(createdDossier.dossier_id)).toBeTruthy();
    expect(within(preflight).queryByText('metadata_only_conversion_dossier_required')).toBeNull();
    expect(
      within(preflight).getByText('evidência local reunida para revisão externa'),
    ).toBeTruthy();
    expect(within(preflight).getByText('nenhum bloqueio de metadados local')).toBeTruthy();
    expect(
      within(preflight).getByText(/legal_acceptance_recorded_is_operator_evidence_only/i),
    ).toBeTruthy();
    expect(screen.getByText(/metadata-only, non-canonical/i)).toBeTruthy();
    expect(screen.getByText(/Ata criada: não/i)).toBeTruthy();
    expect(screen.getAllByText(/documento canónico: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/PDF\/A: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/assinatura: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/selo: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/validade legal: não/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/Na resposta: não/i)).toBeTruthy();
    expect(screen.queryByText(rawOcrText)).toBeNull();
    expect(
      calls.some((call) => /\/(document|signature|seal|archive\/package)(\/|$)/.test(call.url)),
    ).toBe(false);
  });

  it('renders an existing conversion dossier without encouraging duplicate creation', async () => {
    const preserved = preservedPaperImport({
      import_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      bytes_download: '/v1/books/paper-import/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/bytes',
    });
    const draft = ocrDraft(preserved.import_id, {
      draft_id: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
      extracted_text: 'Texto OCR auxiliar visível apenas na área do rascunho.',
    });
    const dossierId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
    const artifact = conversionExecutionArtifact(preserved.import_id, draft.draft_id, {
      artifact_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      dossier_id: dossierId,
      target_act_id: '12121212-1212-4121-8121-121212121212',
    });
    const dossier = conversionDossier(preserved.import_id, draft.draft_id, {
      dossier_id: dossierId,
      conversion_execution_artifacts: [artifact],
    });
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (url === `/v1/books/paper-import/${preserved.import_id}/ocr-drafts` && method === 'GET') {
        return jsonResponse([draft]);
      }
      if (
        url === `/v1/books/paper-import/${preserved.import_id}/conversion-dossiers` &&
        method === 'GET'
      ) {
        return jsonResponse([dossier]);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('Dossier já registado')).toBeTruthy();
    const summary = await screen.findByRole('region', {
      name: 'Resumo de profundidade OCR e dossier do livro em papel',
    });
    expect(within(summary).getByText('Resumo OCR/dossier derivado')).toBeTruthy();
    expect(
      within(summary).getByText(/Aceite para referência auxiliar, sem conversão canónica/i),
    ).toBeTruthy();
    expect(
      within(summary).getByText(
        'Dossier só de metadados registado (dddddddd-dddd-4ddd-8ddd-dddddddddddd).',
      ),
    ).toBeTruthy();
    expect(within(summary).getByText(/Só metadados: sim/i)).toBeTruthy();
    expect(within(summary).getByText(/documento canónico: não/i)).toBeTruthy();
    expect(within(summary).getByText(/pacote de arquivo:\s* não/i)).toBeTruthy();
    expect(within(summary).getByText(/PDF\/UA: não/i)).toBeTruthy();
    expect(within(summary).getByText(/validade legal: não/i)).toBeTruthy();
    const artifactRegion = await screen.findByRole('region', {
      name: 'Evidência de execução de conversão revista eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    });
    expect(within(artifactRegion).getByText('Evidência revista')).toBeTruthy();
    expect(within(artifactRegion).getByText('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee')).toBeTruthy();
    expect(within(artifactRegion).getByText(dossierId)).toBeTruthy();
    expect(within(artifactRegion).getByText(/ata mutável criada:\s*sim/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/minutas canónicas:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/arquivo legal\/pacote:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/certificação de arquivo:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/assinatura:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/selo:\s*não/i)).toBeTruthy();
    expect(within(artifactRegion).getByText(/No artefacto:\s*não/i)).toBeTruthy();
    expect(screen.getAllByText(dossierId).length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText(/Digest da fonte OCR/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByRole('button', { name: /Criar dossier de conversão/i })).toBeNull();
    expect(
      calls.some((call) => call.url.endsWith('/conversion-dossier') && call.method === 'POST'),
    ).toBe(false);
    expect(calls.some((call) => /\/(document|signature|seal|archive)(\/|$)/.test(call.url))).toBe(
      false,
    );
  });

  it('does not expose conversion dossier creation for non-accepted OCR drafts', async () => {
    const preserved = preservedPaperImport({
      import_id: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
      bytes_download: '/v1/books/paper-import/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee/bytes',
    });
    const draft = ocrDraft(preserved.import_id, {
      draft_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      review_status: 'unreviewed',
      reviewed_at: null,
      reviewed_by: null,
      review_note: null,
    });
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (url === `/v1/books/paper-import/${preserved.import_id}/ocr-drafts` && method === 'GET') {
        return jsonResponse([draft]);
      }
      if (
        url === `/v1/books/paper-import/${preserved.import_id}/conversion-dossiers` &&
        method === 'GET'
      ) {
        return jsonResponse([]);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect((await screen.findAllByText('Sem revisão OCR')).length).toBeGreaterThan(0);
    const summary = await screen.findByRole('region', {
      name: 'Resumo de profundidade OCR e dossier do livro em papel',
    });
    expect(
      within(summary).getByText('Sem rascunho OCR revisto nos metadados carregados.'),
    ).toBeTruthy();
    expect(within(summary).getByText('Sem rascunho OCR aceite.')).toBeTruthy();
    expect(within(summary).getByText('Sem dossier aplicável sem rascunho aceite.')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Criar dossier de conversão/i })).toBeNull();
    expect(
      calls.some((call) => call.url.endsWith('/conversion-dossier') && call.method === 'POST'),
    ).toBe(false);
  });

  it('runs local OCR for a preserved import and exposes the auxiliary non-canonical draft', async () => {
    const preserved: PaperBookImportView = {
      import_id: '55555555-5555-4555-8555-555555555555',
      entity_ref: 'ent-1',
      entity_name: 'Encosto Estratégico, Lda.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_count: 240,
      sha256: 'ef'.repeat(32),
      size_bytes: 8192,
      content_type: 'application/pdf',
      source_filename: 'ag-local-ocr.pdf',
      notes: null,
      imported_at: '2026-07-10T10:00:00Z',
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
      bytes_download: '/v1/books/paper-import/55555555-5555-4555-8555-555555555555/bytes',
    };
    const runDraft: PaperBookOcrDraftView = {
      draft_id: '66666666-6666-4666-8666-666666666666',
      import_id: preserved.import_id,
      extracted_text: 'Livro de atas digitalizado via OCR local.',
      text_digest: null,
      page_spans: [{ start_page: 1, end_page: 240 }],
      confidence: null,
      engine: { name: 'test-local-ocr', version: '0.0.1' },
      created_at: '2026-07-10T13:40:00Z',
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
    const runResult: PaperBookOcrRunView = {
      import_id: preserved.import_id,
      previous_ocr_status: 'not_run',
      ocr_status: 'completed',
      command_configured: true,
      command_exit_success: true,
      command_exit_code: 0,
      timed_out: false,
      failure_reason: null,
      stdout_bytes_captured: 43,
      stdout_truncated: false,
      engine: runDraft.engine,
      draft: runDraft,
      status_notice: preserved.ocr_status_notice,
      draft_notice: runDraft.draft_notice,
      non_canonical: true,
      authoritative_text_claimed: false,
      canonical_minutes_claimed: false,
      canonical_act_created: false,
      canonical_document_created: false,
      signature_created: false,
      legal_validity_claimed: false,
      legal_notice: preserved.legal_notice,
    };
    let rows: PaperBookImportView[] = [preserved];
    let drafts: PaperBookOcrDraftView[] = [];
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse(rows);
      }
      if (
        url === '/v1/books/paper-import/55555555-5555-4555-8555-555555555555/ocr-drafts' &&
        method === 'GET'
      ) {
        return jsonResponse(drafts);
      }
      if (
        url === '/v1/books/paper-import/55555555-5555-4555-8555-555555555555/ocr/run' &&
        method === 'POST'
      ) {
        rows = [{ ...preserved, ocr_status: 'completed' }];
        drafts = [runDraft];
        return jsonResponse(runResult);
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('ag-local-ocr.pdf')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Executar OCR local' }));

    expect(await screen.findByRole('dialog', { name: 'Executar OCR local' })).toBeTruthy();
    expect(screen.getByText(/rascunho OCR auxiliar não canónico/i)).toBeTruthy();
    expect(
      screen.getByText(
        /não cria ata canónica, documento canónico, PDF\/A, assinatura ou validade legal/i,
      ),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Confirmar execução de OCR local' }));

    await waitFor(() =>
      expect(calls).toContainEqual({
        url: '/v1/books/paper-import/55555555-5555-4555-8555-555555555555/ocr/run',
        method: 'POST',
        body: null,
      }),
    );
    expect(
      await screen.findByText(
        'OCR local concluído: rascunho OCR auxiliar não canónico criado e disponível para revisão.',
      ),
    ).toBeTruthy();
    expect(await screen.findByText('OCR concluído')).toBeTruthy();
    expect(await screen.findByText('Livro de atas digitalizado via OCR local.')).toBeTruthy();
    expect(screen.getByText(/Rascunhos OCR são auxiliares, não canónicos/i)).toBeTruthy();
  });

  it('surfaces missing local OCR configuration without creating an auxiliary draft', async () => {
    const preserved: PaperBookImportView = {
      import_id: '77777777-7777-4777-8777-777777777777',
      entity_ref: 'ent-1',
      entity_name: 'Encosto Estratégico, Lda.',
      entity_nipc: '503004642',
      book_ref: 'book-1',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_count: 240,
      sha256: '12'.repeat(32),
      size_bytes: 8192,
      content_type: 'application/pdf',
      source_filename: 'ag-no-ocr-config.pdf',
      notes: null,
      imported_at: '2026-07-10T10:00:00Z',
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
      bytes_download: '/v1/books/paper-import/77777777-7777-4777-8777-777777777777/bytes',
    };
    const { fn, calls } = bookDetailFetch((url, method) => {
      if (url === '/v1/books/paper-import?book_ref=book-1' && method === 'GET') {
        return jsonResponse([preserved]);
      }
      if (
        url === '/v1/books/paper-import/77777777-7777-4777-8777-777777777777/ocr-drafts' &&
        method === 'GET'
      ) {
        return jsonResponse([]);
      }
      if (
        url === '/v1/books/paper-import/77777777-7777-4777-8777-777777777777/ocr/run' &&
        method === 'POST'
      ) {
        return jsonResponse(
          { error: 'operator-configured local OCR command is not configured' },
          422,
        );
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);

    renderAtBook();

    expect(await screen.findByText('ag-no-ocr-config.pdf')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Executar OCR local' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Confirmar execução de OCR local' }));

    expect(await screen.findAllByText(/operator-configured local OCR command/i)).not.toHaveLength(
      0,
    );
    expect(screen.getByText('Sem rascunhos OCR registados')).toBeTruthy();
    expect(screen.queryByText('Livro de atas digitalizado via OCR local.')).toBeNull();
    expect(calls.some((call) => call.url.endsWith('/ocr-drafts') && call.method === 'POST')).toBe(
      false,
    );
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

describe('OpenBookForm — structured termo signatories', () => {
  it('submits signatory name, capacity and normalized email fields in required_signatories', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
      calls.push({ url, method, body });
      if (url === '/v1/settings') return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      if (url === '/v1/books') {
        return Promise.resolve(jsonResponse({ ...BOOK, id: 'book-structured' }, 201));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

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
    fireEvent.change(screen.getByLabelText('Nome do signatário'), {
      target: { value: 'Amélia Marques' },
    });
    fireEvent.change(screen.getByLabelText('Qualidade'), { target: { value: 'Chair' } });
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: /abrir livro/i }));

    await screen.findByText('DETALHE DO LIVRO');
    const post = calls.find((call) => call.url === '/v1/books' && call.method === 'POST');
    expect(post?.body?.required_signatories).toEqual([
      { name: 'Amélia Marques', capacity: 'Chair', email: 'amelia@example.pt' },
    ]);
  });
});

describe('CloseBookForm — structured termo signatories', () => {
  it('submits structured closing signatories', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
      calls.push({ url, method, body });
      if (url === '/v1/books/book-1/close') return Promise.resolve(jsonResponse(BOOK));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<CloseBookForm bookId="book-1" />, ['/livros/book-1/encerrar']);

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-12-31' },
    });
    fireEvent.change(screen.getByLabelText('Nome do signatário'), {
      target: { value: 'Rui Nunes' },
    });
    fireEvent.change(screen.getByLabelText('Qualidade'), { target: { value: 'Administrator' } });
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'rui@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Encerrar livro' }));

    await waitFor(() =>
      expect(calls.some((call) => call.url === '/v1/books/book-1/close')).toBe(true),
    );
    const post = calls.find((call) => call.url === '/v1/books/book-1/close');
    expect(post?.body).toMatchObject({
      reason: 'BookFull',
      closing_date: '2026-12-31',
      required_signatories: [
        { name: 'Rui Nunes', capacity: 'Administrator', email: 'rui@example.pt' },
      ],
    });
  });
});
