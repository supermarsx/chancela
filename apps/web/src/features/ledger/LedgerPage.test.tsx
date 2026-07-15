import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import type { LedgerEventView, LedgerEventsPage } from '../../api/types';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn((result: { filename: string }) => `Guardado: ${result.filename}`),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { LedgerPage } from './LedgerPage';

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

async function themeCss(): Promise<string> {
  const nodeFs = 'node:fs';
  const { readFileSync } = (await import(nodeFs)) as {
    readFileSync(path: string, encoding: 'utf8'): string;
  };
  return readFileSync('src/theme.css', 'utf8');
}

function expectCssRule(css: string, selector: RegExp, declarations: string[]) {
  const block = css.match(selector)?.[1] ?? '';
  for (const declaration of declarations) expect(block).toContain(declaration);
}

function makeEvent(seq: number, patch: Partial<LedgerEventView> = {}): LedgerEventView {
  return {
    id: `event-${seq}`,
    seq,
    actor: 'amelia.marques',
    justification: null,
    timestamp: `2026-07-07T10:${String(seq % 60).padStart(2, '0')}:30Z`,
    scope: `act:${seq}`,
    kind: `event.${seq}`,
    payload_digest: 'aa'.repeat(32),
    prev_hash: '00'.repeat(32),
    hash: String(seq % 10).repeat(64),
    chains: ['global', 'book:book-123456789'],
    attestation: null,
    ...patch,
  };
}

const INTEGRITY = {
  healthy: true,
  degraded: false,
  global: {
    chain: 'global',
    genesis_kind: null,
    length: 1000,
    head: 'bb'.repeat(32),
    verified: true,
    first_break: null,
  },
  chains: [
    {
      chain: 'book:book-123456789',
      genesis_kind: 'book.opened',
      length: 1000,
      head: 'bb'.repeat(32),
      verified: true,
      first_break: null,
    },
  ],
  reanchored_segments: [],
};

interface RecordedCall {
  url: string;
  method: string;
}

function page(events: LedgerEventView[], patch: Partial<LedgerEventsPage> = {}): LedgerEventsPage {
  return {
    events,
    next_cursor: null,
    has_more: false,
    limit: 100,
    ...patch,
  };
}

function stubLedgerFetch(firstPage: LedgerEventsPage, olderPage = page([])) {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method });

    if (url.includes('/v1/ledger/archive/document')) {
      const format = new URL(`http://test${url}`).searchParams.get('format') ?? 'pdfa';
      const contentType =
        format === 'json'
          ? 'application/json'
          : format === 'txt'
            ? 'text/plain; charset=utf-8'
            : format === 'csv'
              ? 'text/csv; charset=utf-8'
              : format === 'html'
                ? 'text/html; charset=utf-8'
                : 'application/pdf';
      return Promise.resolve(
        new Response(format === 'pdfa' ? '%PDF-archive' : `archive-${format}`, {
          status: 200,
          headers: { 'Content-Type': contentType },
        }),
      );
    }
    if (url.includes('/v1/ledger/events/page')) {
      return Promise.resolve(jsonResponse(url.includes('before_seq=') ? olderPage : firstPage));
    }
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 1000 }));
    }
    if (url.includes('/v1/ledger/integrity')) return Promise.resolve(jsonResponse(INTEGRITY));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

describe('LedgerPage', () => {
  it('requests the first page newest-first and presents it in server order', async () => {
    const calls = stubLedgerFetch(page([makeEvent(100), makeEvent(99)]));
    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('event.100')).toBeTruthy();
    const ledgerCall = calls.find((c) => c.url.includes('/v1/ledger/events/page'));
    expect(ledgerCall?.url).toBe('/v1/ledger/events/page?limit=100&order=desc');
    expect(screen.getByText('Mais recentes primeiro')).toBeTruthy();
    expect(screen.getByText('Filtros ativos: 0')).toBeTruthy();

    const rows = screen.getAllByRole('row');
    expect(within(rows[1]).getByText('100')).toBeTruthy();
    expect(within(rows[2]).getByText('99')).toBeTruthy();
  });

  it('loads older records with the server cursor instead of fetching every event', async () => {
    const calls = stubLedgerFetch(
      page([makeEvent(100)], { next_cursor: 99, has_more: true }),
      page([makeEvent(99)]),
    );
    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('event.100')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Carregar eventos mais antigos' }));

    expect(await screen.findByText('event.99')).toBeTruthy();
    expect(
      calls.some((c) => c.url === '/v1/ledger/events/page?before_seq=99&limit=100&order=desc'),
    ).toBe(true);
  });

  it('shows a bounded first page for a 1000+ log archive and loads more by cursor', async () => {
    const firstHundred = Array.from({ length: 100 }, (_, index) => makeEvent(1050 - index));
    const calls = stubLedgerFetch(
      page(firstHundred, { next_cursor: 950, has_more: true }),
      page([makeEvent(950)]),
    );
    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('event.1050')).toBeTruthy();
    expect(screen.getByLabelText('100 eventos carregados; existem mais')).toBeTruthy();
    expect(screen.queryByText('event.1')).toBeNull();
    expect(screen.getAllByRole('row')).toHaveLength(101);
    expect(calls.filter((c) => c.url.includes('/v1/ledger/events/page'))).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Carregar eventos mais antigos' }));
    expect(await screen.findByText('event.950')).toBeTruthy();
    expect(
      calls.some(
        (c) =>
          c.url ===
          '/v1/ledger/events/page?before_seq=950&limit=100&order=desc',
      ),
    ).toBe(true);
  });

  it('applies server-backed filters and exposes an icon-only clear button with a tooltip', async () => {
    const calls = stubLedgerFetch(page([makeEvent(88, { kind: 'act.sealed' })]));
    const { container } = renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('act.sealed')).toBeTruthy();
    const searchRegion = screen.getByRole('search', { name: 'Pesquisar e filtrar arquivo' });
    expect(searchRegion.classList.contains('ledger-filters')).toBe(true);

    const clear = screen.getByRole('button', { name: 'Limpar filtros do arquivo' });
    expect(clear.textContent?.trim()).toBe('');
    expect((clear as HTMLButtonElement).disabled).toBe(true);
    const tooltipId = clear.getAttribute('aria-describedby') ?? '';
    expect(document.getElementById(tooltipId)?.textContent).toBe('Limpar filtros do arquivo');
    const iconPaths = Array.from(clear.querySelectorAll('svg.icon path')).map((path) =>
      path.getAttribute('d'),
    );
    expect(iconPaths).toContain('M4.5 5.5h15l-6 7v5l-3 1.5v-6.5z');
    expect(iconPaths).toContain('M16.5 15.5l3 3M19.5 15.5l-3 3');
    expect(iconPaths).not.toContain('M6 6l12 12M18 6 6 18');
    const advanced = container.querySelector(
      'details.ledger-advanced-filters.filter-advanced',
    ) as HTMLDetailsElement;
    expect(advanced).toBeTruthy();
    expect(advanced.open).toBe(false);
    expect(within(advanced).queryByLabelText('Filtros ativos: 0')).toBeNull();

    fireEvent.change(screen.getByLabelText('Pesquisar'), {
      target: { value: 'approved digest' },
    });
    fireEvent.change(screen.getByLabelText('Filtrar por cadeia'), {
      target: { value: 'book:book-123456789' },
    });
    fireEvent.change(screen.getByLabelText('Filtrar por âmbito'), {
      target: { value: 'act:88' },
    });
    fireEvent.click(screen.getByText('Filtros avançados'));
    fireEvent.change(screen.getByLabelText('Tipo de evento'), { target: { value: 'act.sealed' } });
    fireEvent.change(screen.getByLabelText('Autor'), { target: { value: 'amelia.marques' } });
    fireEvent.change(screen.getByLabelText('Desde'), { target: { value: '2026-07-01' } });
    fireEvent.change(screen.getByLabelText('Até'), { target: { value: '2026-07-31' } });
    fireEvent.change(screen.getByLabelText('Eventos por página'), { target: { value: '50' } });

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url ===
            '/v1/ledger/events/page?q=approved+digest&chain=book%3Abook-123456789&scope=act%3A88&kind=act.sealed&actor=amelia.marques&from=2026-07-01&to=2026-07-31&limit=50&order=desc',
        ),
      ).toBe(true),
    );
    expect((clear as HTMLButtonElement).disabled).toBe(false);
    await waitFor(() => expect(screen.getByText('Filtros ativos: 8')).toBeTruthy());
    expect(within(advanced).getByLabelText('Filtros ativos: 8')).toBeTruthy();

    fireEvent.click(clear);
    await waitFor(() =>
      expect((screen.getByLabelText('Pesquisar') as HTMLInputElement).value).toBe(''),
    );
    expect((screen.getByLabelText('Filtrar por âmbito') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText('Eventos por página') as HTMLSelectElement).value).toBe('100');
    await waitFor(() => expect(screen.getByText('Filtros ativos: 0')).toBeTruthy());
    expect(
      advanced.querySelector('.ledger-advanced-filters__body.filter-advanced__body'),
    ).toBeTruthy();
  });

  it('exports the selected audit format with the current filters through the save helper', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'arquivo-book-book-123456789-act-88.txt',
      contentType: 'text/plain;charset=utf-8',
      bytes: 11,
    });
    const calls = stubLedgerFetch(page([makeEvent(88)]));

    renderWithProviders(<LedgerPage />);

    expect(await screen.findByRole('option', { name: 'Livro book-123' })).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Pesquisar'), {
      target: { value: 'approved digest' },
    });
    fireEvent.change(screen.getByLabelText('Filtrar por cadeia'), {
      target: { value: 'book:book-123456789' },
    });
    fireEvent.change(screen.getByLabelText('Filtrar por âmbito'), {
      target: { value: 'act:88' },
    });
    expect((screen.getByLabelText('Âmbito da exportação') as HTMLSelectElement).value).toBe(
      'current_page',
    );
    fireEvent.change(screen.getByLabelText('Formato de exportação'), { target: { value: 'txt' } });
    fireEvent.click(screen.getByRole('button', { name: 'Exportar arquivo' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('arquivo-book-book-123456789-act-88.txt');
    expect(saved.contentType).toBe('text/plain;charset=utf-8');
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(await blobText(saved.blob)).toBe('archive-txt');
    expect(calls.find((c) => c.url.includes('/v1/ledger/archive/document'))?.url).toBe(
      '/v1/ledger/archive/document?format=txt&q=approved+digest&chain=book%3Abook-123456789&scope=act%3A88&limit=100&order=desc',
    );
    expect(screen.getByRole('option', { name: 'PDF/A canónico (.pdf)' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'TXT de auditoria (.txt)' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'JSON de intercâmbio (.json)' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'CSV de auditoria (.csv)' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'HTML de auditoria (.html)' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Página atual filtrada' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Todos os filtrados' })).toBeTruthy();
    const helpTexts = screen
      .getAllByRole('button', { name: 'Ajuda' })
      .flatMap((button) => (button.getAttribute('aria-describedby') ?? '').split(/\s+/))
      .map((id) => document.getElementById(id)?.textContent);
    expect(
      helpTexts.some(
        (text) =>
          text ===
          'Para Página atual, usa os filtros ativos, ordem mais recentes primeiro e o limite de Eventos por página; em Todos os filtrados, JSON/TXT/CSV/HTML exportam todos os correspondentes por streaming, enquanto PDF/A tem limite por segurança de memória.',
      ),
    ).toBe(true);
  });

  it('exports all filtered records server-side without loading older pages into the table', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'arquivo-global-all-filtered.json',
      contentType: 'application/json',
      bytes: 14,
    });
    const calls = stubLedgerFetch(
      page([makeEvent(1050)], { next_cursor: 950, has_more: true }),
      page([makeEvent(950)]),
    );

    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('event.1050')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Âmbito da exportação'), {
      target: { value: 'all_filtered' },
    });
    fireEvent.change(screen.getByLabelText('Formato de exportação'), { target: { value: 'json' } });
    fireEvent.click(screen.getByRole('button', { name: 'Exportar arquivo' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    expect(calls.filter((c) => c.url.includes('/v1/ledger/events/page'))).toHaveLength(1);
    const archiveCall = calls.find((c) => c.url.includes('/v1/ledger/archive/document'));
    expect(archiveCall?.url).toBe(
      '/v1/ledger/archive/document?format=json&export_scope=all_filtered&order=desc',
    );
    expect(saveFileMock.saveBlobAs.mock.calls[0][0].filename).toBe(
      'arquivo-global-all-filtered.json',
    );
    expect(screen.queryByText('event.950')).toBeNull();
  });

  it('shows a filtered empty state without losing the clear action', async () => {
    stubLedgerFetch(page([]));
    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('Sem eventos')).toBeTruthy();
    fireEvent.click(screen.getByText('Filtros avançados'));
    fireEvent.change(screen.getByLabelText('Autor'), { target: { value: 'nobody' } });

    expect(await screen.findByText('Sem resultados')).toBeTruthy();
    expect(
      screen.getByText('Altere a pesquisa ou os filtros para voltar a ver eventos.'),
    ).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Limpar filtros do arquivo' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it('keeps ledger filters and export controls responsive', async () => {
    const css = await themeCss();

    expectCssRule(css, /\.ledger-filterbar__primary\s*\{([^}]*)\}/, [
      'display: flex;',
      'flex-wrap: wrap;',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.ledger-advanced-filters__body\s*\{([^}]*)\}/, [
      'display: grid;',
      'grid-template-columns: repeat(auto-fit, minmax(min(100%, 12rem), 1fr));',
      'max-width: 100%;',
    ]);
    expectCssRule(css, /\.ledger-advanced-filters__summary\s*\{([^}]*)\}/, [
      'display: inline-flex;',
      'align-items: center;',
      'gap: 0.5rem;',
    ]);
    expectCssRule(css, /\.ledger-export-controls\s*\{([^}]*)\}/, [
      'display: flex;',
      'flex-wrap: wrap;',
      'max-width: 100%;',
    ]);
  });
});
