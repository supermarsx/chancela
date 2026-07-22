import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { useLocation } from 'react-router-dom';
import { renderWithProviders, Wrapper } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import type { BookView, Entity, LedgerEventView, LedgerEventsPage } from '../../api/types';

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

function makeBook(patch: Partial<BookView> = {}): BookView {
  return {
    id: 'book-123456789',
    entity_id: 'entity-1',
    kind: 'AssembleiaGeral',
    state: 'Open',
    purpose: 'Atas da assembleia geral',
    numbering_scheme: null,
    opening_date: '2026-01-02',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 3,
    predecessor: null,
    required_signatories_abertura: null,
    required_signatories_encerramento: null,
    ...patch,
  };
}

function makeEntity(patch: Partial<Entity> = {}): Entity {
  return {
    id: 'entity-1',
    name: 'Encosto Estratégico, Lda.',
    ...patch,
  } as Entity;
}

function stubLedgerFetch(
  firstPage: LedgerEventsPage,
  olderPage = page([]),
  books: BookView[] = [makeBook()],
  entities: Entity[] = [makeEntity()],
) {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method });

    if (url.includes('/v1/books/') && url.includes('/archive/package')) {
      return Promise.resolve(
        new Response('PK-preservation', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        }),
      );
    }
    if (url.includes('/v1/books/') && url.endsWith('/export')) {
      return Promise.resolve(
        new Response('PK-bundle', { status: 200, headers: { 'Content-Type': 'application/zip' } }),
      );
    }
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse(books));
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse(entities));
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
  it('widens the Registo panel only, on a deep link as well as a tab switch', async () => {
    stubLedgerFetch(page([makeEvent(100)]));
    renderLedger();

    expect(await screen.findByText('event.100')).toBeTruthy();
    // Shared with the Minutas catalog: one wide-page rule, not a bespoke override per page.
    const panel = () => document.querySelector('.route-transition');
    expect(panel()?.classList.contains('wide-page')).toBe(true);

    // Exportação is two cards, so it stays at the prose measure.
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));
    expect(await screen.findByText('Documento do registo de auditoria')).toBeTruthy();
    expect(panel()?.classList.contains('wide-page')).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Registo' }));
    await waitFor(() => expect(panel()?.classList.contains('wide-page')).toBe(true));

    // t18 named the wide shell measure as a custom prop on `.app`; the wide-page opt-out now
    // caps to it (the 92rem literal lives on the `--app-measure-wide` declaration).
    const css = await themeCss();
    expectCssRule(css, /\.app\s*\{([^}]*)\}/, ['--app-measure-wide: 92rem;']);
    expectCssRule(css, /\.app:has\(\.wide-page\)\s*\{([^}]*)\}/, [
      'max-width: var(--app-measure-wide);',
    ]);
  });

  it('widens the Registo panel when it is reached by deep link, not only by first paint', async () => {
    stubLedgerFetch(page([makeEvent(10)]));
    renderLedger(['/archive/export']);

    expect(await screen.findByText('Documento do registo de auditoria')).toBeTruthy();
    expect(document.querySelector('.route-transition')?.classList.contains('wide-page')).toBe(
      false,
    );

    cleanup();
    stubLedgerFetch(page([makeEvent(10)]));
    renderLedger(['/archive/register']);

    expect(await screen.findByText('event.10')).toBeTruthy();
    expect(document.querySelector('.route-transition')?.classList.contains('wide-page')).toBe(true);
  });

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
      calls.some((c) => c.url === '/v1/ledger/events/page?before_seq=950&limit=100&order=desc'),
    ).toBe(true);
  }, 15_000);

  it('never claims a total it does not have, and announces the count when more is loaded', async () => {
    // The page endpoint reports `has_more`/`next_cursor` and no total. A lazily-extending table
    // that published `aria-rowcount="100"` would tell a screen-reader user the audit log ends at
    // the fetch boundary; -1 is ARIA's "not known". The count then only becomes real when the
    // server says there is nothing older.
    const calls = stubLedgerFetch(
      page([makeEvent(100)], { next_cursor: 99, has_more: true }),
      page([makeEvent(99)]),
    );
    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('event.100')).toBeTruthy();
    expect(screen.getByRole('table').getAttribute('aria-rowcount')).toBe('-1');
    // The count is a live region, so clicking "load older" — which moves no focus — is not silent.
    const status = screen
      .getAllByRole('status')
      .find((el) => el.textContent?.includes('eventos carregados'));
    expect(status?.textContent).toContain('1 eventos carregados; existem mais');

    fireEvent.click(screen.getByRole('button', { name: 'Carregar eventos mais antigos' }));

    expect(await screen.findByText('event.99')).toBeTruthy();
    // Exhausted: header + two events, and the badge stops hedging.
    expect(screen.getByRole('table').getAttribute('aria-rowcount')).toBe('3');
    expect(
      screen
        .getAllByRole('status')
        .some((el) => el.textContent?.includes('2 eventos carregados') === true),
    ).toBe(true);
    expect(calls.filter((c) => c.url.includes('/v1/ledger/events/page'))).toHaveLength(2);
  });

  it('applies server-backed filters and exposes an icon-only clear button with a tooltip', async () => {
    const calls = stubLedgerFetch(page([makeEvent(88, { kind: 'act.sealed' })]));
    const { container } = renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('Ata selada')).toBeTruthy();
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
    // The filters live in Registo; the export controls they feed live in Exportação.
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));
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
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));
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

  it('announces the loading archive through a busy region instead of loading silently', async () => {
    // Every skeleton bar is `aria-hidden`, so without the region a screen reader hears
    // NOTHING while the archive loads — a regression against the plain "A carregar…" line
    // the skeletons replaced. The region is what carries that announcement now.
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/ledger/events/page')) return new Promise<Response>(() => {});
      if (url.includes('/v1/ledger/verify')) {
        return Promise.resolve(jsonResponse({ valid: true, length: 1 }));
      }
      if (url.includes('/v1/ledger/integrity')) return Promise.resolve(jsonResponse(INTEGRITY));
      if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([makeBook()]));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LedgerPage />);

    const region = await screen.findByRole('status');
    expect(region.getAttribute('aria-busy')).toBe('true');
    expect(region.textContent).toContain('A carregar');
    // …and the decorative bars stay out of the accessibility tree: the region speaks once
    // rather than the shimmer being read as content.
    const bars = region.querySelectorAll('.skeleton');
    expect(bars.length).toBeGreaterThan(0);
    for (const bar of bars) expect(bar.closest('[aria-hidden="true"]')).toBeTruthy();
    expect(screen.queryByRole('table')).toBeNull();
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

/** Reads the live location so an address assertion works under MemoryRouter (history in memory). */
function LocationProbe() {
  const location = useLocation();
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>;
}

function renderLedger(initialEntries = ['/archive']) {
  return render(
    <Wrapper initialEntries={initialEntries}>
      <LedgerPage />
      <LocationProbe />
    </Wrapper>,
  );
}

function locationValue(): string {
  return screen.getByTestId('location').textContent ?? '';
}

describe('LedgerPage — sub-tabs', () => {
  it('renders both sub-tabs from the shared SubNav with Registo pressed by default', async () => {
    stubLedgerFetch(page([makeEvent(10)]));
    renderLedger();

    const nav = await screen.findByRole('group', { name: 'Secções do arquivo' });
    const tabs = within(nav).getAllByRole('button');
    expect(tabs.map((b) => b.textContent)).toEqual(['Registo', 'Exportação']);
    expect(tabs[0].getAttribute('aria-pressed')).toBe('true');
    expect(tabs[1].getAttribute('aria-pressed')).toBe('false');

    // The default section carries no segment of its own.
    expect(locationValue()).toBe('/archive');
    expect(await screen.findByText('event.10')).toBeTruthy();
  });

  it('writes the section segment when leaving Registo and drops it on the way back', async () => {
    stubLedgerFetch(page([makeEvent(10)]));
    renderLedger();

    expect(await screen.findByText('event.10')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));
    await waitFor(() => expect(locationValue()).toBe('/archive/export'));

    fireEvent.click(screen.getByRole('button', { name: 'Registo' }));
    await waitFor(() => expect(locationValue()).toBe('/archive'));
  });

  it('paints the incoming sub-tab on the click, not after the enter animation', async () => {
    stubLedgerFetch(page([makeEvent(10)]));
    renderLedger();
    expect(await screen.findByText('event.10')).toBeTruthy();

    // Deliberately NO `await` between the click and the query. The keyed wrapper is a
    // remount, not a mount-after-animation: `.route-transition`/`panel-enter` fade content
    // that is already in the DOM, and no animation-end callback sits in this path. If a
    // transition ever starts gating the swap, this is the assertion that catches it.
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));
    expect(screen.getByText('Documento do registo de auditoria')).toBeTruthy();
    expect(screen.queryByText('event.10')).toBeNull();
  });

  it('opens Exportação directly from a deep link and falls back to Registo for an unknown sec', async () => {
    stubLedgerFetch(page([makeEvent(10)]));
    const deep = renderLedger(['/archive/export']);

    expect(await screen.findByText('Documento do registo de auditoria')).toBeTruthy();
    expect(screen.getByText('Exportações de um livro')).toBeTruthy();
    expect(screen.queryByRole('table')).toBeNull();
    deep.unmount();

    renderLedger(['/archive/nao-existe']);
    expect(await screen.findByText('event.10')).toBeTruthy();
    expect(screen.queryByText('Documento do registo de auditoria')).toBeNull();
  });

  it('keeps the Registo table, its filters and the chain badge in the first sub-tab', async () => {
    stubLedgerFetch(page([makeEvent(88, { kind: 'act.sealed' })]));
    renderLedger();

    expect(await screen.findByText('Ata selada')).toBeTruthy();
    expect(screen.getByRole('search', { name: 'Pesquisar e filtrar arquivo' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Limpar filtros do arquivo' })).toBeTruthy();
    expect(screen.getByText('Filtros avançados')).toBeTruthy();
    // The integrity headline belongs to the whole surface, so it survives a tab switch.
    expect(screen.getByText('Cadeia verificada (1000 eventos)')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));
    expect(screen.getByText('Cadeia verificada (1000 eventos)')).toBeTruthy();
  });

  it('echoes the Registo filter count in Exportação and offers a way back to change it', async () => {
    stubLedgerFetch(page([makeEvent(88)]));
    renderLedger();

    expect(await screen.findByText('event.88')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Filtrar por âmbito'), { target: { value: 'act:88' } });
    fireEvent.click(screen.getByRole('button', { name: 'Exportação' }));

    await waitFor(() => expect(screen.getByText('Filtros ativos: 1')).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { name: 'Alterar filtros no Registo' }));
    await waitFor(() => expect(locationValue()).toBe('/archive'));
    expect((screen.getByLabelText('Filtrar por âmbito') as HTMLInputElement).value).toBe('act:88');
  });

  it('labels the preservation package and the portability bundle as different formats', async () => {
    stubLedgerFetch(page([makeEvent(10)]));
    renderLedger(['/archive/export']);

    expect(await screen.findByText('Pacote de preservação — depósito e prova')).toBeTruthy();
    expect(screen.getByText('Pacote de portabilidade — mudar de instância')).toBeTruthy();
    expect(screen.getByText('chancela-internal-preservation-package/v1')).toBeTruthy();
    expect(screen.getByText('chancela-book-bundle/v1')).toBeTruthy();
    // The bundle's retained/logged side effect is stated, the preservation package's is not.
    expect(screen.getByText('Esta exportação fica registada')).toBeTruthy();
    // The cascade auto-selects the sole entity → type → book, so the book step offers the
    // book's own purpose and the type step offers its kind label.
    expect(await screen.findByRole('option', { name: 'Atas da assembleia geral' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'Assembleia Geral' })).toBeTruthy();
  });

  it('downloads the preservation package with the export-time legal hold it was given', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'chancela-preservation-book-book-123456789.zip',
      contentType: 'application/zip',
      bytes: 15,
    });
    const calls = stubLedgerFetch(page([makeEvent(10)]));
    renderLedger(['/archive/export']);

    expect(await screen.findByRole('option', { name: 'Atas da assembleia geral' })).toBeTruthy();
    fireEvent.click(screen.getByRole('switch', { name: 'Marcar retenção legal nesta exportação' }));
    // A blank reason is a server 422, so the export is held back and the field says why.
    fireEvent.click(screen.getByRole('button', { name: 'Pacote de preservação Chancela' }));
    expect(screen.getByText('Indique o motivo antes de marcar a retenção legal.')).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/archive/package'))).toBe(false);

    fireEvent.change(screen.getByLabelText('Motivo da retenção legal'), {
      target: { value: 'Processo 44/26' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Pacote de preservação Chancela' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    expect(calls.find((c) => c.url.includes('/archive/package'))?.url).toBe(
      '/v1/books/book-123456789/archive/package?legal_hold=true&legal_hold_reason=Processo+44%2F26',
    );
    expect(saveFileMock.saveBlobAs.mock.calls[0][0].filename).toBe(
      'chancela-preservation-book-book-123456789.zip',
    );
  });

  it('exports the portability bundle through the POST endpoint the importer accepts', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'book-book-123456789.zip',
      contentType: 'application/zip',
      bytes: 9,
    });
    const calls = stubLedgerFetch(page([makeEvent(10)]));
    renderLedger(['/archive/export']);

    fireEvent.click(
      await screen.findByRole('button', { name: 'Exportar pacote de portabilidade' }),
    );

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const bundleCall = calls.find((c) => c.url === '/v1/books/book-123456789/export');
    expect(bundleCall?.method).toBe('POST');
    expect(saveFileMock.saveBlobAs.mock.calls[0][0].filename).toBe('book-book-123456789.zip');
  });

  it('shows an honest empty state when there is no book to package', async () => {
    stubLedgerFetch(page([makeEvent(10)]), page([]), []);
    renderLedger(['/archive/export']);

    expect(await screen.findByText('Sem livros para exportar')).toBeTruthy();
    // The instance-wide ledger export does not depend on a book, so it stays available.
    expect(screen.getByRole('button', { name: 'Exportar arquivo' })).toBeTruthy();
  });

  it('replaces the book exports with a permission note and fires no book request', async () => {
    const calls = stubLedgerFetch(page([makeEvent(10)]));
    render(
      <Wrapper initialEntries={['/archive/export']}>
        <StaticPermissionsProvider value={permissionsValue((perm) => perm !== 'book.export')}>
          <LedgerPage />
        </StaticPermissionsProvider>
      </Wrapper>,
    );

    expect(await screen.findByText('Documento do registo de auditoria')).toBeTruthy();
    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByLabelText('Livro a exportar')).toBeNull();
    await waitFor(() => expect(calls.some((c) => c.url.includes('/v1/ledger/verify'))).toBe(true));
    expect(calls.some((c) => c.url.includes('/v1/books'))).toBe(false);
  });
});
