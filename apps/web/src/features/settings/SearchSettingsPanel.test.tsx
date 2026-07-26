import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type { SearchSettings, SearchStatusResponse } from '../../api/types';
import { i18nStore } from '../../i18n';
import { renderWithProviders } from '../../test/utils';
import { SearchSettingsPanel } from './SearchSettingsPanel';

const SEARCH_SETTINGS: SearchSettings = {
  enabled: true,
  batch_size: 256,
  interval_seconds: 30,
  queue_capacity: 64,
  result_limit: 100,
  snippet_chars: 240,
  facet_limit: 50,
  max_content_chars: 200_000,
  max_total_content_chars: 25_000_000,
  event_retention_days: 3_650,
  min_query_chars: 2,
};

const STATUS: SearchStatusResponse = {
  enabled: true,
  partial: false,
  stale: false,
  content_truncated: true,
  phase: 'idle',
  generation: 7,
  document_count: 12_000,
  truncated_document_count: 18,
  indexed_content_chars: 24_900_000,
  content_budget_chars: 25_000_000,
  content_budget_exhausted: true,
  processed: 125,
  total: 250,
  last_event_seq: 987,
  last_started_at: '2026-07-26T08:00:00Z',
  last_completed_at: '2026-07-26T08:03:00Z',
  details_redacted: false,
  last_error: 'projection reader stopped at generation 6',
  error_at: '2026-07-26T08:01:00Z',
  updated_at: '2026-07-26T08:04:00Z',
  queue_depth: 3,
  queue_capacity: 64,
  dropped_commands: 2,
  projection_writer: true,
  worker_thread: 'chancela-search-0',
};

interface FetchCall {
  url: string;
  method: string;
  body?: unknown;
}

function searchFetch(initialStatus: SearchStatusResponse = STATUS): {
  fetch: typeof globalThis.fetch;
  calls: FetchCall[];
} {
  const calls: FetchCall[] = [];
  let currentStatus = initialStatus;
  let currentSettings = SEARCH_SETTINGS;
  const json = (body: unknown) =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  const fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body =
      typeof init?.body === 'string' && init.body.length > 0 ? JSON.parse(init.body) : undefined;
    calls.push({ url, method, body });

    if (url.includes('/v1/search/settings')) {
      if (method === 'PUT') currentSettings = body as SearchSettings;
      return Promise.resolve(json(currentSettings));
    }
    if (url.includes('/v1/search/status')) return Promise.resolve(json(currentStatus));
    if (url.includes('/v1/search/pause')) {
      currentStatus = { ...currentStatus, phase: 'paused' };
      return Promise.resolve(json(currentStatus));
    }
    if (url.includes('/v1/search/resume')) {
      currentStatus = { ...currentStatus, phase: 'idle' };
      return Promise.resolve(json(currentStatus));
    }
    if (url.includes('/v1/search/rebuild')) {
      currentStatus = { ...currentStatus, phase: 'rebuilding' };
      return Promise.resolve(json(currentStatus));
    }
    return Promise.reject(new Error(`no test response for ${method} ${url}`));
  }) as typeof globalThis.fetch;
  return { fetch, calls };
}

afterEach(() => {
  cleanup();
  i18nStore.setActiveLocale('pt-PT');
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('SearchSettingsPanel', () => {
  it('presents index health and management-only diagnostics as a readable table', async () => {
    vi.stubGlobal('fetch', searchFetch().fetch);
    renderWithProviders(<SearchSettingsPanel />);

    const table = await screen.findByRole('table', { name: 'Estado do índice' });
    expect(within(table).getByRole('row', { name: /Fase Disponível/ })).toBeTruthy();
    expect(
      within(table).getByRole('row', { name: /Documentos 12.*000 documentos.*18 limitados/ }),
    ).toBeTruthy();
    expect(within(table).getByRole('row', { name: /Geração 7/ })).toBeTruthy();
    expect(within(table).getByRole('row', { name: /Progresso 125.*250/ })).toBeTruthy();
    expect(within(table).getByRole('row', { name: /Fila 3 de 64/ })).toBeTruthy();
    expect(within(table).getByRole('row', { name: /Worker chancela-search-0/ })).toBeTruthy();
    expect(within(table).getByRole('row', { name: /Escritor da projeção Sim/ })).toBeTruthy();
    expect(within(table).getByRole('row', { name: /Comandos descartados 2/ })).toBeTruthy();

    expect(screen.getByText('Foi atingido o limite global de conteúdo')).toBeTruthy();
    expect(screen.getByText('projection reader stopped at generation 6')).toBeTruthy();
  });

  it('renders every SearchSettings value with the server bounds and clamps edits', async () => {
    const stub = searchFetch();
    vi.stubGlobal('fetch', stub.fetch);
    renderWithProviders(<SearchSettingsPanel />);
    await screen.findByRole('table', { name: 'Estado do índice' });

    expect(
      (screen.getByRole('switch', { name: 'Pesquisa ativa' }) as HTMLInputElement).checked,
    ).toBe(true);
    const fields = [
      ['Documentos por lote', 256, 16, 5_000],
      ['Intervalo de reconciliação', 30, 5, 86_400],
      ['Capacidade da fila', 64, 1, 1_024],
      ['Resultados por página', 100, 1, 500],
      ['Tamanho dos excertos', 240, 32, 2_000],
      ['Valores por filtro', 50, 1, 200],
      ['Conteúdo por documento', 200_000, 1_000, 1_000_000],
      ['Conteúdo total do índice', 25_000_000, 100_000, 100_000_000],
      ['Retenção de eventos', 3_650, 1, 36_500],
      ['Mínimo da pesquisa', 2, 2, 8],
    ] as const;

    for (const [label, value, min, max] of fields) {
      const input = screen.getByLabelText(label) as HTMLInputElement;
      expect(input.type).toBe('number');
      expect(input.valueAsNumber).toBe(value);
      expect(input.min).toBe(String(min));
      expect(input.max).toBe(String(max));
    }

    fireEvent.change(screen.getByLabelText('Resultados por página'), {
      target: { value: '9999' },
    });
    expect((screen.getByLabelText('Resultados por página') as HTMLInputElement).valueAsNumber).toBe(
      500,
    );
    fireEvent.change(screen.getByLabelText('Documentos por lote'), {
      target: { value: '1' },
    });
    expect((screen.getByLabelText('Documentos por lote') as HTMLInputElement).valueAsNumber).toBe(
      16,
    );
    await waitFor(() =>
      expect(
        stub.calls.some(
          (call) =>
            call.url === '/v1/search/settings' &&
            call.method === 'PUT' &&
            (call.body as SearchSettings | undefined)?.result_limit === 500 &&
            (call.body as SearchSettings | undefined)?.batch_size === 16,
        ),
      ).toBe(true),
    );
  });

  it('loads settings and keeps index commands usable through the search management surface', async () => {
    const stub = searchFetch({ ...STATUS, content_budget_exhausted: false, last_error: null });
    vi.stubGlobal('fetch', stub.fetch);
    renderWithProviders(<SearchSettingsPanel />);
    await screen.findByRole('table', { name: 'Estado do índice' });

    const settingsFieldset = screen
      .getByRole('switch', { name: 'Pesquisa ativa' })
      .closest('fieldset') as HTMLFieldSetElement;
    expect(settingsFieldset.disabled).toBe(false);
    expect(settingsFieldset.contains(screen.getByLabelText('Documentos por lote'))).toBe(true);
    const pause = screen.getByRole('button', {
      name: 'Pausar indexação',
    }) as HTMLButtonElement;
    expect(pause.disabled).toBe(false);

    fireEvent.click(pause);
    await waitFor(() =>
      expect(stub.calls).toContainEqual({
        url: '/v1/search/pause',
        method: 'POST',
        body: undefined,
      }),
    );
  });

  it('rebuilds, pauses and resumes through the dedicated management endpoints', async () => {
    const stub = searchFetch({ ...STATUS, content_budget_exhausted: false, last_error: null });
    vi.stubGlobal('fetch', stub.fetch);
    renderWithProviders(<SearchSettingsPanel />);
    await screen.findByRole('table', { name: 'Estado do índice' });

    fireEvent.click(screen.getByRole('button', { name: 'Pausar indexação' }));
    await waitFor(() =>
      expect(stub.calls).toContainEqual({
        url: '/v1/search/pause',
        method: 'POST',
        body: undefined,
      }),
    );
    const resume = (await screen.findByRole('button', {
      name: 'Retomar indexação',
    })) as HTMLButtonElement;
    await waitFor(() => expect(resume.disabled).toBe(false));
    fireEvent.click(resume);
    await waitFor(() =>
      expect(stub.calls).toContainEqual({
        url: '/v1/search/resume',
        method: 'POST',
        body: undefined,
      }),
    );

    const rebuild = screen.getByRole('button', {
      name: 'Reconstruir índice',
    }) as HTMLButtonElement;
    await waitFor(() => expect(rebuild.disabled).toBe(false));
    fireEvent.click(rebuild);
    await waitFor(() =>
      expect(stub.calls).toContainEqual({
        url: '/v1/search/rebuild',
        method: 'POST',
        body: undefined,
      }),
    );
  });
});
