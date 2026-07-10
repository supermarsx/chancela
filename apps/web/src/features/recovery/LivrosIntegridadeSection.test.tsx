import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn((result: { filename: string }) => `Guardado: ${result.filename}`),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { LivrosIntegridadeSection } from './LivrosIntegridadeSection';

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

const HEALTHY_REPORT = {
  healthy: true,
  degraded: false,
  global: {
    chain: 'global',
    genesis_kind: null,
    length: 5,
    head: 'aa'.repeat(32),
    verified: true,
    first_break: null,
  },
  chains: [],
  reanchored_segments: [],
};

const BROKEN_REPORT = {
  healthy: false,
  degraded: true,
  global: {
    chain: 'global',
    genesis_kind: null,
    length: 5,
    head: 'aa'.repeat(32),
    verified: false,
    first_break: {
      chain: 'global',
      kind: 'HashMismatch',
      global_seq: 3,
      chain_seq: 3,
      event_id: 'bb'.repeat(16),
      expected_hash: 'cc'.repeat(32),
      actual_hash: 'dd'.repeat(32),
      message: 'hash mismatch at seq 3',
    },
  },
  chains: [],
  reanchored_segments: [],
};

const BOOK = {
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

interface Recorded {
  url: string;
  method: string;
}

/** A fetch stub over the section's read endpoints; `report` chooses healthy vs broken. */
function sectionFetch(report: unknown, extra?: (url: string, method: string) => Response | null) {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method });
    const custom = extra?.(url, method);
    if (custom) return Promise.resolve(custom);
    if (url.includes('/v1/ledger/integrity')) return Promise.resolve(jsonResponse(report));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([BOOK]));
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse([]));
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
});

describe('LivrosIntegridadeSection', () => {
  it('renders the per-chain integrity report with the exact break location when broken', async () => {
    const { fn } = sectionFetch(BROKEN_REPORT);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    // A broken chain also puts the instance in read-only (degraded) mode.
    expect(await screen.findByText('Modo só-leitura ativo')).toBeTruthy();
    // The exact break detail is surfaced (kind + message).
    expect(await screen.findByText('Local exato da quebra')).toBeTruthy();
    expect(screen.getByText('HashMismatch')).toBeTruthy();
    expect(screen.getByText('hash mismatch at seq 3')).toBeTruthy();

    // Re-anchor is enabled only because the chain is broken.
    const reanchor = screen.getByRole('button', { name: /Re-ancorar cadeia/ });
    expect((reanchor as HTMLButtonElement).disabled).toBe(false);
  });

  it('disables re-anchor when all chains are intact', async () => {
    const { fn } = sectionFetch(HEALTHY_REPORT);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    expect(await screen.findByText('Todas as cadeias íntegras')).toBeTruthy();
    const reanchor = screen.getByRole('button', { name: /Re-ancorar cadeia/ });
    expect((reanchor as HTMLButtonElement).disabled).toBe(true);
  });

  it('exports a book bundle through the save prompt helper', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });

    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/book-1/export') && method === 'POST') {
        return new Response('zipbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        });
      }
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    fireEvent.click(await screen.findByRole('button', { name: /Exportar/ }));
    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('book-book-1.zip');
    expect(saved.contentType).toBe('application/zip');
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/zip');
    expect(await blobText(saved.blob)).toBe('zipbytes');
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-save',
      filename: 'book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
  });

  it('imports a bundle and shows the honest Quarantined verdict', async () => {
    const outcome = {
      import_id: 'imp-1',
      entity_id: 'ent-1',
      book_id: 'book-9',
      verdict: {
        status: 'Quarantined',
        break: { chain: 'book:book-9', kind: 'HashMismatch', message: 'forged' },
      },
      source_instance_id: 'other',
      bundle_digest: 'ee'.repeat(32),
      collided: false,
    };
    const { fn } = sectionFetch(HEALTHY_REPORT, (url, method) => {
      if (url.includes('/v1/books/import') && method === 'POST') return jsonResponse(outcome);
      return null;
    });
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<LivrosIntegridadeSection />);

    // The file input carries the accessible "Choose bundle…" label of its wrapping button.
    const fileInput = document.querySelector('input[type=file]') as HTMLInputElement;
    const file = new File(['zip'], 'bundle.zip', { type: 'application/zip' });
    // jsdom's File does not implement arrayBuffer(); provide it so the import can read bytes.
    Object.defineProperty(file, 'arrayBuffer', {
      value: () => Promise.resolve(new ArrayBuffer(3)),
    });
    fireEvent.change(fileInput, { target: { files: [file] } });

    expect(await screen.findByText('Em quarentena')).toBeTruthy();
    expect(
      screen.getByText(
        'O pacote não passou na verificação. Foi isolado em quarentena, apenas de leitura, e nunca associado às cadeias ativas.',
      ),
    ).toBeTruthy();
  });
});
