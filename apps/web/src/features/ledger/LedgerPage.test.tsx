import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import type { LedgerEventView } from '../../api/types';

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

const EVENT: LedgerEventView = {
  id: 'event-1',
  seq: 7,
  actor: 'amelia.marques',
  justification: null,
  timestamp: '2026-07-07T10:15:30Z',
  scope: 'act:7',
  kind: 'act.sealed',
  payload_digest: 'aa'.repeat(32),
  prev_hash: '00'.repeat(32),
  hash: 'bb'.repeat(32),
  chains: ['global', 'book:book-123456789'],
  attestation: null,
};

const INTEGRITY = {
  healthy: true,
  degraded: false,
  global: {
    chain: 'global',
    genesis_kind: null,
    length: 1,
    head: 'bb'.repeat(32),
    verified: true,
    first_break: null,
  },
  chains: [
    {
      chain: 'book:book-123456789',
      genesis_kind: 'book.opened',
      length: 1,
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

function stubLedgerFetch() {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method });

    if (url.includes('/v1/ledger/archive/document')) {
      return Promise.resolve(
        new Response('%PDF-archive', {
          status: 200,
          headers: { 'Content-Type': 'application/pdf' },
        }),
      );
    }
    if (url.includes('/v1/ledger/events')) return Promise.resolve(jsonResponse([EVENT]));
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 1 }));
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
  it('filters the ledger feed by chain and shows chain membership', async () => {
    const calls = stubLedgerFetch();
    renderWithProviders(<LedgerPage />);

    expect(await screen.findByText('act.sealed')).toBeTruthy();
    expect(await screen.findByRole('option', { name: 'Livro book-123' })).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Filtrar por cadeia'), {
      target: { value: 'book:book-123456789' },
    });

    await waitFor(() =>
      expect(calls.some((c) => c.url === '/v1/ledger/events?chain=book%3Abook-123456789')).toBe(
        true,
      ),
    );
    expect(await screen.findByText('Cadeias')).toBeTruthy();
    expect(screen.getByText('book:book-123')).toBeTruthy();
  });

  it('exports the current chain and scope filters through the save prompt helper', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-save',
      filename: 'arquivo-book-book-123456789-act-7.pdf',
      contentType: 'application/pdf',
      bytes: 12,
    });
    const calls = stubLedgerFetch();

    renderWithProviders(<LedgerPage />);

    expect(await screen.findByRole('option', { name: 'Livro book-123' })).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Filtrar por cadeia'), {
      target: { value: 'book:book-123456789' },
    });
    fireEvent.change(screen.getByLabelText('Filtrar por âmbito'), {
      target: { value: 'act:7' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Exportar PDF/A' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      preferBrowserSavePicker: boolean;
    };
    expect(saved.filename).toBe('arquivo-book-book-123456789-act-7.pdf');
    expect(saved.contentType).toBe('application/pdf');
    expect(saved.preferBrowserSavePicker).toBe(true);
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/pdf');
    expect(await blobText(saved.blob)).toBe('%PDF-archive');
    expect(calls.find((c) => c.url.includes('/v1/ledger/archive/document'))?.url).toBe(
      '/v1/ledger/archive/document?chain=book%3Abook-123456789&scope=act%3A7',
    );
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-save',
      filename: 'arquivo-book-book-123456789-act-7.pdf',
      contentType: 'application/pdf',
      bytes: 12,
    });
  });
});
