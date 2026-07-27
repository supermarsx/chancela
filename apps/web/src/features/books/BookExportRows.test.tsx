/**
 * Direct unit coverage for the shared `<BookExportRows>` (t52) — the two book-scoped export
 * rows extracted out of `LedgerPage.tsx` so `LedgerPage.tsx`'s Arquivo → Exportação tab and
 * `BookDetailPage.tsx`'s own Export tab render exactly one implementation. The two call sites'
 * own integration tests (`LedgerPage.test.tsx`, `books.test.tsx`) already exercise this through
 * their surrounding page; this file is the component's own narrow contract — given a `bookId`,
 * it renders the two rows, guards the export-time legal hold the same way the server does, and
 * marks the bundle (and only the bundle) as a mutating/retained export.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn((result: { filename: string }) => `Guardado: ${result.filename}`),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { BookExportRows } from './BookExportRows';

interface RecordedCall {
  url: string;
  method: string;
}

function stubFetch(handler: (url: string, method: string) => Response | null): RecordedCall[] {
  const calls: RecordedCall[] = [];
  vi.stubGlobal(
    'fetch',
    ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method });
      const hit = handler(url, method);
      if (hit) return Promise.resolve(hit);
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch,
  );
  return calls;
}

function renderRows(bookId = 'book-1') {
  renderWithProviders(
    <table>
      <tbody>
        <BookExportRows bookId={bookId} />
      </tbody>
    </table>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('BookExportRows', () => {
  it('renders both rows, with only the bundle marked as a retained/registered export', () => {
    renderRows();

    expect(screen.getByText('chancela-internal-preservation-package/v1')).toBeTruthy();
    expect(screen.getByText('chancela-book-bundle/v1')).toBeTruthy();
    // The bundle's retained/logged side effect is stated, the preservation package's is not.
    expect(screen.getByText('Esta exportação fica registada')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Pacote de preservação Chancela' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Exportar pacote de portabilidade' })).toBeTruthy();
  });

  it('holds back the preservation package request when legal hold has no reason', () => {
    const calls = stubFetch((url, method) => {
      if (url.startsWith('/v1/books/book-1/archive/package') && method === 'GET') {
        return new Response('zipbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        });
      }
      return null;
    });
    renderRows();

    fireEvent.click(
      screen.getByRole('switch', { name: 'Marcar retenção legal nesta exportação' }),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Pacote de preservação Chancela' }));

    expect(screen.getByText('Indique o motivo antes de marcar a retenção legal.')).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/archive/package'))).toBe(false);
  });

  it('downloads the preservation package once a legal-hold reason is given', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'chancela-preservation-book-book-1.zip',
      contentType: 'application/zip',
      bytes: 8,
    });
    const calls = stubFetch((url, method) => {
      if (url.startsWith('/v1/books/book-1/archive/package') && method === 'GET') {
        return new Response('zipbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        });
      }
      return null;
    });
    renderRows();

    fireEvent.click(
      screen.getByRole('switch', { name: 'Marcar retenção legal nesta exportação' }),
    );
    fireEvent.change(screen.getByLabelText('Motivo da retenção legal'), {
      target: { value: 'Processo 44/26' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Pacote de preservação Chancela' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    expect(calls.find((c) => c.url.includes('/archive/package'))?.url).toBe(
      '/v1/books/book-1/archive/package?legal_hold=true&legal_hold_reason=Processo+44%2F26',
    );
  });

  it('exports the portability bundle through the POST endpoint the importer accepts', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'book-book-1.zip',
      contentType: 'application/zip',
      bytes: 9,
    });
    const calls = stubFetch((url, method) => {
      if (url === '/v1/books/book-1/export' && method === 'POST') {
        return new Response('zipbytes', {
          status: 200,
          headers: { 'Content-Type': 'application/zip' },
        });
      }
      return null;
    });
    renderRows();

    fireEvent.click(screen.getByRole('button', { name: 'Exportar pacote de portabilidade' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const bundleCall = calls.find((c) => c.url === '/v1/books/book-1/export');
    expect(bundleCall?.method).toBe('POST');
  });

  it('disables both actions when no book is selected yet', () => {
    renderRows('');

    expect(
      (screen.getByRole('button', { name: 'Pacote de preservação Chancela' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(
      (
        screen.getByRole('button', {
          name: 'Exportar pacote de portabilidade',
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
});
