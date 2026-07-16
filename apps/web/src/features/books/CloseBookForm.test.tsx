import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { CloseBookForm } from './CloseBookForm';
import type { BookView } from '../../api/types';

interface RecordedCall {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

const CLOSED_BOOK: BookView = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Closed',
  purpose: 'Atas da Assembleia',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: '2026-07-13',
  closing_reason: 'BookFull',
  last_ata_number: 3,
  predecessor: null,
  required_signatories_abertura: null,
  required_signatories_encerramento: null,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/** A recording fetch that answers `POST /v1/books/:id/close` with `responder`. */
function recordingFetch(responder: (call: RecordedCall) => Response) {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    const call = { url, method, body };
    calls.push(call);
    return Promise.resolve(responder(call));
  }) as typeof fetch;
  return { fn, calls };
}

/** A never-resolving fetch, to hold the close mutation in flight. */
function pendingFetch() {
  const fn = (() => new Promise<Response>(() => {})) as typeof fetch;
  return fn;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CloseBookForm', () => {
  it('renders the reason, date and signatories with an enabled submit', () => {
    vi.stubGlobal('fetch', pendingFetch());
    renderWithProviders(<CloseBookForm bookId="book-1" />);

    expect(screen.getByLabelText('Motivo do encerramento')).toBeTruthy();
    expect(screen.getByLabelText('Data de encerramento')).toBeTruthy();
    expect(screen.getByText('Signatários do termo de encerramento')).toBeTruthy();

    const submit = screen.getByRole('button', { name: /encerrar livro/i }) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
    expect(submit.textContent).toContain('Encerrar livro');
  });

  it('submits the chosen reason, date and signatory, toasts success and calls onClosed', async () => {
    const onClosed = vi.fn();
    const { fn, calls } = recordingFetch(() => jsonResponse(CLOSED_BOOK));
    vi.stubGlobal('fetch', fn);
    const { container } = renderWithProviders(
      <CloseBookForm bookId="book-1" onClosed={onClosed} />,
    );

    fireEvent.change(screen.getByLabelText('Motivo do encerramento'), {
      target: { value: 'EntityDissolved' },
    });
    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    const name = container.querySelector('#close-signatories-name-0') as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Amélia Marques' } });

    fireEvent.click(screen.getByRole('button', { name: /encerrar livro/i }));

    expect(await screen.findByText('Livro encerrado.')).toBeTruthy();
    await waitFor(() => expect(onClosed).toHaveBeenCalledTimes(1));

    const closeCall = calls.find((c) => c.method === 'POST');
    expect(closeCall?.url).toBe('/v1/books/book-1/close');
    expect(closeCall?.body).toMatchObject({
      reason: 'EntityDissolved',
      closing_date: '2026-07-13',
      required_signatories: [{ name: 'Amélia Marques', capacity: null, email: null }],
    });
  });

  it('disables the submit and shows the pending label while the close is in flight', async () => {
    vi.stubGlobal('fetch', pendingFetch());
    renderWithProviders(<CloseBookForm bookId="book-1" />);

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    fireEvent.click(screen.getByRole('button', { name: /encerrar livro/i }));

    const pending = await screen.findByRole('button', { name: /a encerrar/i });
    expect((pending as HTMLButtonElement).disabled).toBe(true);
    expect(pending.textContent).toContain('A encerrar');
  });

  it('surfaces an inline error note and error toast on failure, without calling onClosed', async () => {
    const onClosed = vi.fn();
    const { fn } = recordingFetch(() =>
      jsonResponse({ error: 'livro já se encontra encerrado' }, 409),
    );
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<CloseBookForm bookId="book-1" onClosed={onClosed} />);

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    fireEvent.click(screen.getByRole('button', { name: /encerrar livro/i }));

    // Inline ErrorNote (close.error) and the error toast both surface the server message.
    expect(
      (await screen.findAllByText('livro já se encontra encerrado')).length,
    ).toBeGreaterThanOrEqual(1);
    expect(onClosed).not.toHaveBeenCalled();
    // The submit returns to its idle, enabled state after the failure.
    const submit = screen.getByRole('button', { name: /encerrar livro/i }) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
  });
});
