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

/**
 * The server's policy for `book.close`, as `GET /v1/confirmation-policy` reports it: floored at
 * confirm-with-reauth-and-phrase with the byte-exact `ENCERRAR LIVRO`.
 *
 * The dialog's strictness comes from HERE, never from the client — that is the whole point of the
 * registry — so the tests below drive whatever the server declares rather than a hard-coded shape.
 */
function confirmationPolicyJson(): Response {
  return jsonResponse({
    actions: [
      {
        action: 'book.close',
        floor: 'confirm_with_reauth_and_phrase',
        effective: 'confirm_with_reauth_and_phrase',
        phrase: 'ENCERRAR LIVRO',
        consequence: 'destructive',
        wired: true,
      },
    ],
  });
}

/**
 * A recording fetch that answers `POST /v1/books/:id/close` with `responder` and the confirmation
 * policy with {@link confirmationPolicyJson}.
 */
function recordingFetch(responder: (call: RecordedCall) => Response) {
  const calls: RecordedCall[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    const call = { url, method, body };
    calls.push(call);
    if (url.startsWith('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
    return Promise.resolve(responder(call));
  }) as typeof fetch;
  return { fn, calls };
}

/** A fetch that resolves the policy but never resolves anything else, holding the close in flight. */
function pendingFetch() {
  return ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.startsWith('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
    return new Promise<Response>(() => {});
  }) as typeof fetch;
}

/** The form's own submit — the control that OPENS the dialog, never the one inside it. */
function formSubmit(container: HTMLElement): HTMLButtonElement {
  return container.querySelector<HTMLButtonElement>('.form__actions button[type=submit]')!;
}

/** The dialog's submit control, found by role + type rather than by its translated label. */
function dialogConfirm(): HTMLButtonElement | null {
  const dialog = screen.queryByRole('dialog');
  return dialog?.querySelector<HTMLButtonElement>('button[type=submit]') ?? null;
}

/**
 * Ask to close, satisfy the server-declared gate, and confirm. Both fields are found structurally
 * (the phrase box is the dialog's only `.mono` input), never by their translated labels.
 */
async function confirmClose(container: HTMLElement): Promise<void> {
  fireEvent.click(formSubmit(container));
  const dialog = await screen.findByRole('dialog');
  // Wait for the SERVER's policy to land before touching anything. Until it does the dialog renders
  // no gate at all and refuses to confirm (`resolved` is false), so a click here would be a silent
  // no-op — and a test that typed into an unresolved gate would prove nothing about the real one.
  await waitFor(() => expect(dialog.querySelector('input.mono')).toBeTruthy());
  const phrase = dialog.querySelector<HTMLInputElement>('input.mono')!;
  fireEvent.change(phrase, { target: { value: 'ENCERRAR LIVRO' } });
  const password = dialog.querySelector<HTMLInputElement>('input[type=password]')!;
  fireEvent.change(password, { target: { value: 'segredo-da-amelia' } });
  fireEvent.click(dialogConfirm()!);
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('CloseBookForm', () => {
  it('renders the reason, date and signatories with an enabled submit', () => {
    vi.stubGlobal('fetch', pendingFetch());
    const { container } = renderWithProviders(<CloseBookForm bookId="book-1" />);

    expect(screen.getByLabelText('Motivo do encerramento')).toBeTruthy();
    expect(screen.getByLabelText('Data de encerramento')).toBeTruthy();
    expect(screen.getByText('Signatários do termo de encerramento')).toBeTruthy();

    const submit = formSubmit(container);
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

    await confirmClose(container);

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

  it('carries the step-up proof and the byte-exact phrase the server verifies', async () => {
    // The server CALLS `require_confirmation` for `book.close`, so a request without both halves of
    // the proof is a 403 that closes nothing. This asserts the halves actually leave the client —
    // a dialog whose proof never reached the wire is exactly the shape of the bug this closed.
    const { fn, calls } = recordingFetch(() => jsonResponse(CLOSED_BOOK));
    vi.stubGlobal('fetch', fn);
    const { container } = renderWithProviders(<CloseBookForm bookId="book-1" />);

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    await confirmClose(container);

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const body = calls.find((c) => c.method === 'POST')?.body as
      { confirmation?: { reauth?: { password?: string }; confirm_phrase?: string } } | undefined;
    expect(body?.confirmation?.reauth?.password).toBe('segredo-da-amelia');
    // Byte-exact and non-localised: not lower-cased, not read from a catalog.
    expect(body?.confirmation?.confirm_phrase).toBe('ENCERRAR LIVRO');
  });

  it('sends no close request at all until the dialog is confirmed', async () => {
    // The click that used to close the book now only opens the dialog. If this ever regresses, the
    // client is back to closing books on a bare click while the server refuses them.
    const { fn, calls } = recordingFetch(() => jsonResponse(CLOSED_BOOK));
    vi.stubGlobal('fetch', fn);
    const { container } = renderWithProviders(<CloseBookForm bookId="book-1" />);

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    fireEvent.click(formSubmit(container));
    await screen.findByRole('dialog');

    expect(calls.some((c) => c.url.includes('/close'))).toBe(false);
  });

  it('disables the submit and shows the pending label while the close is in flight', async () => {
    vi.stubGlobal('fetch', pendingFetch());
    const { container } = renderWithProviders(<CloseBookForm bookId="book-1" />);

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    await confirmClose(container);

    await waitFor(() => expect(formSubmit(container).disabled).toBe(true));
    expect(formSubmit(container).textContent).toContain('A encerrar');
  });

  it('surfaces an inline error note and error toast on failure, without calling onClosed', async () => {
    const onClosed = vi.fn();
    const { fn } = recordingFetch(() =>
      jsonResponse({ error: 'livro já se encontra encerrado' }, 409),
    );
    vi.stubGlobal('fetch', fn);
    const { container } = renderWithProviders(
      <CloseBookForm bookId="book-1" onClosed={onClosed} />,
    );

    fireEvent.change(screen.getByLabelText('Data de encerramento'), {
      target: { value: '2026-07-13' },
    });
    await confirmClose(container);

    // Inline ErrorNote (close.error) and the error toast both surface the server message.
    expect(
      (await screen.findAllByText('livro já se encontra encerrado')).length,
    ).toBeGreaterThanOrEqual(1);
    expect(onClosed).not.toHaveBeenCalled();
    // The submit returns to its idle, enabled state after the failure.
    await waitFor(() => expect(formSubmit(container).disabled).toBe(false));
  });
});
