/**
 * Unit tests for StartOverBookModal (per-book start-over, t54-E4). The modal wraps the
 * shared ConfirmActionModal (which now uses the shared useFocusTrap hook) around a
 * required reason + the new book's opening spec. These tests cover: initial render +
 * focus landing inside the trapped dialog, the confirm gate on the required fields, the
 * successful POST body + toast + close, the pending label in flight (§5) and the inline
 * error + toast on a 503 while the instance is forward-write blocked (§2/§7).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { StartOverBookModal } from './StartOverBookModal';
import type { BookView, StartOverBookResult } from '../../api/types';

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

const RESULT: StartOverBookResult = {
  reinit: {
    scope: 'Book',
    archive_path: 'F:\\ChancelaData\\archives\\book-1.cbackup',
    archived_bundle_digest: 'a'.repeat(64),
    old_book_id: 'book-1',
    new_book_id: 'book-2',
  },
  new_book: { ...BOOK, id: 'book-2', last_ata_number: 0 },
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  method: string;
  body: unknown;
}

function installFetch(handleStartOver: () => Response | Promise<Response>): Recorded[] {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(init.body as string) : null;
    calls.push({ url, method, body });
    if (url.includes('/v1/books/book-1/start-over') && method === 'POST') {
      return Promise.resolve(handleStartOver());
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('StartOverBookModal', () => {
  it('renders the dialog, prefills purpose/opening date and moves focus to the reason field', async () => {
    installFetch(() => jsonResponse(RESULT));
    renderWithProviders(<StartOverBookModal book={BOOK} onClose={vi.fn()} />);

    expect(screen.getByRole('dialog', { name: 'Recomeçar livro' })).toBeTruthy();
    const reason = screen.getByLabelText('Motivo');
    // Purpose is seeded from the book; opening date defaults to a filled ISO date.
    expect((screen.getByLabelText('Finalidade do novo livro') as HTMLInputElement).value).toBe(
      'Atas da Assembleia',
    );
    expect((screen.getByLabelText('Data de abertura') as HTMLInputElement).value).not.toBe('');
    // useFocusTrap + the modal's field-autofocus land focus on the first field (reason).
    await waitFor(() => expect(document.activeElement).toBe(reason));
  });

  it('keeps confirm disabled until a reason and at least one signatory are supplied', () => {
    installFetch(() => jsonResponse(RESULT));
    renderWithProviders(<StartOverBookModal book={BOOK} onClose={vi.fn()} />);

    const confirm = screen.getByRole('button', { name: 'Recomeçar' }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Motivo'), {
      target: { value: 'Novo exercício' },
    });
    // Reason alone is not enough — the signatories are still empty.
    expect(confirm.disabled).toBe(true);

    fireEvent.change(screen.getByLabelText('Signatários obrigatórios'), {
      target: { value: 'Amélia Marques' },
    });
    expect(confirm.disabled).toBe(false);
  });

  it('posts the trimmed reason + opening spec, toasts and closes on success', async () => {
    const onClose = vi.fn();
    const calls = installFetch(() => jsonResponse(RESULT));
    renderWithProviders(<StartOverBookModal book={BOOK} onClose={onClose} />);

    const openingDate = (screen.getByLabelText('Data de abertura') as HTMLInputElement).value;
    fireEvent.change(screen.getByLabelText('Motivo'), {
      target: { value: '  Novo exercício  ' },
    });
    fireEvent.change(screen.getByLabelText('Signatários obrigatórios'), {
      target: { value: 'Amélia Marques,  João Silva ,' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Recomeçar' }));

    await waitFor(() => expect(calls.some((c) => c.url.includes('/start-over'))).toBe(true));
    const post = calls.find((c) => c.url.includes('/start-over'))!;
    expect(post.method).toBe('POST');
    expect(post.body).toEqual({
      reason: 'Novo exercício',
      purpose: 'Atas da Assembleia',
      opening_date: openingDate,
      required_signatories: ['Amélia Marques', 'João Silva'],
      numbering_scheme: 'Sequential',
    });
    expect(await screen.findByText('Livro recomeçado.')).toBeTruthy();
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });

  it('shows the pending label and disables confirm while start-over is in flight (§5)', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    installFetch(() => gate.then(() => jsonResponse(RESULT)));
    renderWithProviders(<StartOverBookModal book={BOOK} onClose={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('Motivo'), { target: { value: 'Novo exercício' } });
    fireEvent.change(screen.getByLabelText('Signatários obrigatórios'), {
      target: { value: 'Amélia Marques' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Recomeçar' }));

    const pending = (await screen.findByRole('button', {
      name: 'A recomeçar…',
    })) as HTMLButtonElement;
    expect(pending.disabled).toBe(true);

    release();
    await waitFor(() => expect(screen.getByText('Livro recomeçado.')).toBeTruthy());
  });

  it('surfaces a 503 forward-write-blocked failure inline and via toast, keeping the modal open', async () => {
    const onClose = vi.fn();
    installFetch(() => jsonResponse({ error: 'instância degradada: escrita bloqueada' }, 503));
    renderWithProviders(<StartOverBookModal book={BOOK} onClose={onClose} />);

    fireEvent.change(screen.getByLabelText('Motivo'), { target: { value: 'Novo exercício' } });
    fireEvent.change(screen.getByLabelText('Signatários obrigatórios'), {
      target: { value: 'Amélia Marques' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Recomeçar' }));

    // Inline field error + toast both carry the server message (the R7 spine).
    await waitFor(() =>
      expect(screen.getAllByText('instância degradada: escrita bloqueada')).toHaveLength(2),
    );
    // The modal must not close on a failed forward-write.
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog', { name: 'Recomeçar livro' })).toBeTruthy();
  });
});
