import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { DraftAtaForm } from './DraftAtaForm';
import type { ActView } from '../../api/types';

interface RecordedCall {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

const NEW_ACT = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Ordinária',
  channel: 'Telematic',
  state: 'Draft',
} as unknown as ActView;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

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

function pendingFetch() {
  return (() => new Promise<Response>(() => {})) as typeof fetch;
}

/**
 * Mount the form on its route with a marker route for the ata editor, so a successful
 * draft that navigates to `/acts/:id` is observable.
 */
function renderDraft(bookId = 'book-1') {
  return renderWithProviders(
    <Routes>
      <Route path="/books/:id/new-act" element={<DraftAtaForm bookId={bookId} />} />
      <Route path="/acts/:id" element={<div>EDITOR DE ATA</div>} />
    </Routes>,
    ['/books/book-1/new-act'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('DraftAtaForm', () => {
  it('renders the title and channel fields with an enabled submit', () => {
    vi.stubGlobal('fetch', pendingFetch());
    renderDraft();

    expect(screen.getByLabelText('Título da ata')).toBeTruthy();
    expect(screen.getByLabelText('Canal da reunião')).toBeTruthy();
    expect(screen.getByPlaceholderText('Assembleia Geral Ordinária')).toBeTruthy();

    const submit = screen.getByRole('button', { name: /nova ata/i }) as HTMLButtonElement;
    expect(submit.disabled).toBe(false);
  });

  it('drafts the ata with the typed title and chosen channel, then navigates to the editor', async () => {
    const { fn, calls } = recordingFetch(() => jsonResponse(NEW_ACT, 201));
    vi.stubGlobal('fetch', fn);
    renderDraft();

    fireEvent.change(screen.getByLabelText('Título da ata'), {
      target: { value: 'Assembleia Geral Ordinária' },
    });
    fireEvent.change(screen.getByLabelText('Canal da reunião'), {
      target: { value: 'Telematic' },
    });
    fireEvent.click(screen.getByRole('button', { name: /nova ata/i }));

    // Success toast survives the navigate-away, and the editor route renders.
    expect(await screen.findByText('Ata criada.')).toBeTruthy();
    expect(await screen.findByText('EDITOR DE ATA')).toBeTruthy();

    const draftCall = calls.find((c) => c.method === 'POST');
    expect(draftCall?.url).toBe('/v1/acts');
    expect(draftCall?.body).toEqual({
      book_id: 'book-1',
      title: 'Assembleia Geral Ordinária',
      channel: 'Telematic',
    });
  });

  it('disables the submit and shows the pending label while the draft is in flight', async () => {
    vi.stubGlobal('fetch', pendingFetch());
    renderDraft();

    fireEvent.change(screen.getByLabelText('Título da ata'), {
      target: { value: 'Assembleia Geral Ordinária' },
    });
    fireEvent.click(screen.getByRole('button', { name: /nova ata/i }));

    const pending = await screen.findByRole('button', { name: /a criar/i });
    expect((pending as HTMLButtonElement).disabled).toBe(true);
    expect(pending.textContent).toContain('A criar');
  });

  it('shows an inline error note and error toast on failure, staying on the form', async () => {
    const { fn } = recordingFetch(() =>
      jsonResponse({ error: 'livro não está aberto para novas atas' }, 409),
    );
    vi.stubGlobal('fetch', fn);
    renderDraft();

    fireEvent.change(screen.getByLabelText('Título da ata'), {
      target: { value: 'Assembleia Geral Ordinária' },
    });
    fireEvent.click(screen.getByRole('button', { name: /nova ata/i }));

    expect(
      (await screen.findAllByText('livro não está aberto para novas atas')).length,
    ).toBeGreaterThanOrEqual(1);
    // No navigation happened: the editor marker never appears.
    await waitFor(() => expect(screen.queryByText('EDITOR DE ATA')).toBeNull());
    expect(screen.getByLabelText('Título da ata')).toBeTruthy();
  });
});
