/**
 * TermoEncerramentoEditor (t44) — the termo de encerramento as a signable ata in its own right, the
 * CLOSE mirror of `TermoAberturaEditor.test.tsx`. These tests cover the Draft edit (incl. the DA1
 * "Other" reason + required note reveal), the Signing collect, and BOTH honest fail-closed `409`
 * causes on close (not-cryptographically-signed and the stale-fact guard), all through the frozen
 * t44-e3 client.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { TermoEncerramentoEditor } from './TermoEncerramentoEditor';
import type { TermoInstrumentView } from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface RecordedCall {
  url: string;
  method: string;
  body: unknown;
}

const DRAFT_TERMO: TermoInstrumentView = {
  id: 'termo-1',
  book_id: 'book-2',
  kind: 'Encerramento',
  state: 'Draft',
  title: 'Termo de encerramento',
  body: [{ id: 'c1', text: 'Aos … dias …', origin: 'TemplateDefault' }],
  fields: { instrument_date: '2026-06-30' },
  signatories: [
    {
      id: 's1',
      name: 'Amélia Marques',
      capacity: 'Manager',
      required: true,
      order: 1,
      signed: false,
    },
  ],
  completion_policy: 'AllRequired',
  completion: {
    policy: 'AllRequired',
    required_slot_count: 1,
    signed_required_slot_count: 0,
    threshold: 1,
    blocking_required_slot_ids: ['s1'],
    complete: false,
  },
  created_at: '2026-06-30T00:00:00Z',
  declared_signatories: [],
};

const SIGNING_TERMO: TermoInstrumentView = {
  ...DRAFT_TERMO,
  state: 'Signing',
  signing_started_at: '2026-07-01T00:00:00Z',
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('TermoEncerramentoEditor', () => {
  it('does not render a card for a book with no encerramento draft (404)', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse({}, 404));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    const { container } = renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    await waitFor(() => expect(screen.queryByText('Termo de encerramento')).toBeNull());
    expect(container.querySelector('.card')).toBeNull();
  });

  it('edits a Draft termo, reveals the Other-reason note, and saves with a PATCH', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(DRAFT_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    const title = (await screen.findByLabelText('Título do termo')) as HTMLInputElement;
    expect(title.value).toBe('Termo de encerramento');
    const date = screen.getByLabelText('Data de encerramento') as HTMLInputElement;
    expect(date.value).toBe('2026-06-30');

    // DA1 — choosing "Outro" reveals a required free-text note.
    expect(screen.queryByLabelText('Qual o motivo')).toBeNull();
    fireEvent.change(screen.getByLabelText('Motivo do encerramento'), {
      target: { value: 'Other' },
    });
    const note = (await screen.findByLabelText('Qual o motivo')) as HTMLInputElement;
    fireEvent.change(note, { target: { value: 'Fusão por incorporação' } });

    fireEvent.click(screen.getByRole('button', { name: 'Guardar rascunho' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'PATCH' && c.url.endsWith('/termo/encerramento'))).toBe(
        true,
      ),
    );
    const patch = calls.find((c) => c.method === 'PATCH');
    expect((patch?.body as { closing_reason?: unknown }).closing_reason).toEqual({
      Other: { note: 'Fusão por incorporação' },
    });
    expect(await screen.findByText('Rascunho guardado.')).toBeTruthy();
  });

  it('collects a signature and surfaces the honest not-signed 409 on close', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/encerramento/close')) {
        return Promise.resolve(
          jsonResponse({ error: 'the termo is not cryptographically signed' }, 409),
        );
      }
      if (url.endsWith('/termo/encerramento/sign'))
        return Promise.resolve(jsonResponse(SIGNING_TERMO));
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    expect(await screen.findByRole('button', { name: 'Assinar' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Encerrar livro' }));

    expect(
      await screen.findByText('O termo ainda não está assinado criptograficamente'),
    ).toBeTruthy();
  });

  it('surfaces the stale-fact 409 distinctly on close', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/encerramento/close')) {
        return Promise.resolve(
          jsonResponse(
            {
              error:
                'o livro registou uma nova ata depois de o termo de encerramento ter sido congelado; o número de atas declarado deixou de corresponder ao livro.',
            },
            409,
          ),
        );
      }
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Encerrar livro' }));

    expect(await screen.findByText('Os factos do livro mudaram durante a assinatura')).toBeTruthy();
  });
});
