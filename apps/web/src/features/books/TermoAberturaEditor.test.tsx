/**
 * TermoAberturaEditor (t23) — the termo de abertura as a signable ata in its own right. These tests
 * cover the three phases the panel renders (Draft edit / Signing collect / honest fail-closed open)
 * plus the one-shot "no separately editable termo" note, all through the frozen t23-e4 client.
 */
import { describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach } from 'vitest';
import { renderWithProviders } from '../../test/utils';
import { TermoAberturaEditor } from './TermoAberturaEditor';
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
}

const DRAFT_TERMO: TermoInstrumentView = {
  id: 'termo-1',
  book_id: 'book-2',
  kind: 'Abertura',
  state: 'Draft',
  title: 'Termo de abertura',
  body: [{ id: 'c1', text: 'Aos … dias …', origin: 'TemplateDefault' }],
  fields: { purpose: 'Atas AG', instrument_date: '2026-01-01', page_capacity: 100 },
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
  created_at: '2026-01-01T00:00:00Z',
  declared_signatories: [],
};

const SIGNING_TERMO: TermoInstrumentView = {
  ...DRAFT_TERMO,
  state: 'Signing',
  signing_started_at: '2026-01-02T00:00:00Z',
};

/** The termo after the sole required slot carries a real per-slot PAdES signature. */
const SIGNED_TERMO: TermoInstrumentView = {
  ...SIGNING_TERMO,
  signatories: [
    { ...SIGNING_TERMO.signatories[0], signed: true, signed_at: '2026-01-03T00:00:00Z' },
  ],
  completion: {
    ...SIGNING_TERMO.completion,
    signed_required_slot_count: 1,
    blocking_required_slot_ids: [],
    complete: true,
  },
};

afterEach(() => {
  cleanup();
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('TermoAberturaEditor', () => {
  it('renders the honest "no separately editable termo" note for a one-shot book (404)', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse({}, 404));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    expect(
      await screen.findByText(
        'Este livro foi aberto num único passo e não tem um termo de abertura editável em separado.',
      ),
    ).toBeTruthy();
  });

  it('edits a Draft termo and saves it with a PATCH', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method });
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(DRAFT_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    // The draft seeds the editor from the loaded termo.
    const title = (await screen.findByLabelText('Título do termo')) as HTMLInputElement;
    expect(title.value).toBe('Termo de abertura');
    // The signatory slot is editable (the termo is an ata, not a static record).
    expect(screen.getByDisplayValue('Amélia Marques')).toBeTruthy();

    fireEvent.change(title, { target: { value: 'Termo de abertura do Livro 1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar rascunho' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'PATCH' && c.url.endsWith('/termo/abertura'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('Rascunho guardado.')).toBeTruthy();
  });

  it('collects a signature and surfaces the honest fail-closed 409 on open', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/abertura/open')) {
        // Until real per-slot PAdES lands (t41) the open fails closed for every book.
        return Promise.resolve(
          jsonResponse({ error: 'the termo de abertura is not cryptographically signed' }, 409),
        );
      }
      if (url.endsWith('/termo/abertura/sign')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    // The signing phase offers a sign action for the first unsigned required slot.
    expect(await screen.findByRole('button', { name: 'Assinar' })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Abrir livro' }));

    // The 409 is surfaced honestly — the book is NOT pretended open.
    expect(
      await screen.findByText('O termo ainda não está assinado criptograficamente'),
    ).toBeTruthy();
  });

  it('signs a slot with a real PKCS#12 co-signature, then the book opens', async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method });
      if (url.endsWith('/termo/abertura/sign/pkcs12'))
        return Promise.resolve(jsonResponse(SIGNED_TERMO));
      if (url.endsWith('/termo/abertura/open'))
        return Promise.resolve(jsonResponse({ id: 'book-2', entity_id: 'ent-1', state: 'Open' }));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    // Expand the active slot's real-signature form.
    fireEvent.click(await screen.findByRole('button', { name: 'Assinar' }));

    // Provide the local PKCS#12 certificate + passphrase (transient) and produce the real signature.
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [new File(['pfx-bytes'], 'cert.pfx', { type: 'application/x-pkcs12' })] },
    });
    fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'segredo' } });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar com certificado' }));

    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/sign/pkcs12')),
      ).toBe(true),
    );
    expect(await screen.findByText('Assinatura registada.')).toBeTruthy();

    // With the required slot really signed, the open no longer fails closed.
    fireEvent.click(screen.getByRole('button', { name: 'Abrir livro' }));
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/open'))).toBe(
        true,
      ),
    );
    expect(screen.queryByText('O termo ainda não está assinado criptograficamente')).toBeNull();
  });

  it('does not collect or submit PKCS#12 secrets outside the desktop app', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method });
      if (url.endsWith('/termo/abertura/sign/pkcs12'))
        return Promise.resolve(jsonResponse({ error: 'só na aplicação de secretária' }, 409));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar' }));

    expect(await screen.findByText('Disponível apenas na aplicação de secretária')).toBeTruthy();
    expect(screen.queryByLabelText('Ficheiro PKCS#12/PFX')).toBeNull();
    expect(screen.queryByLabelText('Frase-passe')).toBeNull();
    expect(calls.some((call) => call.url.endsWith('/termo/abertura/sign/pkcs12'))).toBe(false);
  });
});
