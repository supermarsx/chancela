/**
 * TermoEncerramentoEditor (t44) — the termo de encerramento as a signable ata in its own right, the
 * CLOSE mirror of `TermoAberturaEditor.test.tsx`. These tests cover the Draft edit (incl. the DA1
 * "Other" reason + required note reveal), the Signing collect, and every honest fail-closed `409`
 * cause on close, all through the frozen t44-e3 client.
 *
 * **The close refusals are classified by the server's stable error `code`, never by its prose**
 * (t58-e3a). Three of the tests below exist specifically to hold that line: one sends the retired
 * regex's exact prose under a *contradicting* code, one sends that prose with no code at all, and
 * both assert the branch follows the code. A regex over prose could not have survived either.
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

/** The termo after the sole required slot carries a real per-slot PAdES signature. */
const SIGNED_TERMO: TermoInstrumentView = {
  ...SIGNING_TERMO,
  signatories: [
    { ...SIGNING_TERMO.signatories[0], signed: true, signed_at: '2026-07-02T00:00:00Z' },
  ],
  completion: {
    ...SIGNING_TERMO.completion,
    signed_required_slot_count: 1,
    blocking_required_slot_ids: [],
    complete: true,
  },
};

/**
 * `GET /v1/confirmation-policy` as the server emits it, for the two guarded actions this panel
 * fires. The levels mirror `confirmation.rs`'s floors: freezing is a plain confirm; closing is
 * floored at a typed phrase plus step-up, because `chancela_core::book` has no way back from
 * `Closed`.
 */
function confirmationPolicyJson(): Response {
  return jsonResponse({
    actions: [
      {
        action: 'termo_encerramento.advance',
        floor: 'confirm',
        effective: 'confirm',
        consequence: 'consequential',
        wired: true,
      },
      {
        action: 'termo_encerramento.close',
        floor: 'confirm_with_reauth_and_phrase',
        effective: 'confirm_with_reauth_and_phrase',
        phrase: 'ENCERRAR LIVRO',
        consequence: 'destructive',
        wired: true,
      },
    ],
  });
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
async function confirmClose(): Promise<void> {
  fireEvent.click(await screen.findByRole('button', { name: 'Encerrar livro' }));
  const dialog = await screen.findByRole('dialog');
  const phrase = dialog.querySelector<HTMLInputElement>('input.mono');
  if (phrase) fireEvent.change(phrase, { target: { value: 'ENCERRAR LIVRO' } });
  const password = dialog.querySelector<HTMLInputElement>('input[type=password]');
  if (password) fireEvent.change(password, { target: { value: 'segredo-da-amelia' } });
  fireEvent.click(dialogConfirm()!);
}

afterEach(() => {
  cleanup();
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
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

    const { container } = renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    const title = (await screen.findByLabelText('Título do termo')) as HTMLInputElement;
    expect(title.value).toBe('Termo de encerramento');
    const date = screen.getByLabelText('Data de encerramento') as HTMLInputElement;
    expect(date.value).toBe('2026-06-30');

    const rows = container.querySelector('.termo-editor__rows.settings-rows');
    expect(rows).toBeTruthy();
    expect(rows?.querySelectorAll(':scope > .field')).toHaveLength(9);
    expect(title.closest('.field')?.parentElement).toBe(rows);
    expect(date.closest('.field')?.parentElement).toBe(rows);
    expect(screen.getByLabelText('Texto').closest('.field-table')).toBeTruthy();
    expect(screen.getByDisplayValue('Amélia Marques').closest('.field-table')).toBeTruthy();
    const required = screen.getByRole('switch', { name: 'Exigido' });
    expect(required).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Guardar rascunho' }).closest('.field')?.parentElement,
    ).toBe(rows);

    // DA1 — choosing "Outro" reveals a required free-text note.
    expect(screen.queryByLabelText('Qual o motivo')).toBeNull();
    fireEvent.change(screen.getByLabelText('Motivo do encerramento'), {
      target: { value: 'Other' },
    });
    const note = (await screen.findByLabelText('Qual o motivo')) as HTMLInputElement;
    fireEvent.change(note, { target: { value: 'Fusão por incorporação' } });
    fireEvent.click(required);

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
    expect(
      (
        patch?.body as {
          signatories?: Array<{ required?: boolean }>;
        }
      ).signatories?.[0]?.required,
    ).toBe(false);
    expect(await screen.findByText('Rascunho guardado.')).toBeTruthy();
  });

  it('collects a signature and surfaces the honest not-signed 409 on close', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/encerramento/close')) {
        return Promise.resolve(
          jsonResponse(
            {
              error: 'refusing to close the book: the termo de encerramento is not signed.',
              code: 'termo_encerramento_not_signed',
            },
            409,
          ),
        );
      }
      if (url.endsWith('/termo/encerramento/sign'))
        return Promise.resolve(jsonResponse(SIGNING_TERMO));
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    expect(await screen.findByRole('button', { name: 'Assinar' })).toBeTruthy();
    expect(document.querySelector('.termo-status-table')).toBeTruthy();
    expect(document.querySelector('.termo-signatories-table')).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Encerrar livro' }).closest('.termo-action-row'),
    ).toBeTruthy();
    await confirmClose();

    expect(
      await screen.findByText('O termo ainda não está assinado criptograficamente'),
    ).toBeTruthy();
  });

  it('renders the Sealed phase in the same one-column status-row convention', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/encerramento')) {
        return Promise.resolve(jsonResponse({ ...SIGNED_TERMO, state: 'Sealed' }));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    expect(
      await screen.findByText('O termo produziu efeito e o livro foi encerrado. É imutável.'),
    ).toBeTruthy();
    expect(document.querySelector('.termo-status-table')).toBeTruthy();
    expect(document.querySelector('.termo-status-table')?.children).toHaveLength(2);
  });

  /** Drive `close` to a `409` carrying `body`, and return once the panel has rendered. */
  function stubCloseRefusal(body: Record<string, unknown>) {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/encerramento/close')) {
        return Promise.resolve(jsonResponse(body, 409));
      }
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);
  }

  it('surfaces the stale-fact 409 distinctly on close', async () => {
    // The prose deliberately shares nothing with the retired `/nova ata|número de atas/i` regex:
    // the `code` alone must select this branch.
    stubCloseRefusal({
      error: 'the declared figures no longer match the book',
      code: 'termo_stale_facts',
    });

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    await confirmClose();

    expect(await screen.findByText('Os factos do livro mudaram durante a assinatura')).toBeTruthy();
  });

  /**
   * THE REGRESSION THE RETIRED REGEX COULD NOT SURVIVE.
   *
   * `termo_snapshot_render_drift` means the document's composition moved while the book's figures
   * stayed correct — the opposite claim to `termo_stale_facts`. The body below carries the OLD
   * stale-fact prose verbatim, so `/nova ata|número de atas/i` would have classified it `stale` and
   * told the operator a new ata was registered when none was. The branch must follow the `code`.
   */
  it('classifies render drift by code even when the message reads like the old stale-fact prose', async () => {
    stubCloseRefusal({
      error:
        'o livro registou uma nova ata depois de o termo de encerramento ter sido congelado; o número de atas declarado deixou de corresponder ao livro.',
      code: 'termo_snapshot_render_drift',
    });

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    await confirmClose();

    expect(
      await screen.findByText(/O que mudou foi a composição do documento, não os dados do livro/),
    ).toBeTruthy();
    // The stale-fact claim must be absent: no ata was registered.
    expect(screen.queryByText('Os factos do livro mudaram durante a assinatura')).toBeNull();
    // And the server's raw prose is never what the operator reads.
    expect(screen.queryByText(/o livro registou uma nova ata/)).toBeNull();
  });

  it('surfaces the snapshot-mismatch 409 without naming a cause it has not established', async () => {
    stubCloseRefusal({
      error: 'the termo de encerramento no longer re-renders to the bytes its signatories signed',
      code: 'termo_snapshot_mismatch',
    });

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    await confirmClose();

    expect(await screen.findByText(/Não foi possível apurar em que ponto divergiu/)).toBeTruthy();
    expect(screen.queryByText('Os factos do livro mudaram durante a assinatura')).toBeNull();
    expect(screen.queryByText('O termo ainda não está assinado criptograficamente')).toBeNull();
  });

  /**
   * NO PROSE FALLBACK. A `409` whose message matches the retired regex word for word, but which
   * carries no `code`, must not be classified at all — it renders through `ErrorNote` rather than
   * asserting either fail-closed cause on no evidence.
   */
  it('does not classify a coded-less 409 from its prose', async () => {
    stubCloseRefusal({
      error:
        'o livro registou uma nova ata depois de o termo de encerramento ter sido congelado; o número de atas declarado deixou de corresponder ao livro.',
    });

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    await confirmClose();

    // `ErrorNote`'s generic 409 tier headline — it claims no cause, and the English prose is
    // demoted into the technical-details block rather than becoming the operator's copy.
    await waitFor(() => expect(document.querySelector('.error-note__headline')).toBeTruthy());
    expect(document.querySelector('.error-note__headline')?.textContent).toBe(
      'A operação foi recusada porque o estado atual não a permite.',
    );
    expect(screen.queryByText('Os factos do livro mudaram durante a assinatura')).toBeNull();
    expect(screen.queryByText('O termo ainda não está assinado criptograficamente')).toBeNull();
  });

  // --- The guarded actions the server declares (t78) --------------------------------------------
  //
  // `confirmation.rs` registers `termo_encerramento.advance` and `termo_encerramento.close` in
  // `ROUTE_GUARD` and neither handler calls `require_confirmation`, so for these the client IS the
  // gate. What these pin is the ABSENCE of a write before the operator confirms — not that a dialog
  // renders, which would still pass if the mutation had already gone out behind it.

  it('writes nothing when the freeze is asked for, until the dialog is confirmed', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/encerramento/advance'))
        return Promise.resolve(jsonResponse(SIGNING_TERMO));
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(DRAFT_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);
    await screen.findByLabelText('Título do termo');

    fireEvent.click(screen.getByRole('button', { name: 'Avançar para assinatura' }));
    await screen.findByRole('dialog');

    // The freeze saves before it advances, so BOTH writes must still be absent.
    expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0);

    fireEvent.click(dialogConfirm()!);

    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/encerramento/advance')),
      ).toBe(true),
    );
    expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
  });

  it('writes nothing when the close is asked for, until the phrase gate is passed', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/encerramento/close'))
        return Promise.resolve(jsonResponse({ id: 'book-2', entity_id: 'ent-1', state: 'Closed' }));
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(SIGNED_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Encerrar livro' }));
    await screen.findByRole('dialog');

    // Nothing written, and the server's declared level cannot be satisfied by an empty gate: an
    // irreversible close is not one stray click away.
    expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0);
    expect(dialogConfirm()?.disabled).toBe(true);

    fireEvent.click(dialogConfirm()!);
    expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0);
  });

  it('signs a slot with a real PKCS#12 co-signature, then the book closes', async () => {
    (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (url.endsWith('/termo/encerramento/sign/pkcs12'))
        return Promise.resolve(jsonResponse(SIGNED_TERMO));
      if (url.endsWith('/termo/encerramento/close'))
        return Promise.resolve(jsonResponse({ id: 'book-2', entity_id: 'ent-1', state: 'Closed' }));
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: 'Assinar' }));
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [new File(['pfx-bytes'], 'cert.pfx', { type: 'application/x-pkcs12' })] },
    });
    fireEvent.change(screen.getByLabelText('Frase-passe'), { target: { value: 'segredo' } });
    fireEvent.click(screen.getByRole('button', { name: 'Assinar com certificado' }));

    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/encerramento/sign/pkcs12')),
      ).toBe(true),
    );
    expect(await screen.findByText('Assinatura registada.')).toBeTruthy();

    await confirmClose();
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/encerramento/close')),
      ).toBe(true),
    );
    expect(screen.queryByText('O termo ainda não está assinado criptograficamente')).toBeNull();
  });
});
