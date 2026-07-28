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
import { termoPtPT } from './termoStrings';
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
  body?: unknown;
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
    {
      ...SIGNING_TERMO.signatories[0],
      signed: true,
      signed_at: '2026-01-03T00:00:00Z',
      pades_document_available: true,
    },
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
 * fires. The levels mirror `confirmation.rs`'s floors: freezing is a plain confirm; opening is
 * floored at a typed phrase plus step-up, because it appends the `book.opened` genesis event.
 */
function confirmationPolicyJson(): Response {
  return jsonResponse({
    actions: [
      {
        action: 'termo_abertura.advance',
        floor: 'confirm',
        effective: 'confirm',
        consequence: 'consequential',
        wired: true,
      },
      {
        action: 'termo_abertura.open',
        floor: 'confirm_with_reauth_and_phrase',
        effective: 'confirm_with_reauth_and_phrase',
        phrase: 'ABRIR LIVRO',
        consequence: 'consequential',
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
 * Satisfy the open dialog's server-declared gate: transcribe the phrase and supply a step-up
 * proof. Both fields are found structurally (the phrase box is the dialog's only `.mono` input),
 * never by their translated labels.
 */
function passOpenGate(): void {
  const dialog = screen.getByRole('dialog');
  const phrase = dialog.querySelector<HTMLInputElement>('input.mono');
  if (phrase) fireEvent.change(phrase, { target: { value: 'ABRIR LIVRO' } });
  const password = dialog.querySelector<HTMLInputElement>('input[type=password]');
  if (password) fireEvent.change(password, { target: { value: 'segredo-da-amelia' } });
}

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

    const { container } = renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    // The draft seeds the editor from the loaded termo.
    const title = (await screen.findByLabelText('Título do termo')) as HTMLInputElement;
    expect(title.value).toBe('Termo de abertura');
    // The signatory slot is editable (the termo is an ata, not a static record).
    expect(screen.getByDisplayValue('Amélia Marques')).toBeTruthy();

    // The complete draft is one settings-row composition. Metadata, body, signatories and
    // actions share one stable outer label column; repeated structures use compact nested tables.
    const rows = container.querySelector('.termo-editor__rows.settings-rows');
    expect(rows).toBeTruthy();
    expect(rows?.querySelectorAll(':scope > .field')).toHaveLength(11);
    expect(title.closest('.field')?.parentElement).toBe(rows);
    expect(screen.getByLabelText('Finalidade').closest('.field')?.parentElement).toBe(rows);
    expect(screen.getByLabelText('Data de abertura').closest('.field')?.parentElement).toBe(rows);
    expect(screen.getByLabelText('Texto').closest('.field-table')).toBeTruthy();
    expect(screen.getByDisplayValue('Amélia Marques').closest('.field-table')).toBeTruthy();
    expect(screen.getByRole('switch', { name: 'Exigido' })).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Guardar rascunho' }).closest('.field')?.parentElement,
    ).toBe(rows);

    fireEvent.change(title, { target: { value: 'Termo de abertura do Livro 1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar rascunho' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'PATCH' && c.url.endsWith('/termo/abertura'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('Rascunho guardado.')).toBeTruthy();
  });

  // --- The sede (registered office) the termo declares -----------------------------------------
  //
  // These assert on the input's stable id (`#termo-entity-seat`) and on the PATCH payload, never on
  // rendered pt-PT sentences: the copy is reviewable prose and a substring match on it would pass or
  // fail for reasons that have nothing to do with the behaviour being pinned.

  const BOOK = { id: 'book-2', entity_id: 'ent-1' };

  /** Stub the three reads the panel makes, plus a PATCH echo; record every request body. */
  function stubReads(options: { entitySeat: string; termo?: TermoInstrumentView }) {
    const bodies: { url: string; method: string; body: unknown }[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (init?.body) bodies.push({ url, method, body: JSON.parse(String(init.body)) });
      if (url.endsWith('/termo/abertura')) {
        return Promise.resolve(jsonResponse(options.termo ?? DRAFT_TERMO));
      }
      if (url.endsWith('/entities/ent-1')) {
        return Promise.resolve(jsonResponse({ ...ENTITY, seat: options.entitySeat }));
      }
      if (url.endsWith('/books/book-2')) return Promise.resolve(jsonResponse(BOOK));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);
    return bodies;
  }

  const ENTITY = {
    id: 'ent-1',
    tenant_id: 'tenant-1',
    group_id: null,
    name: 'Encosto Estratégico Lda',
    nipc: '503004642',
    nipc_validated: true,
    seat: '',
    family: 'CommercialCompany',
    kind: 'Lda',
  };

  it("seeds the sede from the entity's registered office, postal code included", async () => {
    stubReads({ entitySeat: 'Rua das Amoreiras, n.º 12, 1250-020 Lisboa' });

    const { container } = renderWithProviders(<TermoAberturaEditor bookId="book-2" />);
    await screen.findByLabelText('Título do termo');

    await waitFor(() => {
      const seat = container.querySelector<HTMLInputElement>('#termo-entity-seat');
      expect(seat?.value).toBe('Rua das Amoreiras, n.º 12, 1250-020 Lisboa');
    });
    // The seeded default is a real seat, so nothing warns about a missing one.
    expect(container.querySelector('.inline-warning--warn')).toBeNull();
  });

  it("sends the operator's override as the sede this termo declares", async () => {
    const bodies = stubReads({ entitySeat: 'Rua das Amoreiras, n.º 12, 1250-020 Lisboa' });

    const { container } = renderWithProviders(<TermoAberturaEditor bookId="book-2" />);
    await screen.findByLabelText('Título do termo');
    await waitFor(() =>
      expect(container.querySelector<HTMLInputElement>('#termo-entity-seat')?.value).not.toBe(''),
    );

    const seat = container.querySelector<HTMLInputElement>('#termo-entity-seat')!;
    fireEvent.change(seat, {
      target: { value: 'Avenida da Liberdade, n.º 214, 1250-148 Lisboa' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar rascunho' }));

    await waitFor(() => expect(bodies.some((b) => b.method === 'PATCH')).toBe(true));
    const patch = bodies.find((b) => b.method === 'PATCH')!.body as Record<string, unknown>;
    expect(patch.entity_seat).toBe('Avenida da Liberdade, n.º 214, 1250-148 Lisboa');
    // The place of drawing up is a different fact and must not have been filled from the seat.
    expect(patch.place).toBeUndefined();
  });

  it("keeps the sede the termo already declares over the entity's current one", async () => {
    stubReads({
      entitySeat: 'Rua das Amoreiras, n.º 12, 1250-020 Lisboa',
      termo: {
        ...DRAFT_TERMO,
        fields: { ...DRAFT_TERMO.fields, entity_seat: 'Largo da Sé, n.º 3, 3000-138 Coimbra' },
      },
    });

    const { container } = renderWithProviders(<TermoAberturaEditor bookId="book-2" />);
    await screen.findByLabelText('Título do termo');

    // The entity read resolves too; the declared snapshot must survive its arrival.
    await waitFor(() =>
      expect(container.querySelector<HTMLInputElement>('#termo-entity-seat')?.value).toBe(
        'Largo da Sé, n.º 3, 3000-138 Coimbra',
      ),
    );
  });

  it('says so when neither the termo nor the entity has a sede, instead of showing a blank', async () => {
    const bodies = stubReads({ entitySeat: '' });

    const { container } = renderWithProviders(<TermoAberturaEditor bookId="book-2" />);
    await screen.findByLabelText('Título do termo');

    await waitFor(() => expect(container.querySelector('.inline-warning--warn')).toBeTruthy());
    expect(container.querySelector<HTMLInputElement>('#termo-entity-seat')?.value).toBe('');

    // Saving does not invent one: the empty string clears the override rather than declaring a
    // blank office, and the server refuses to seal a termo with no seat on either side.
    fireEvent.click(screen.getByRole('button', { name: 'Guardar rascunho' }));
    await waitFor(() => expect(bodies.some((b) => b.method === 'PATCH')).toBe(true));
    expect(
      (bodies.find((b) => b.method === 'PATCH')!.body as Record<string, unknown>).entity_seat,
    ).toBe('');
  });

  it('collects a signature and surfaces the honest fail-closed 409 on open', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/abertura/open')) {
        // The evidentiary gate: a required slot carries no real per-slot PAdES signature (a slot
        // recorded as signed by *reference* only reaches exactly this refusal).
        return Promise.resolve(
          jsonResponse(
            {
              error: 'the termo de abertura is not cryptographically signed',
              code: 'termo_abertura_not_signed',
            },
            409,
          ),
        );
      }
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/abertura/sign')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNING_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    // The signing phase offers a sign action for the first unsigned required slot.
    expect(await screen.findByRole('button', { name: 'Assinar' })).toBeTruthy();
    expect(document.querySelector('.termo-status-table')).toBeTruthy();
    expect(document.querySelector('.termo-signatories-table')).toBeTruthy();
    expect(
      screen
        .getByRole('button', { name: termoPtPT['books.termo.action.open'] })
        .closest('.termo-action-row'),
    ).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: termoPtPT['books.termo.action.open'] }));
    await screen.findByRole('dialog');
    passOpenGate();
    fireEvent.click(dialogConfirm()!);

    // The refusal is surfaced honestly — the book is NOT pretended open. Keyed on the exported
    // copy entry, not on a transcribed sentence: a reworded headline must not flip this test.
    expect(await screen.findByText(termoPtPT['books.termo.open.notSignedTitle'])).toBeTruthy();
  });

  /**
   * The fail-closed headline asserts one specific cause. The open path answers `409` for other
   * reasons too, and dressing one of those in the "not cryptographically signed" headline reports
   * the wrong cause for a refusal on a legal instrument. Classified on the server's stable `code`;
   * anything else falls through to `ErrorNote`, which says what the server said.
   *
   * Asserted on the rendered tone class, not on copy: the two notes are distinguishable by
   * structure alone.
   */
  it('does not claim "not signed" for a 409 that is a different refusal', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.endsWith('/termo/abertura/open')) {
        return Promise.resolve(
          jsonResponse({ error: 'book is not in the Created state; it cannot be opened' }, 409),
        );
      }
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNED_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    const { container } = renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.action.open'] }),
    );
    await screen.findByRole('dialog');
    passOpenGate();
    fireEvent.click(dialogConfirm()!);

    await waitFor(() => expect(container.querySelector('.inline-warning--error')).toBeTruthy());
    expect(container.querySelector('.inline-warning--warn')).toBeNull();
    expect(screen.queryByText(termoPtPT['books.termo.open.notSignedTitle'])).toBeNull();
  });

  // --- The guarded actions the server declares (t78, enforced t80) ------------------------------
  //
  // `confirmation.rs` registers `termo_abertura.advance` and `termo_abertura.open` in `ROUTE_GUARD`.
  // They are no longer alike:
  //
  //   • `termo_abertura.open` is floored at confirm-with-reauth-and-phrase and the handler now CALLS
  //     `require_confirmation` (t80), so the server refuses a request whose body carries no proof.
  //     The dialog gathers it; the request must actually transmit it, which is what
  //     `carries the gathered proof …` below pins — a client that opened the dialog and then sent an
  //     empty body would render identically and 403 in production.
  //   • `termo_abertura.advance` is floored at `confirm`, which no server can observe, so for that
  //     one the client really is the gate.
  //
  // Both still pin the ABSENCE of a write before the operator confirms — not that a dialog renders,
  // which would pass even if the mutation had already gone out behind it.

  it('writes nothing when the freeze is asked for, until the dialog is confirmed', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method });
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/abertura/advance'))
        return Promise.resolve(jsonResponse(SIGNING_TERMO));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(DRAFT_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);
    await screen.findByLabelText('Título do termo');

    fireEvent.click(screen.getByRole('button', { name: termoPtPT['books.termo.action.advance'] }));
    await screen.findByRole('dialog');

    // The freeze saves before it advances, so BOTH writes must still be absent — a gate that let
    // the PATCH through would have already persisted the edits the operator did not commit to.
    expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0);

    fireEvent.click(dialogConfirm()!);

    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/advance')),
      ).toBe(true),
    );
    expect(calls.some((c) => c.method === 'PATCH')).toBe(true);
  });

  it('writes nothing when the open is asked for, until the phrase gate is passed', async () => {
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/abertura/open'))
        return Promise.resolve(jsonResponse({ id: 'book-2', entity_id: 'ent-1', state: 'Open' }));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNED_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.action.open'] }),
    );
    await screen.findByRole('dialog');

    // Nothing written, and the server's declared level cannot be satisfied by an empty gate: the
    // genesis commit is not one stray click away.
    expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0);
    expect(dialogConfirm()?.disabled).toBe(true);

    passOpenGate();
    expect(calls.filter((c) => c.method !== 'GET')).toHaveLength(0);

    fireEvent.click(dialogConfirm()!);
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/open'))).toBe(
        true,
      ),
    );
  });

  it('carries the gathered proof in the open request the server verifies', async () => {
    // The server half of this gate (t80) reads `confirmation.reauth` and `confirmation.confirm_phrase`
    // off the request body and refuses with `403` when either is missing. A dialog that gathers both
    // and then posts them nowhere looks correct on screen and opens no book, so the transmitted body
    // is what has to be asserted — not the dialog.
    const calls: RecordedCall[] = [];
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: init?.body ? JSON.parse(init.body as string) : undefined });
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
      if (url.endsWith('/termo/abertura/open'))
        return Promise.resolve(jsonResponse({ id: 'book-2', entity_id: 'ent-1', state: 'Open' }));
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNED_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);
    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.action.open'] }),
    );
    await screen.findByRole('dialog');
    passOpenGate();
    fireEvent.click(dialogConfirm()!);

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/open'))).toBe(
        true,
      ),
    );
    const open = calls.find((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/open'));
    const body = open?.body as
      | { confirmation?: { reauth?: { password?: string }; confirm_phrase?: string } }
      | undefined;
    expect(body?.confirmation?.reauth?.password).toBe('segredo-da-amelia');
    // Byte-exact and deliberately non-localised, like `ASSINAR TESTE`: the server compares it
    // literally, so a translated phrase would be a `403` in every locale but pt-PT.
    expect(body?.confirmation?.confirm_phrase).toBe('ABRIR LIVRO');
  });

  it('renders the Sealed phase as status rows with a labelled artifact action row', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/abertura')) {
        return Promise.resolve(jsonResponse({ ...SIGNED_TERMO, state: 'Sealed' }));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    expect(
      await screen.findByText('O termo produziu efeito e o livro foi aberto. É imutável.'),
    ).toBeTruthy();
    expect(document.querySelector('.termo-status-table')).toBeTruthy();
    expect(
      screen
        .getByRole('button', { name: 'Descarregar PDF base sem assinaturas' })
        .closest('.termo-action-row'),
    ).toBeTruthy();
  });

  it('labels the frozen base as unsigned and hides downloads for provisional-only signatures', async () => {
    const provisionalOnly: TermoInstrumentView = {
      ...SIGNED_TERMO,
      signatories: [
        {
          ...SIGNED_TERMO.signatories[0],
          signed: true,
          pades_document_available: false,
        },
      ],
    };
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(provisionalOnly));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    expect(
      await screen.findByRole('button', { name: 'Descarregar PDF base sem assinaturas' }),
    ).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Descarregar PDF assinado:/ })).toBeNull();
  });

  it('offers a signed-PDF download only when the server reports a stored PAdES artifact', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SIGNED_TERMO));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    expect(
      await screen.findByRole('button', {
        name: 'Descarregar PDF assinado: Amélia Marques',
      }),
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
      if (url.includes('/v1/confirmation-policy')) return Promise.resolve(confirmationPolicyJson());
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
    fireEvent.click(screen.getByRole('button', { name: termoPtPT['books.termo.action.open'] }));
    await screen.findByRole('dialog');
    passOpenGate();
    fireEvent.click(dialogConfirm()!);
    await waitFor(() =>
      expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/termo/abertura/open'))).toBe(
        true,
      ),
    );
    expect(screen.queryByText(termoPtPT['books.termo.open.notSignedTitle'])).toBeNull();
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
