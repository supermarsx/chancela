/**
 * TermoEncerramentoEditor — the drafting surface, the CLOSE mirror of
 * `TermoAberturaEditor.drafting.test.tsx`.
 *
 * The existing `TermoEncerramentoEditor.test.tsx` holds the refusal-classification line (every
 * fail-closed `409` cause is selected by the server's stable `code`) and the phase transitions.
 * This file covers what the operator TYPES: the closing reason (including the `Other` note that
 * becomes part of the record), the book number, the clauses and the signatory slots. Each is
 * asserted through the PATCH payload, because a field that never reaches the body is a termo that
 * closes the book on a fact nobody stated.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { TermoEncerramentoEditor } from './TermoEncerramentoEditor';
import { termoPtPT } from './termoStrings';
import type { TermoInstrumentView, PatchTermoEncerramentoBody } from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
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

function stubReads(termo: TermoInstrumentView, patched: PatchTermoEncerramentoBody[]) {
  vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (method === 'PATCH' && url.endsWith('/termo/encerramento')) {
      patched.push(JSON.parse(String(init?.body)) as PatchTermoEncerramentoBody);
      return Promise.resolve(jsonResponse(termo));
    }
    if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(termo));
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch);
}

async function byId(id: string): Promise<HTMLElement> {
  return waitFor(() => {
    const el = document.getElementById(id);
    if (!el) throw new Error(`no #${id} yet`);
    return el;
  });
}

/** The nth signatory of a captured PATCH body, asserted to exist rather than index-and-hope. */
function slot(body: PatchTermoEncerramentoBody, index: number) {
  const entry = body.signatories?.[index];
  if (!entry) throw new Error(`the PATCH body carries no signatory at ${index}`);
  return entry;
}

function save() {
  fireEvent.click(screen.getByRole('button', { name: termoPtPT['books.termo.editor.save'] }));
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('TermoEncerramentoEditor draft fields', () => {
  it('carries every edited field into the PATCH body', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.change(await byId('encerramento-title'), { target: { value: 'Encerramento do L3' } });
    fireEvent.change(await byId('encerramento-date'), { target: { value: '2026-07-31' } });
    fireEvent.change(await byId('encerramento-number'), { target: { value: '3' } });
    fireEvent.change(await byId('encerramento-place'), { target: { value: 'Coimbra' } });
    fireEvent.change(await byId('encerramento-predecessor-note'), {
      target: { value: 'Sucedido pelo n.º 4' },
    });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0]).toMatchObject({
      title: 'Encerramento do L3',
      closing_date: '2026-07-31',
      book_number: 3,
      place: 'Coimbra',
      predecessor_note: 'Sucedido pelo n.º 4',
    });
  });

  it('omits a blanked place and closing date rather than sending an empty one', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.change(await byId('encerramento-date'), { target: { value: '' } });
    fireEvent.change(await byId('encerramento-place'), { target: { value: '  ' } });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].closing_date).toBeUndefined();
    expect(patched[0].place).toBeUndefined();
  });

  it('sends a named closing reason as the bare wire variant', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.change(await byId('encerramento-reason'), { target: { value: 'EntityDissolved' } });
    // A named reason has no free-text note to fill in.
    expect(document.getElementById('encerramento-reason-note')).toBeNull();
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].closing_reason).toBe('EntityDissolved');
  });

  it('sends an «Other» closing reason as its note, and drops the note when the reason changes back', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    const reason = await byId('encerramento-reason');
    fireEvent.change(reason, { target: { value: 'Other' } });
    fireEvent.change(await byId('encerramento-reason-note'), {
      target: { value: '  Cessação de atividade  ' },
    });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].closing_reason).toEqual({ Other: { note: 'Cessação de atividade' } });

    fireEvent.change(reason, { target: { value: 'BookFull' } });
    expect(document.getElementById('encerramento-reason-note')).toBeNull();
    save();
    await waitFor(() => expect(patched).toHaveLength(2));
    // The free text does not survive as a claim under a different reason.
    expect(patched[1].closing_reason).toBe('BookFull');
  });

  it('adds and edits a body clause', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.addClause'] }),
    );
    fireEvent.change(await byId('encerramento-clause-heading-1'), {
      target: { value: 'Cláusula final' },
    });
    fireEvent.change(await byId('encerramento-clause-text-1'), {
      target: { value: 'Encerrado com 87 atas.' },
    });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].body).toEqual([
      { heading: undefined, text: 'Aos … dias …' },
      { heading: 'Cláusula final', text: 'Encerrado com 87 atas.' },
    ]);
  });

  it('removes a body clause', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.removeClause'] }),
    );
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].body).toEqual([]);
  });

  it('adds a signatory slot at the next order and edits its name and email', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.addSignatory'] }),
    );
    fireEvent.change(await byId('encerramento-slot-name-1'), { target: { value: 'Rui Bastos' } });
    fireEvent.change(await byId('encerramento-slot-email-1'), {
      target: { value: 'rui@exemplo.pt' },
    });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].signatories).toEqual([
      {
        name: 'Amélia Marques',
        email: undefined,
        capacity: 'Manager',
        capacity_note: undefined,
        required: true,
        order: 1,
      },
      {
        name: 'Rui Bastos',
        email: 'rui@exemplo.pt',
        capacity: 'Manager',
        capacity_note: undefined,
        required: true,
        order: 2,
      },
    ]);
  });

  it('sends a signatory capacity note only under the «Other» capacity', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    const capacity = await byId('encerramento-slot-capacity-0');
    fireEvent.change(capacity, { target: { value: 'Other' } });
    fireEvent.change(await byId('encerramento-slot-note-0'), { target: { value: 'Procurador' } });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(slot(patched[0], 0)).toMatchObject({
      capacity: 'Other',
      capacity_note: 'Procurador',
    });

    fireEvent.change(capacity, { target: { value: 'Secretary' } });
    save();
    await waitFor(() => expect(patched).toHaveLength(2));
    expect(slot(patched[1], 0).capacity).toBe('Secretary');
    expect(slot(patched[1], 0)).not.toHaveProperty('capacity_note');
  });

  it('falls back to the slot position when the order box is emptied, never to 0', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.change(await byId('encerramento-slot-order-0'), { target: { value: '' } });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(slot(patched[0], 0).order).toBe(1);
  });

  it('clears the required flag through the toggle', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('switch', { name: termoPtPT['books.termo.signatory.required'] }),
    );
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(slot(patched[0], 0).required).toBe(false);
  });

  it('removes a signatory slot', async () => {
    const patched: PatchTermoEncerramentoBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.removeSignatory'] }),
    );
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].signatories).toEqual([]);
  });

  it('surfaces a failed save as a toast rather than a silent no-op', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (method === 'PATCH') {
        return Promise.resolve(
          jsonResponse({ code: 'forbidden', message: 'sem permissão para book.close' }, 403),
        );
      }
      if (url.endsWith('/termo/encerramento')) return Promise.resolve(jsonResponse(DRAFT_TERMO));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch);
    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    fireEvent.change(await byId('encerramento-place'), { target: { value: 'Porto' } });
    save();

    // An error toast, plus the panel's own persistent note above the actions.
    expect(await screen.findByRole('alert')).toBeTruthy();
    await waitFor(() => expect(document.querySelector('.error-note')).toBeTruthy());
  });
});

describe('TermoEncerramentoEditor load failures', () => {
  it('reports a non-404 load failure instead of rendering nothing at all', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/encerramento')) {
        return Promise.resolve(
          jsonResponse({ code: 'internal', message: 'store indisponível' }, 500),
        );
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoEncerramentoEditor bookId="book-2" />);

    const note = await waitFor(() => {
      const el = document.querySelector('.error-note');
      if (!el) throw new Error('no error note yet');
      return el;
    });
    // The 404 case renders nothing; a 500 must NOT be silently indistinguishable from it.
    expect(note.textContent).toContain('store indisponível');
  });
});
