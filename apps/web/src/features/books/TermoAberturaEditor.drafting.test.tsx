/**
 * TermoAberturaEditor — the drafting surface, the artifact downloads and the load-failure states.
 *
 * The existing `TermoAberturaEditor.test.tsx` covers the phase transitions (draft → freeze →
 * collect → open) and the sede. This file covers what the operator actually TYPES into a legal
 * instrument and what the panel does when a download or the load itself fails, because that is
 * where a silent drop matters most: the termo de abertura declares the book's page capacity, its
 * number and who signs it, and a field that never reaches the PATCH body is a false record.
 *
 * Everything is asserted against the PATCH payload and against stable ids/roles. The one place a
 * rendered sentence is compared, it is compared to the entry in `termoStrings` — the key, resolved
 * — never to a pt-PT literal copied into the test.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { TermoAberturaEditor } from './TermoAberturaEditor';
import { termoPtPT } from './termoStrings';
import type { TermoInstrumentView, PatchTermoAberturaBody } from '../../api/types';

const saveBlobAs = vi.hoisted(() => vi.fn());
vi.mock('../../desktop/saveFile', () => ({
  saveBlobAs,
  saveBlobResultMessage: () => 'saved',
}));

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
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

/**
 * Stub the whole panel's reads. `/termo/abertura` answers `termo`; the book and its entity answer
 * with a resolved (empty) sede so the draft form is not left in its "still loading" state.
 */
function stubReads(termo: TermoInstrumentView, patched: PatchTermoAberturaBody[]) {
  vi.stubGlobal('fetch', ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (method === 'PATCH' && url.endsWith('/termo/abertura')) {
      patched.push(JSON.parse(String(init?.body)) as PatchTermoAberturaBody);
      return Promise.resolve(jsonResponse(termo));
    }
    if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(termo));
    if (/\/v1\/books\/book-2$/.test(url)) {
      return Promise.resolve(jsonResponse({ id: 'book-2', entity_id: 'ent-1', state: 'Created' }));
    }
    if (/\/v1\/entities\/ent-1$/.test(url)) {
      return Promise.resolve(jsonResponse({ id: 'ent-1', name: 'Encosto Estratégico Lda' }));
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch);
}

/** The nth signatory of a captured PATCH body, asserted to exist rather than index-and-hope. */
function slot(body: PatchTermoAberturaBody, index: number) {
  const entry = body.signatories?.[index];
  if (!entry) throw new Error(`the PATCH body carries no signatory at ${index}`);
  return entry;
}

function save() {
  fireEvent.click(screen.getByRole('button', { name: termoPtPT['books.termo.editor.save'] }));
}

/** The element with this id once it exists. Throws (rather than resolving `null`) so `waitFor` retries. */
async function byId(id: string): Promise<HTMLElement> {
  return waitFor(() => {
    const el = document.getElementById(id);
    if (!el) throw new Error(`no #${id} yet`);
    return el;
  });
}

afterEach(() => {
  cleanup();
  saveBlobAs.mockReset();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('TermoAberturaEditor draft fields', () => {
  it('carries every edited assurance field into the PATCH body', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.change(await byId('termo-title'), { target: { value: 'Termo do Livro 3' } });
    fireEvent.change(await byId('termo-purpose'), { target: { value: 'Atas da direção' } });
    fireEvent.change(await byId('termo-date'), { target: { value: '2026-03-15' } });
    fireEvent.change(await byId('termo-pages'), { target: { value: '250' } });
    fireEvent.change(await byId('termo-number'), { target: { value: '3' } });
    fireEvent.change(await byId('termo-place'), { target: { value: 'Braga' } });
    fireEvent.change(await byId('termo-predecessor-note'), {
      target: { value: 'Sucede ao n.º 2' },
    });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0]).toMatchObject({
      title: 'Termo do Livro 3',
      purpose: 'Atas da direção',
      opening_date: '2026-03-15',
      // The numeric boxes are strings in the DOM and MUST reach the server as numbers: the page
      // capacity is what the termo de encerramento is later checked against.
      page_capacity: 250,
      book_number: 3,
      place: 'Braga',
      predecessor_note: 'Sucede ao n.º 2',
    });
  });

  it('omits blanked optional fields, but still sends an emptied sede as ""', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(
      { ...DRAFT_TERMO, fields: { ...DRAFT_TERMO.fields, entity_seat: 'Rua A, 1000 Lisboa' } },
      patched,
    );
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    const seat = (await screen.findByDisplayValue('Rua A, 1000 Lisboa')) as HTMLInputElement;
    fireEvent.change(seat, { target: { value: '   ' } });
    fireEvent.change(document.getElementById('termo-purpose')!, { target: { value: '   ' } });
    fireEvent.change(document.getElementById('termo-pages')!, { target: { value: '' } });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    // Omitting a key leaves the stored value alone; '' is the only way to say "clear it".
    expect(patched[0].entity_seat).toBe('');
    expect(patched[0].purpose).toBeUndefined();
    expect(patched[0].page_capacity).toBeUndefined();
  });

  it('adds a body clause and sends its heading and text', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.addClause'] }),
    );
    fireEvent.change(document.getElementById('termo-clause-heading-1')!, {
      target: { value: 'Cláusula segunda' },
    });
    fireEvent.change(document.getElementById('termo-clause-text-1')!, {
      target: { value: 'O livro tem 250 páginas.' },
    });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].body).toEqual([
      { heading: undefined, text: 'Aos … dias …' },
      { heading: 'Cláusula segunda', text: 'O livro tem 250 páginas.' },
    ]);
  });

  it('removes the clause the operator asked to remove, and only that one', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(
      {
        ...DRAFT_TERMO,
        body: [
          { id: 'c1', text: 'primeira', origin: 'TemplateDefault' },
          { id: 'c2', text: 'segunda', origin: 'TemplateDefault' },
        ],
      },
      patched,
    );
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    const removes = await screen.findAllByRole('button', {
      name: termoPtPT['books.termo.editor.removeClause'],
    });
    fireEvent.click(removes[0]);
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].body).toEqual([{ heading: undefined, text: 'segunda' }]);
  });

  it('adds a signatory slot with a sequential order and the required flag set', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.addSignatory'] }),
    );
    fireEvent.change(document.getElementById('termo-slot-name-1')!, {
      target: { value: 'Rui Bastos' },
    });
    fireEvent.change(document.getElementById('termo-slot-email-1')!, {
      target: { value: ' rui@exemplo.pt ' },
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

  it('sends a capacity note only while the capacity is «Other»', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    const capacity = (await byId('termo-slot-capacity-0')) as HTMLSelectElement;
    fireEvent.change(capacity, { target: { value: 'Other' } });
    const note = document.getElementById('termo-slot-note-0') as HTMLInputElement;
    expect(note).toBeTruthy();
    fireEvent.change(note, { target: { value: 'Procurador' } });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(slot(patched[0], 0)).toMatchObject({
      capacity: 'Other',
      capacity_note: 'Procurador',
    });

    // Switching back hides the box AND drops the note: a stale note under a named capacity would
    // describe the signatory as something they are not.
    fireEvent.change(capacity, { target: { value: 'Manager' } });
    expect(document.getElementById('termo-slot-note-0')).toBeNull();
    save();
    await waitFor(() => expect(patched).toHaveLength(2));
    expect(slot(patched[1], 0).capacity).toBe('Manager');
    // Absent on the wire, not merely empty.
    expect(slot(patched[1], 0)).not.toHaveProperty('capacity_note');
  });

  it('falls back to the slot position when its order box is emptied', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.change(await byId('termo-slot-order-0'), { target: { value: '' } });
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    // Never 0 — an order of zero would sort ahead of every real slot.
    expect(slot(patched[0], 0).order).toBe(1);
  });

  it('clears the required flag through the toggle', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('switch', { name: termoPtPT['books.termo.signatory.required'] }),
    );
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(slot(patched[0], 0).required).toBe(false);
  });

  it('removes a signatory slot', async () => {
    const patched: PatchTermoAberturaBody[] = [];
    stubReads(DRAFT_TERMO, patched);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', { name: termoPtPT['books.termo.editor.removeSignatory'] }),
    );
    save();

    await waitFor(() => expect(patched).toHaveLength(1));
    expect(patched[0].signatories).toEqual([]);
  });
});

describe('TermoAberturaEditor artifact downloads', () => {
  const SEALED: TermoInstrumentView = {
    ...DRAFT_TERMO,
    state: 'Sealed',
    signatories: [{ ...DRAFT_TERMO.signatories[0], signed: true, pades_document_available: true }],
  };

  function stubSealed(documentStatus = 200) {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/termo/abertura/signatures/')) {
        return Promise.resolve(
          documentStatus === 200
            ? new Response(new Blob(['%PDF-signed']), { status: 200 })
            : jsonResponse({ code: 'not_found', message: 'x' }, documentStatus),
        );
      }
      if (url.endsWith('/termo/abertura/document')) {
        return Promise.resolve(
          documentStatus === 200
            ? new Response(new Blob(['%PDF-base']), { status: 200 })
            : jsonResponse({ code: 'not_found', message: 'x' }, documentStatus),
        );
      }
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(SEALED));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);
  }

  it('names the base artifact as unsigned, so it cannot be mistaken for the signed one', async () => {
    stubSealed();
    saveBlobAs.mockResolvedValue({ kind: 'download' });
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', {
        name: termoPtPT['books.termo.document.downloadUnsignedBase'],
      }),
    );

    await waitFor(() => expect(saveBlobAs).toHaveBeenCalledTimes(1));
    expect(saveBlobAs.mock.calls[0][0]).toMatchObject({
      filename: 'termo-de-abertura-book-2-base-sem-assinaturas.pdf',
      contentType: 'application/pdf',
    });
  });

  it('downloads one independently verifiable PAdES revision per signed slot', async () => {
    stubSealed();
    saveBlobAs.mockResolvedValue({ kind: 'download' });
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: /Amélia Marques$/ }));

    await waitFor(() => expect(saveBlobAs).toHaveBeenCalledTimes(1));
    // Keyed by SLOT — never one merged "final" file, which no client can produce without
    // invalidating the per-slot signatures.
    expect(saveBlobAs.mock.calls[0][0]).toMatchObject({
      filename: 'termo-de-abertura-assinado-s1.pdf',
    });
  });

  it('surfaces a failed base download as a toast instead of a silent no-op', async () => {
    stubSealed(500);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', {
        name: termoPtPT['books.termo.document.downloadUnsignedBase'],
      }),
    );

    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(saveBlobAs).not.toHaveBeenCalled();
  });

  it('surfaces a failed WRITE of the downloaded bytes, not only a failed fetch', async () => {
    stubSealed();
    saveBlobAs.mockRejectedValue(new Error('disk full'));
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(
      await screen.findByRole('button', {
        name: termoPtPT['books.termo.document.downloadUnsignedBase'],
      }),
    );

    expect(await screen.findByRole('alert')).toBeTruthy();
  });

  it('surfaces a failed WRITE of a signed slot revision too', async () => {
    stubSealed();
    saveBlobAs.mockRejectedValue(new Error('disk full'));
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: /Amélia Marques$/ }));

    expect(await screen.findByRole('alert')).toBeTruthy();
  });

  it('surfaces a failed signed-slot download', async () => {
    stubSealed(404);
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    fireEvent.click(await screen.findByRole('button', { name: /Amélia Marques$/ }));

    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(saveBlobAs).not.toHaveBeenCalled();
  });
});

describe('TermoAberturaEditor completion policies', () => {
  function stubSigning(termo: TermoInstrumentView) {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/abertura')) return Promise.resolve(jsonResponse(termo));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);
  }

  const SIGNING: TermoInstrumentView = { ...DRAFT_TERMO, state: 'Signing' };

  it('renders a SingleQualifying policy as its own assurance sentence', async () => {
    stubSigning({ ...SIGNING, completion_policy: 'SingleQualifying' });
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    const table = await screen.findByRole('list', {
      name: termoPtPT['books.termo.editor.signatoriesLegend'],
    });
    expect(table).toBeTruthy();
    expect(document.querySelector('.termo-status-table')?.textContent).toContain(
      termoPtPT['books.termo.policy.SingleQualifying'],
    );
  });

  it('renders an AtLeast policy with the threshold the server declared', async () => {
    stubSigning({ ...SIGNING, completion_policy: { AtLeast: 2 } });
    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    await waitFor(() => expect(document.querySelector('.termo-status-table')).toBeTruthy());
    const rows = document.querySelector('.termo-status-table') as HTMLElement;
    // The threshold is a fact from the server, so it must appear — a policy line that dropped the
    // number would understate what the termo requires.
    expect(within(rows).getByText(/2/)).toBeTruthy();
  });
});

describe('TermoAberturaEditor load failures', () => {
  it('reports a non-404 load failure instead of claiming the book has no termo', async () => {
    vi.stubGlobal('fetch', ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.endsWith('/termo/abertura')) {
        return Promise.resolve(jsonResponse({ code: 'forbidden', message: 'sem permissão' }, 403));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch);

    renderWithProviders(<TermoAberturaEditor bookId="book-2" />);

    const note = await waitFor(() => {
      const el = document.querySelector('.error-note');
      if (!el) throw new Error('no error note yet');
      return el;
    });
    expect(note.textContent).toContain('sem permissão');
    // The 404 "one-shot book" copy asserts something specific and false about this book.
    expect(screen.queryByText(termoPtPT['books.termo.none'])).toBeNull();
  });
});
