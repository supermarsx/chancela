/**
 * Structured ata-editor tests (t31): the mesa presidente clearing the blocking compliance
 * error live, the VoteResult editor round-tripping both variants through the PATCH body,
 * and agenda add/remove. Driven against a small stateful `fetch` stub that recomputes the
 * compliance report from the act's mesa (so filling the chair really flips it to clean).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { AtaEditorPage } from './AtaEditorPage';
import { makeClient } from '../../test/utils';
import type { ActView, BookView, ComplianceReport } from '../../api/types';

const baseAct: ActView = {
  id: 'act-1',
  book_id: 'book-1',
  title: 'Assembleia Geral Anual',
  channel: 'Physical',
  meeting_date: '2026-06-30',
  meeting_time: null,
  place: 'Lisboa',
  mesa: { presidente: null, secretarios: [] },
  agenda: [],
  attendance_reference: 'Lista anexa',
  members_present: null,
  members_represented: null,
  referenced_documents: [],
  deliberations: 'Aprovadas as contas.',
  deliberation_items: [],
  telematic_evidence: null,
  attachments: [],
  signatories: [{ name: 'Ana', capacity: 'Chair', signed: true }],
  state: 'Signing',
  ata_number: null,
  payload_digest: null,
  seal_event_seq: null,
  retifies: null,
};

const book: BookView = {
  id: 'book-1',
  entity_id: 'ent-1',
  kind: 'AssembleiaGeral',
  state: 'Open',
  purpose: 'Atas AG',
  numbering_scheme: 'Sequential',
  opening_date: '2026-01-01',
  closing_date: null,
  closing_reason: null,
  last_ata_number: 0,
  predecessor: null,
  required_signatories_abertura: ['Presidente'],
  required_signatories_encerramento: null,
};

const mesaError: ComplianceReport['issues'][number] = {
  rule_id: 'CSC-63/mesa-presidente',
  severity: 'Error',
  message: 'A ata tem de identificar o presidente da mesa (CSC art. 63.º).',
};

/** A `fetch` stub that persists PATCHes and derives compliance from the act's mesa chair. */
function stateful(initial: ActView) {
  let act = initial;
  const patches: Record<string, unknown>[] = [];
  const json = (body: unknown, status = 200) =>
    Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  const fetchImpl = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    if (url.includes('/compliance')) {
      const hasChair = !!act.mesa.presidente?.trim();
      const report: ComplianceReport = {
        rule_pack: 'csc-art63/v2',
        family: 'CommercialCompany',
        statute_overlay: false,
        issues: hasChair ? [] : [mesaError],
        errors: hasChair ? 0 : 1,
        warnings: 0,
        seal_allowed: hasChair,
      };
      return json(report);
    }
    if (url.includes('/v1/books/')) return json(book);
    if (/\/v1\/acts\/[^/]+$/.test(url)) {
      if (method === 'PATCH') {
        const body = JSON.parse(init!.body as string) as Record<string, unknown>;
        patches.push(body);
        act = { ...act, ...(body as Partial<ActView>) };
        return json(act);
      }
      return json(act);
    }
    return Promise.reject(new Error(`no stub for ${method} ${url}`));
  }) as typeof fetch;
  return { fetchImpl, patches };
}

function renderEditor() {
  return render(
    <QueryClientProvider client={makeClient()}>
      <MemoryRouter initialEntries={['/atas/act-1']}>
        <Routes>
          <Route path="/atas/:id" element={<AtaEditorPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AtaEditorPage — mesa presidente unblocks the seal', () => {
  it('clears the mesa-presidente compliance error once the chair is filled and saved', async () => {
    const shared = stateful(baseAct);
    vi.stubGlobal('fetch', shared.fetchImpl);

    renderEditor();

    // The blocking error is shown while the chair is empty.
    expect(await screen.findByText(/tem de identificar o presidente/i)).toBeTruthy();
    await waitFor(() => expect(screen.getByText(/1 erro/i)).toBeTruthy());

    // Fill the presidente and save.
    fireEvent.change(screen.getByLabelText('Presidente da mesa'), {
      target: { value: 'Ana Presidente' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    // Compliance refetches and goes clean.
    await waitFor(() => expect(screen.getByText('Conforme', { exact: true })).toBeTruthy());
    expect(screen.queryByText(/1 erro/i)).toBeNull();
    expect(shared.patches.at(-1)?.mesa).toEqual({
      presidente: 'Ana Presidente',
      secretarios: [],
    });
  });
});

describe('AtaEditorPage — VoteResult editor round-trips both variants', () => {
  it('saves a Recorded vote with its tallied counts', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Adicionar deliberação' }));
    fireEvent.change(screen.getByLabelText('Texto da deliberação'), {
      target: { value: 'Aprovado o relatório.' },
    });
    fireEvent.change(screen.getByLabelText('Resultado da votação'), {
      target: { value: 'Recorded' },
    });
    fireEvent.change(screen.getByLabelText('A favor'), { target: { value: '8' } });
    fireEvent.change(screen.getByLabelText('Contra'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Abstenções'), { target: { value: '1' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const items = shared.patches.at(-1)?.deliberation_items as ActView['deliberation_items'];
      expect(items?.[0].vote).toEqual({
        type: 'Recorded',
        em_favor: 8,
        contra: 2,
        abstencoes: 1,
      });
    });
  });

  it('saves a Unanimous vote', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Adicionar deliberação' }));
    fireEvent.change(screen.getByLabelText('Resultado da votação'), {
      target: { value: 'Unanimous' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const items = shared.patches.at(-1)?.deliberation_items as ActView['deliberation_items'];
      expect(items?.[0].vote).toEqual({ type: 'Unanimous' });
    });
    // No count fields when unanimous.
    expect(screen.queryByLabelText('A favor')).toBeNull();
  });
});

describe('AtaEditorPage — agenda add/remove', () => {
  it('adds a numbered agenda item and removes it', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Adicionar ponto' }));
    const item = screen.getByLabelText('Ponto da ordem de trabalhos');
    fireEvent.change(item, { target: { value: 'Aprovação de contas' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(shared.patches.at(-1)?.agenda).toEqual([{ number: 1, text: 'Aprovação de contas' }]),
    );

    // Remove the item (scoped to its row so the signatory "Remover" is not hit).
    const row = screen.getByLabelText('Ponto da ordem de trabalhos').closest('.rowline')!;
    fireEvent.click(within(row as HTMLElement).getByRole('button', { name: 'Remover' }));
    expect(screen.queryByLabelText('Ponto da ordem de trabalhos')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));
    await waitFor(() => expect(shared.patches.at(-1)?.agenda).toEqual([]));
  });
});
