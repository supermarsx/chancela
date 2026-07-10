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
import { ataFieldHelp } from './fieldHelp';
import { makeClient } from '../../test/utils';
import { ToastProvider } from '../../ui/toast';
import { ALLOW_ALL_PERMISSIONS, StaticPermissionsProvider } from '../session/permissions';
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
  seal_metadata: null,
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
function stateful(initial: ActView, options: { warnings?: ComplianceReport['issues'] } = {}) {
  let act = initial;
  const patches: Record<string, unknown>[] = [];
  const seals: Record<string, unknown>[] = [];
  const verifications: Record<string, unknown>[] = [];
  const warnings = options.warnings ?? [];
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
        issues: hasChair ? warnings : [mesaError, ...warnings],
        errors: hasChair ? 0 : 1,
        warnings: warnings.length,
        seal_allowed: hasChair,
      };
      return json(report);
    }
    if (url.includes('/v1/books/')) return json(book);
    if (url.includes(`/v1/acts/${act.id}/follow-ups`) && method === 'GET') return json([]);
    if (url.includes(`/v1/acts/${act.id}/seal`) && method === 'POST') {
      const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : {};
      seals.push(body);
      act = {
        ...act,
        state: 'Sealed',
        ata_number: 1,
        payload_digest: 'sha256:sealed',
        seal_event_seq: 7,
      };
      return json({
        act,
        ata_number: 1,
        event_seq: 7,
        payload_digest: 'sha256:sealed',
        acknowledged_warnings: warnings,
        document: null,
      });
    }
    if (url.includes(`/v1/acts/${act.id}/human-verification`) && method === 'POST') {
      const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : {};
      verifications.push(body);
      const status =
        body.decision === 'accept'
          ? ('accepted_by_human' as const)
          : ('rejected_by_human' as const);
      act = {
        ...act,
        ai_provenance: act.ai_provenance
          ? {
              ...act.ai_provenance,
              human_verification: {
                status,
                actor: 'api',
                reviewed_at: '2026-07-10T10:00:00Z',
                note: typeof body.note === 'string' ? body.note : null,
              },
            }
          : null,
      };
      return json(act);
    }
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
  return { fetchImpl, patches, seals, verifications };
}

function renderEditor() {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={ALLOW_ALL_PERMISSIONS}>
          <MemoryRouter initialEntries={['/atas/act-1']}>
            <Routes>
              <Route path="/atas/:id" element={<AtaEditorPage />} />
            </Routes>
          </MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AtaEditorPage — mesa presidente unblocks the seal', () => {
  it('adds inline help to top-level meeting and free-text fields', async () => {
    const shared = stateful({ ...baseAct, channel: 'Hybrid' });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    expect(await screen.findByDisplayValue('Assembleia Geral Anual')).toBeTruthy();
    expect(document.body.textContent).toContain(ataFieldHelp.title);
    expect(document.body.textContent).toContain(ataFieldHelp.channel);
    expect(document.body.textContent).toContain(ataFieldHelp.meetingDate);
    expect(document.body.textContent).toContain(ataFieldHelp.meetingTime);
    expect(document.body.textContent).toContain(ataFieldHelp.place);
    expect(document.body.textContent).toContain(ataFieldHelp.attendanceReference);
    expect(document.body.textContent).toContain(ataFieldHelp.membersPresent);
    expect(document.body.textContent).toContain(ataFieldHelp.membersRepresented);
    expect(document.body.textContent).toContain(ataFieldHelp.telematicEvidence);
    expect(document.body.textContent).toContain(ataFieldHelp.conveningDispatchDate);
    expect(document.body.textContent).toContain(ataFieldHelp.conveningChannel);
    expect(document.body.textContent).toContain(ataFieldHelp.conveningAntecedenceDays);
    expect(document.body.textContent).toContain(ataFieldHelp.conveningEvidenceReference);
    expect(document.body.textContent).toContain(ataFieldHelp.deliberationsText);
  });

  it('saves bounded convening evidence through the act patch body', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByDisplayValue('Assembleia Geral Anual');
    fireEvent.change(screen.getByLabelText('Data da convocatória'), {
      target: { value: '2026-06-01' },
    });
    fireEvent.change(screen.getByLabelText('Meio da convocatória'), {
      target: { value: 'Email' },
    });
    fireEvent.change(screen.getByLabelText('Antecedência efetiva (dias)'), {
      target: { value: '29' },
    });
    fireEvent.change(screen.getByLabelText('Prova da convocatória'), {
      target: { value: 'doc:convocatoria-2026-06-01' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      expect(shared.patches.at(-1)?.convening).toEqual({
        convener: null,
        convener_capacity: null,
        dispatch_date: '2026-06-01',
        antecedence_days: 29,
        channel: 'Email',
        evidence_reference: 'doc:convocatoria-2026-06-01',
        recipients: [],
        second_call: null,
      });
    });
  });

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

    // A success toast fires on save (t44 retrofit-a).
    expect(await screen.findByText('Ata guardada.')).toBeTruthy();

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

describe('AtaEditorPage — signatories', () => {
  it('renders and saves a signatory email through the act patch body', async () => {
    const withChair: ActView = {
      ...baseAct,
      mesa: { presidente: 'Ana', secretarios: [] },
      signatories: [{ name: 'Ana', email: 'ana@example.pt', capacity: 'Chair', signed: true }],
    };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    expect(await screen.findByDisplayValue('ana@example.pt')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'ana.legal@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const signatories = shared.patches.at(-1)?.signatories as ActView['signatories'];
      expect(signatories?.[0]).toMatchObject({
        name: 'Ana',
        email: 'ana.legal@example.pt',
        capacity: 'Chair',
        signed: true,
      });
    });
  });
});

describe('AtaEditorPage — AI human review gate', () => {
  it('records reject and accept decisions and only enables Signing after acceptance', async () => {
    const withAi: ActView = {
      ...baseAct,
      state: 'TextApproved',
      mesa: { presidente: 'Ana', secretarios: [] },
      ai_provenance: {
        source: 'mcp',
        tool: 'draft_act',
        statement_source: 'operator instruction',
        human_verification: {
          status: 'pending_human_verification',
          actor: null,
          reviewed_at: null,
          note: null,
        },
      },
    };
    const shared = stateful(withAi);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    expect(await screen.findByText('Revisão humana pendente')).toBeTruthy();
    expect(screen.getByText('mcp')).toBeTruthy();
    const advance = screen.getByRole<HTMLButtonElement>('button', {
      name: 'Avançar para «Em assinatura»',
    });
    expect(advance.disabled).toBe(true);
    expect(screen.getByText(/Aceite a revisão humana/i)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Nota de revisão'), {
      target: { value: 'needs correction' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Rejeitar revisão' }));

    await waitFor(() =>
      expect(shared.verifications.at(-1)).toEqual({
        decision: 'reject',
        note: 'needs correction',
      }),
    );
    expect(await screen.findByText('Revisão humana rejeitada')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Nota de revisão'), {
      target: { value: 'human reviewed only' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Aceitar revisão' }));

    await waitFor(() =>
      expect(shared.verifications.at(-1)).toEqual({
        decision: 'accept',
        note: 'human reviewed only',
      }),
    );
    expect(await screen.findByText('Revisão humana aceite')).toBeTruthy();
    await waitFor(() =>
      expect(
        screen.getByRole<HTMLButtonElement>('button', {
          name: 'Avançar para «Em assinatura»',
        }).disabled,
      ).toBe(false),
    );
  });
});

describe('AtaEditorPage — seal warning acknowledgement', () => {
  it('seals without sending an implicit warning acknowledgement when compliance is clean', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Selar ata' }));

    await waitFor(() => expect(shared.seals).toHaveLength(1));
    expect(shared.seals[0]).toEqual({});
    expect(shared.seals[0]).not.toHaveProperty('acknowledge_warnings');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('requires an explicit acknowledgement checkbox before sealing with compliance warnings', async () => {
    const warning = {
      rule_id: 'SIG-03/manual-signature',
      severity: 'Warning' as const,
      message: 'A ata será selada com assinatura manual.',
    };
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair, { warnings: [warning] });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Selar ata' }));

    const dialog = await screen.findByRole('dialog', {
      name: 'Confirmar avisos de conformidade',
    });
    expect(shared.seals).toHaveLength(0);
    expect(within(dialog).getByText('SIG-03/manual-signature')).toBeTruthy();
    expect(within(dialog).getByText(/assinatura manual/i)).toBeTruthy();

    const confirm = within(dialog).getByRole<HTMLButtonElement>('button', {
      name: 'Selar ata com avisos',
    });
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(shared.seals).toHaveLength(0);

    fireEvent.click(
      within(dialog).getByLabelText(/Reconheço explicitamente estes avisos de conformidade/i),
    );
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);

    await waitFor(() => expect(shared.seals).toHaveLength(1));
    expect(shared.seals[0]).toEqual({ acknowledge_warnings: true });
  });
});
