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
import { AtaEditorPage, actDocumentPanelTargetFromLocation } from './AtaEditorPage';
import {
  buildAiProvenanceReviewPacket,
  formatAiProvenanceReviewPacket,
} from './aiProvenanceReviewPacket';
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
function stateful(
  initial: ActView,
  options: {
    warnings?: ComplianceReport['issues'];
    writtenResolutionStatus?: ComplianceReport['written_resolution_evidence_status'];
  } = {},
) {
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
        written_resolution_evidence_status: options.writtenResolutionStatus,
      };
      return json(report);
    }
    if (url.includes('/v1/books/')) return json(book);
    if (url.includes(`/v1/acts/${act.id}/follow-ups`) && method === 'GET') return json([]);
    if (url.includes(`/v1/acts/${act.id}/seal`) && method === 'POST') {
      const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : {};
      seals.push(body);
      const manualReference = body.manual_signature_original_reference as
        NonNullable<ActView['seal_metadata']>['manual_signature_original_reference'] | undefined;
      act = {
        ...act,
        state: 'Sealed',
        ata_number: 1,
        payload_digest: 'sha256:sealed',
        seal_event_seq: 7,
        seal_metadata: {
          rule_pack_id: 'csc-art63/v2',
          version: 'v2',
          family: 'CommercialCompany',
          profile: 'SociedadeAnonima',
          ...(manualReference ? { manual_signature_original_reference: manualReference } : {}),
        },
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
  it('parses generated document dispatch-evidence deep links for the document panel', () => {
    expect(
      actDocumentPanelTargetFromLocation(
        '?generated_document_id=generated-absent-1&focus=dispatch-evidence',
        '#generated-dispatch-evidence',
      ),
    ).toEqual({
      generatedDocumentId: 'generated-absent-1',
      focus: 'dispatch-evidence',
    });
  });

  it('parses imported-document review deep links for the document panel', () => {
    expect(
      actDocumentPanelTargetFromLocation(
        '?imported_document_id=import-1&focus=import-review',
        '#imported-documents',
      ),
    ).toEqual({
      importedDocumentId: 'import-1',
      focus: 'import-review',
    });
  });

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
  type AiProvenance = NonNullable<ActView['ai_provenance']>;
  type AiStatementSources = NonNullable<AiProvenance['statement_sources']>;

  const aiReviewStatementSources: AiStatementSources = [
    {
      path: '/draft',
      source_type: 'ai_suggestion',
      source_label: 'draft_act',
      human_verified: false,
      human_verification_status: 'pending_human_verification',
      authoritative_source_claimed: false,
      legal_validity_claimed: false,
    },
    {
      path: '/draft/title',
      source_type: 'caller_supplied',
      source_label: 'arguments.title',
      human_verified: false,
      human_verification_status: 'pending_human_verification',
      authoritative_source_claimed: false,
      legal_validity_claimed: false,
    },
    {
      path: '/draft/body',
      source_type: 'ai_suggestion',
      source_label: 'draft_act.body',
      human_verified: false,
      human_verification_status: 'pending_human_verification',
      authoritative_source_claimed: false,
      legal_validity_claimed: false,
    },
  ];

  function actWithAiReview(statementSources: AiStatementSources | null): ActView {
    const ai_provenance: AiProvenance = {
      source: 'mcp',
      tool: 'draft_act',
      statement_source: 'operator instruction',
      human_verification: {
        status: 'pending_human_verification',
        actor: null,
        reviewed_at: null,
        note: null,
      },
    };
    if (statementSources !== null) ai_provenance.statement_sources = statementSources;
    return {
      ...baseAct,
      state: 'TextApproved',
      mesa: { presidente: 'Ana', secretarios: [] },
      ai_provenance,
    };
  }

  it('builds a deterministic review packet without raw sensitive review fields', () => {
    const sensitiveSources = [
      {
        path: '/draft',
        source_type: 'ai_suggestion',
        source_label: 'SECRET_DRAFT_BODY',
        human_verified: false,
        human_verification_status: 'pending_human_verification',
        authoritative_source_claimed: false,
        legal_validity_claimed: false,
      },
      {
        path: '/draft/title',
        source_type: 'caller_supplied',
        source_label: 'SECRET_TITLE_ARGUMENT',
        human_verified: true,
        human_verification_status: 'accepted_by_human',
        authoritative_source_claimed: true,
        legal_validity_claimed: false,
      },
      {
        path: '/draft/missing',
        source_type: null,
        source_label: 'SECRET_MISSING_LABEL',
        human_verified: true,
        human_verification_status: null,
        authoritative_source_claimed: false,
        legal_validity_claimed: false,
      },
    ] as unknown as AiStatementSources;
    const provenance: AiProvenance = {
      source: 'mcp',
      tool: 'draft_act',
      statement_source: 'SECRET_OPERATOR_INSTRUCTION',
      human_verification: {
        status: 'accepted_by_human',
        actor: 'reviewer.secret@example.pt',
        reviewed_at: '2026-07-14T10:00:00Z',
        note: 'SECRET_REVIEW_NOTE',
      },
      statement_sources: sensitiveSources,
    };

    const packet = buildAiProvenanceReviewPacket(provenance);

    expect(packet).toEqual({
      schema_version: 'ai-provenance-review-packet/v1',
      generated_from: 'act.ai_provenance',
      source: 'mcp',
      tool: 'draft_act',
      statement_source_present: true,
      human_review: {
        status: 'accepted_by_human',
        actor_present: true,
        reviewed_at_present: true,
        note_present: true,
      },
      statement_sources: {
        total: 3,
        counts_by_source_type: {
          ai_suggestion: 1,
          caller_supplied: 1,
          missing: 1,
        },
        counts_by_review_status: {
          accepted_by_human: 1,
          missing: 1,
          pending_human_verification: 1,
        },
        missing: {
          row_count: 1,
          rows: [{ index: 2, path: '/draft/missing' }],
        },
        pending_or_unverified_row_count: 2,
        claim_flagged_row_count: 1,
      },
      no_claim_flags: {
        legal_validity: false,
        source_certification: false,
        provider_assurance: false,
        trust_validation: false,
        external_validation: false,
        signature_qualification: false,
        mcp_completion: false,
        ai_quality: false,
      },
    });
    expect(Object.values(packet.no_claim_flags).every((value) => value === false)).toBe(true);

    const serialized = formatAiProvenanceReviewPacket(provenance);
    expect(serialized).toBe(`${JSON.stringify(packet, null, 2)}\n`);
    expect(serialized).not.toContain('SECRET_DRAFT_BODY');
    expect(serialized).not.toContain('SECRET_TITLE_ARGUMENT');
    expect(serialized).not.toContain('SECRET_MISSING_LABEL');
    expect(serialized).not.toContain('SECRET_OPERATOR_INSTRUCTION');
    expect(serialized).not.toContain('reviewer.secret@example.pt');
    expect(serialized).not.toContain('SECRET_REVIEW_NOTE');
  });

  it('renders grouped provenance summary by source_type', async () => {
    const shared = stateful(actWithAiReview(aiReviewStatementSources));
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    const summary = await screen.findByLabelText('Resumo por tipo de origem');
    const aiSuggestion = within(summary).getByText('ai_suggestion').closest('div')!;
    const callerSupplied = within(summary).getByText('caller_supplied').closest('div')!;
    expect(within(aiSuggestion as HTMLElement).getByText('2')).toBeTruthy();
    expect(within(callerSupplied as HTMLElement).getByText('1')).toBeTruthy();
  });

  it('renders deterministic local review status and no-claim boundaries', async () => {
    const shared = stateful(actWithAiReview(aiReviewStatementSources));
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    const localSummary = await screen.findByLabelText('Resumo da revisão local');
    const totalRows = within(localSummary).getByText('Linhas de proveniência').closest('div')!;
    const pendingRows = within(localSummary).getByText('Linhas pendentes/incertas').closest('div')!;
    const missingRows = within(localSummary)
      .getByText('Linhas com campos de proveniência em falta')
      .closest('div')!;
    const flaggedRows = within(localSummary)
      .getByText('Linhas com alegações assinaladas')
      .closest('div')!;
    expect(within(totalRows as HTMLElement).getByText('3')).toBeTruthy();
    expect(within(pendingRows as HTMLElement).getByText('3')).toBeTruthy();
    expect(within(missingRows as HTMLElement).getByText('0')).toBeTruthy();
    expect(within(flaggedRows as HTMLElement).getByText('0')).toBeTruthy();

    const statusSummary = screen.getByLabelText('Resumo por estado de revisão');
    const pendingStatus = within(statusSummary)
      .getByText('pending_human_verification')
      .closest('div')!;
    expect(within(pendingStatus as HTMLElement).getByText('3')).toBeTruthy();

    const pageText = document.body.textContent ?? '';
    expect(pageText).toContain('Limites da revisão local');
    expect(pageText).toContain('no bridge/API/AI-provider/hidden-provider calls; no secrets');
    expect(pageText).toContain('legal_validity: false');
    expect(pageText).toContain('source_certification: false');
    expect(pageText).toContain('provider: false');
    expect(pageText).toContain('trust: false');
    expect(pageText).toContain('external_validation: false');
    expect(pageText).toContain('signature_qualification: false');
    expect(pageText).not.toMatch(/legal validity confirmed/i);
    expect(pageText).not.toMatch(/source certified/i);
    expect(pageText).not.toMatch(/provider assurance recorded/i);
    expect(pageText).not.toMatch(/automated legal review completed/i);
  });

  it('renders statement-source rows with path type label status and conservative flags', async () => {
    const shared = stateful(actWithAiReview(aiReviewStatementSources));
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    await screen.findByRole('heading', { name: 'Proveniência das declarações' });
    const titleRow = screen.getByText('/draft/title').closest('tr')!;
    expect(within(titleRow as HTMLElement).getByText('caller_supplied')).toBeTruthy();
    expect(within(titleRow as HTMLElement).getByText('arguments.title')).toBeTruthy();
    expect(within(titleRow as HTMLElement).getByText('pending_human_verification')).toBeTruthy();
    expect(within(titleRow as HTMLElement).getByText('human_verified=false')).toBeTruthy();
    expect(
      within(titleRow as HTMLElement).getByText('authoritative_source_claimed=false/no claim'),
    ).toBeTruthy();
    expect(
      within(titleRow as HTMLElement).getByText('legal_validity_claimed=false/no claim'),
    ).toBeTruthy();
  });

  it('renders missing statement-source fields with missing labels', async () => {
    const malformedStatementSources = [
      {
        source_type: null,
        source_label: undefined,
        human_verified: false,
        human_verification_status: null,
        authoritative_source_claimed: false,
        legal_validity_claimed: false,
      },
    ] as unknown as AiStatementSources;
    const shared = stateful(actWithAiReview(malformedStatementSources));
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    const summary = await screen.findByLabelText('Resumo por tipo de origem');
    const missingSummary = within(summary).getByText('Não indicado').closest('div')!;
    expect(within(missingSummary as HTMLElement).getByText('1')).toBeTruthy();

    const localSummary = screen.getByLabelText('Resumo da revisão local');
    const pendingRows = within(localSummary).getByText('Linhas pendentes/incertas').closest('div')!;
    const missingRows = within(localSummary)
      .getByText('Linhas com campos de proveniência em falta')
      .closest('div')!;
    expect(within(pendingRows as HTMLElement).getByText('1')).toBeTruthy();
    expect(within(missingRows as HTMLElement).getByText('1')).toBeTruthy();

    const heading = screen.getByRole('heading', { name: 'Proveniência das declarações' });
    const provenanceSection = heading.closest('section')!;
    const row = within(provenanceSection as HTMLElement)
      .getByText('human_verified=false')
      .closest('tr')!;
    expect(within(row as HTMLElement).getAllByText('Não indicado').length).toBe(4);
  });

  it('keeps missing and empty statement_sources safe', async () => {
    const emptySources: AiStatementSources = [];
    for (const statementSources of [null, emptySources]) {
      cleanup();
      const shared = stateful(actWithAiReview(statementSources));
      vi.stubGlobal('fetch', shared.fetchImpl);
      renderEditor();

      expect(await screen.findByText('Sem fontes de declaração registadas.')).toBeTruthy();
    }
  });

  it('copies the deterministic review packet as stable pretty JSON', async () => {
    const withAi = actWithAiReview(aiReviewStatementSources);
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });
    const shared = stateful(withAi);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Copiar pacote de revisão' }));

    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith(
        formatAiProvenanceReviewPacket(withAi.ai_provenance!),
      ),
    );
  });

  it('records reject and accept decisions and only enables Signing after acceptance', async () => {
    const withAi = actWithAiReview(aiReviewStatementSources);
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

describe('AtaEditorPage — written-resolution evidence review', () => {
  const falseWrittenResolutionReceiptFlags = {
    consent_proof_claimed: false,
    quorum_proof_claimed: false,
    identity_proof_claimed: false,
    legal_acceptance_claimed: false,
    legal_sufficiency_claimed: false,
    external_validation_claimed: false,
    automatic_approval_claimed: false,
    authority_certified_claimed: false,
  } as const;

  it('renders local review receipt depth from compliance without proof wording', async () => {
    const { fetchImpl } = stateful(
      {
        ...baseAct,
        channel: 'WrittenResolution',
        mesa: { presidente: 'Ana', secretarios: [] },
      },
      {
        writtenResolutionStatus: {
          status: 'bound_present',
          boundary: 'workflow_evidence_status_only',
          signed_signatory_slots: 1,
          digested_attachments: 0,
          checklist_items: 1,
          digested_checklist_items: 1,
          referenced_checklist_items: 0,
          bound_count: 2,
          referenced_only_count: 0,
          review_receipts: 1,
          latest_review_status: 'reviewed',
          reviewed_evidence_locators: 1,
          reviewed_evidence_digests: 1,
        },
      },
    );
    vi.stubGlobal('fetch', fetchImpl);

    renderEditor();

    expect(
      await screen.findByLabelText('Revisão local da evidência da deliberação por escrito'),
    ).toBeTruthy();
    expect(screen.getByText('Comprovativo registado')).toBeTruthy();
    expect(
      screen.getByText(/Não se afirma consentimento, quórum, identidade, suficiência jurídica/i),
    ).toBeTruthy();
    expect(screen.queryByText(/legal acceptance/i)).toBeNull();
    expect(screen.queryByText(/automatic approval is granted/i)).toBeNull();
  });

  it('appends local receipt metadata through the existing patch contract without overclaiming', async () => {
    const existingReceipt: NonNullable<
      NonNullable<ActView['written_resolution_evidence']>['review_receipts']
    >[number] = {
      reviewer: 'existing.operator@example.pt',
      reviewed_at: '2026-07-12T09:00:00Z',
      status: 'needs_follow_up',
      guardrail_acknowledgements: ['local_metadata_only'],
      evidence: [
        {
          label: 'Existing written approvals folder',
          locator: 'folder:written-approvals',
          digest: null,
        },
      ],
      note: 'Existing receipt remains in the history.',
      ...falseWrittenResolutionReceiptFlags,
    };
    const shared = stateful({
      ...baseAct,
      channel: 'WrittenResolution',
      mesa: { presidente: 'Ana', secretarios: [] },
      written_resolution_evidence: {
        status: {
          status: 'referenced_only',
          boundary: 'workflow_evidence_status_only',
          signed_signatory_slots: 0,
          digested_attachments: 0,
          checklist_items: 1,
          digested_checklist_items: 0,
          referenced_checklist_items: 1,
          bound_count: 0,
          referenced_only_count: 1,
          review_receipts: 1,
          latest_review_status: 'needs_follow_up',
          reviewed_evidence_locators: 1,
          reviewed_evidence_digests: 0,
        },
        checklist: [
          {
            label: 'Approval pack',
            reference: 'doc:approval-pack',
            digest: null,
            note: 'Retained outside this editor.',
          },
        ],
        review_receipts: [existingReceipt],
        note: 'Existing evidence note.',
      },
    });
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    expect(
      await screen.findByLabelText('Histórico de comprovativos da deliberação por escrito'),
    ).toBeTruthy();
    expect(screen.getByText('existing.operator@example.pt')).toBeTruthy();
    expect(screen.getByText(/Existing receipt remains in the history/i)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Revisor'), {
      target: { value: 'operator@example.pt' },
    });
    fireEvent.change(screen.getByLabelText('Revisto em'), {
      target: { value: '2026-07-13T10:15:00Z' },
    });
    fireEvent.change(screen.getByLabelText('Etiqueta da evidência'), {
      target: { value: 'Approval pack review receipt' },
    });
    fireEvent.change(screen.getByLabelText('Referência da evidência'), {
      target: { value: 'doc:approval-pack' },
    });
    fireEvent.change(screen.getByLabelText('Notas do comprovativo'), {
      target: { value: 'Reviewed local metadata only.' },
    });
    fireEvent.click(screen.getByLabelText(/Apenas metadados locais/i));
    fireEvent.click(screen.getByRole('button', { name: 'Registar comprovativo local' }));

    await waitFor(() => expect(shared.patches).toHaveLength(1));
    const patch = shared.patches[0];
    expect(Object.keys(patch)).toEqual(['written_resolution_evidence']);
    const evidence = patch.written_resolution_evidence as Record<string, unknown>;
    expect(evidence.note).toBe('Existing evidence note.');
    expect(evidence.checklist).toEqual([
      {
        label: 'Approval pack',
        reference: 'doc:approval-pack',
        digest: null,
        note: 'Retained outside this editor.',
      },
    ]);

    const receipts = evidence.review_receipts as Record<string, unknown>[];
    expect(receipts).toHaveLength(2);
    expect(receipts[0]).toMatchObject(existingReceipt);
    expect(receipts[1]).toEqual({
      reviewer: 'operator@example.pt',
      reviewed_at: '2026-07-13T10:15:00Z',
      status: 'reviewed',
      guardrail_acknowledgements: [
        'local_metadata_only',
        'no_consent_quorum_identity_or_legal_proof',
        'no_external_validation_provider_authority_or_completion_claim',
      ],
      evidence: [
        {
          label: 'Approval pack review receipt',
          locator: 'doc:approval-pack',
          digest: null,
        },
      ],
      note: 'Reviewed local metadata only.',
      ...falseWrittenResolutionReceiptFlags,
    });
    expect(receipts[1]).toMatchObject(falseWrittenResolutionReceiptFlags);

    const pageText = document.body.textContent ?? '';
    expect(pageText).toContain('legal_sufficiency_claimed=false');
    expect(pageText).not.toMatch(/legal sufficiency confirmed/i);
    expect(pageText).not.toMatch(/legal acceptance/i);
    expect(pageText).not.toMatch(/external validation completed/i);
    expect(pageText).not.toMatch(/authority certified/i);
  });
});

describe('AtaEditorPage — manual seal acknowledgement', () => {
  it('requires a manual original reference before sealing when compliance is clean', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Selar ata' }));

    const dialog = await screen.findByRole('dialog', {
      name: 'Confirmar selagem manual',
    });
    expect(shared.seals).toHaveLength(0);
    const confirm = within(dialog).getByRole<HTMLButtonElement>('button', {
      name: 'Confirmar e selar ata',
    });
    expect(confirm.disabled).toBe(true);
    expect(
      within(dialog).getByText(/não validam a assinatura nem certificam o arquivo/i),
    ).toBeTruthy();
    expect(dialog.textContent ?? '').not.toMatch(/revi os avisos de conformidade/i);

    fireEvent.change(within(dialog).getByLabelText(/^Referência do original assinado$/i), {
      target: { value: 'Arquivo A / Pasta 2026 / Ata 1' },
    });
    fireEvent.change(within(dialog).getByLabelText(/Custodiante/i), {
      target: { value: 'Secretariado' },
    });
    fireEvent.change(within(dialog).getByLabelText(/Nota/i), {
      target: { value: 'Original em papel; referência local apenas.' },
    });
    fireEvent.click(
      within(dialog).getByLabelText(/referência do original assinado manualmente foi registada/i),
    );
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);

    await waitFor(() => expect(shared.seals).toHaveLength(1));
    expect(shared.seals[0]).toEqual({
      manual_signature_original_reference: {
        storage_reference: 'Arquivo A / Pasta 2026 / Ata 1',
        custodian: 'Secretariado',
        note: 'Original em papel; referência local apenas.',
      },
    });
    expect(shared.seals[0]).not.toHaveProperty('acknowledge_warnings');
    expect(JSON.stringify(shared.seals[0])).not.toMatch(
      /legal_validity_claimed|qualified_signature_claimed|archive_certification_claimed|manual_signature_verified/,
    );
    await screen.findByText('Arquivo A / Pasta 2026 / Ata 1');
    expect(screen.getByText('Secretariado')).toBeTruthy();
  });

  it('requires manual original reference and explicit checkbox before sealing with warnings', async () => {
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
      name: 'Confirmar selagem manual',
    });
    expect(shared.seals).toHaveLength(0);
    expect(within(dialog).getByText('SIG-03/manual-signature')).toBeTruthy();
    expect(within(dialog).getByText(/assinatura manual/i)).toBeTruthy();
    expect(
      within(dialog).getByText(/não validam a assinatura nem certificam o arquivo/i),
    ).toBeTruthy();

    const confirm = within(dialog).getByRole<HTMLButtonElement>('button', {
      name: 'Confirmar e selar ata',
    });
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(shared.seals).toHaveLength(0);

    fireEvent.change(within(dialog).getByLabelText(/^Referência do original assinado$/i), {
      target: { value: 'Cofre documental 2 / Ata AG 2026' },
    });
    expect(confirm.disabled).toBe(true);

    fireEvent.click(
      within(dialog).getByLabelText(
        /revi os avisos de conformidade.*referência do original assinado manualmente foi registada/i,
      ),
    );
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);

    await waitFor(() => expect(shared.seals).toHaveLength(1));
    expect(shared.seals[0]).toEqual({
      acknowledge_warnings: true,
      manual_signature_original_reference: {
        storage_reference: 'Cofre documental 2 / Ata AG 2026',
      },
    });
  });

  it('blocks manual original references containing control characters before submit', async () => {
    const withChair = { ...baseAct, mesa: { presidente: 'Ana', secretarios: [] } };
    const shared = stateful(withChair);
    vi.stubGlobal('fetch', shared.fetchImpl);
    renderEditor();

    fireEvent.click(await screen.findByRole('button', { name: 'Selar ata' }));

    const dialog = await screen.findByRole('dialog', {
      name: 'Confirmar selagem manual',
    });
    const confirm = within(dialog).getByRole<HTMLButtonElement>('button', {
      name: 'Confirmar e selar ata',
    });
    const reference = within(dialog).getByLabelText(/^Referência do original assinado$/i);

    fireEvent.change(reference, {
      target: { value: 'Arquivo A\u0007Pasta 2026' },
    });
    fireEvent.click(
      within(dialog).getByLabelText(/referência do original assinado manualmente foi registada/i),
    );

    expect(within(dialog).getByRole('alert').textContent).toMatch(/caracteres de controlo/i);
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    expect(shared.seals).toHaveLength(0);

    fireEvent.change(reference, {
      target: { value: 'Arquivo A / Pasta 2026' },
    });
    expect(within(dialog).queryByRole('alert')).toBeNull();
    expect(confirm.disabled).toBe(false);
  });
});
