import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type {
  BreachPlaybookView,
  DpiaRecordView,
  DpiaTemplateView,
  PrivacyAdvisoryReviewSummary,
  ProcessorRecordView,
  RetentionPolicyView,
  TransferControlView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { PrivacyComplianceSection } from './PrivacyComplianceSection';

const hooks = vi.hoisted(() => {
  const query = () => ({ data: [] as unknown[], isLoading: false, error: null as unknown });
  const mutation = () => ({ mutateAsync: vi.fn(), isPending: false, data: null as unknown });
  return {
    processors: query(),
    dpiaTemplate: { data: null as unknown, isLoading: false, error: null as unknown },
    dpias: query(),
    breaches: query(),
    transfers: query(),
    retentionPolicies: query(),
    dueCandidates: { data: null as unknown, isLoading: false, error: null as unknown },
    candidateResolutions: query(),
    executions: query(),
    createProcessor: mutation(),
    patchProcessor: mutation(),
    createDpia: mutation(),
    patchDpia: mutation(),
    createBreach: mutation(),
    patchBreach: mutation(),
    createTransfer: mutation(),
    patchTransfer: mutation(),
    createRetention: mutation(),
    patchRetention: mutation(),
    dryRun: mutation(),
    recordResolution: mutation(),
    closeReview: mutation(),
    executionHook: vi.fn(),
  };
});

vi.mock('../../api/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/hooks')>();
  return {
    ...actual,
    usePrivacyProcessors: () => hooks.processors,
    usePrivacyDpiaTemplate: () => hooks.dpiaTemplate,
    usePrivacyDpias: () => hooks.dpias,
    usePrivacyBreachPlaybooks: () => hooks.breaches,
    usePrivacyTransferControls: () => hooks.transfers,
    usePrivacyRetentionPolicies: () => hooks.retentionPolicies,
    usePrivacyRetentionDueCandidates: () => hooks.dueCandidates,
    usePrivacyRetentionCandidateResolutions: () => hooks.candidateResolutions,
    usePrivacyRetentionExecutions: (status: string, enabled: boolean) => {
      hooks.executionHook(status, enabled);
      return hooks.executions;
    },
    useCreatePrivacyProcessor: () => hooks.createProcessor,
    usePatchPrivacyProcessor: () => hooks.patchProcessor,
    useCreatePrivacyDpia: () => hooks.createDpia,
    usePatchPrivacyDpia: () => hooks.patchDpia,
    useCreatePrivacyBreachPlaybook: () => hooks.createBreach,
    usePatchPrivacyBreachPlaybook: () => hooks.patchBreach,
    useCreatePrivacyTransferControl: () => hooks.createTransfer,
    usePatchPrivacyTransferControl: () => hooks.patchTransfer,
    useCreatePrivacyRetentionPolicy: () => hooks.createRetention,
    usePatchPrivacyRetentionPolicy: () => hooks.patchRetention,
    useDryRunPrivacyRetentionPolicy: () => hooks.dryRun,
    useRecordPrivacyRetentionCandidateResolution: () => hooks.recordResolution,
    useClosePrivacyRetentionExecutionReview: () => hooks.closeReview,
  };
});

const advisory = (
  overrides: Partial<PrivacyAdvisoryReviewSummary> = {},
): PrivacyAdvisoryReviewSummary => ({
  status: 'current',
  last_reviewed_at: '2026-07-01T10:00:00Z',
  next_review_due_at: '2027-07-01',
  days_until_due: 350,
  review_interval_days: 365,
  receipt_count: 1,
  review_receipt_count: 1,
  drill_receipt_count: 0,
  local_advisory_only: true,
  authority_notification_claimed: false,
  subject_notification_claimed: false,
  transfer_approval_claimed: false,
  transfer_execution_claimed: false,
  external_delivery_configured: false,
  legal_completion_claimed: false,
  ...overrides,
});

const processor: ProcessorRecordView = {
  id: 'processor-1',
  name: 'Alpha Processor',
  purpose: 'EU hosting',
  legal_basis: 'Contract',
  data_categories: ['Identity', 'Contact'],
  subprocessors: [],
  risk_level: 'low',
  status: 'draft',
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'owner',
  updated_at: 'invalid-local-date',
  updated_by: 'owner',
};

const dpia: DpiaRecordView = {
  id: 'dpia-1',
  title: 'High-risk profiling',
  purpose: 'Fraud triage',
  legal_basis: 'Legitimate interests',
  data_categories: ['Behaviour'],
  subprocessors: ['Signals Ltd'],
  risk_level: 'high',
  status: 'under_review',
  evidence_receipts: [],
  advisory_review: {
    ...advisory({ status: 'overdue', days_until_due: -4 }),
    authority_filing_claimed: false,
    legal_acceptance_claimed: false,
    legal_certification_claimed: false,
    external_delivery_claimed: false,
    completion_claimed: false,
    compliance_certification_claimed: false,
  },
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'owner',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'owner',
};

const breach: BreachPlaybookView = {
  id: 'breach-1',
  title: 'Account compromise',
  scope: 'identity service',
  detection_channels: ['SIEM', 'support'],
  containment_steps: ['Revoke sessions', 'reset credentials'],
  notification_roles: ['DPO'],
  authority_notification_window: '72 hours when required',
  subject_notification_guidance: 'Notify only after human risk review',
  risk_level: 'critical',
  status: 'active',
  review_notes: 'Annual tabletop',
  evidence_receipts: [
    {
      id: 'breach-receipt-1',
      evidence_type: 'drill',
      recorded_at: '2026-07-02T11:00:00Z',
      recorded_by: 'dpo',
      notes: 'Tabletop only',
      authority_notified: false,
      subjects_notified: false,
    },
  ],
  advisory_review: advisory({
    status: 'due_soon',
    last_reviewed_at: undefined,
    last_drill_at: '2026-07-02T11:00:00Z',
    days_until_due: 5,
    drill_receipt_count: 1,
  }),
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'owner',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'owner',
};

const transfer: TransferControlView = {
  id: 'transfer-1',
  name: 'UK support access',
  purpose: 'Case investigation',
  legal_basis: 'Contract',
  data_categories: ['Support messages'],
  recipient: 'Support UK Ltd',
  destination_country: 'United Kingdom',
  transfer_mechanism: 'Adequacy regulation',
  safeguards: ['Ticket-scoped access'],
  risk_level: 'medium',
  status: 'retired',
  review_notes: 'Quarterly review',
  evidence_receipts: [],
  advisory_review: advisory({ status: 'no_receipt', last_reviewed_at: undefined }),
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'owner',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'owner',
};

const retentionPolicy: RetentionPolicyView = {
  id: 'retention-1',
  name: 'Closed books archive',
  scope: 'book_archive',
  category: 'documents',
  schedule_id: 'legal-10y',
  retention_period: 'P10Y',
  legal_basis: 'Corporate record law',
  disposal_action: 'archive',
  status: 'suspended',
  active: false,
  notes: 'Manual legal review',
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'owner',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'owner',
};

const dpiaTemplate: DpiaTemplateView = {
  schema: 'chancela-privacy-dpia-template/v1',
  template_id: 'privacy-dpia-guidance/v1',
  title: 'DPIA guidance',
  version: 1,
  language: 'en',
  scope: 'local_offline_guidance_only',
  local_offline_guidance_only: true,
  sections: [
    {
      id: 'risk',
      title: 'Risk prompts',
      description: 'Human review prompts only.',
      prompts: ['What can harm a data subject?'],
      checklist: [
        {
          id: 'evidence',
          label: 'Evidence reference',
          field_type: 'evidence_reference',
          required: true,
        },
      ],
    },
  ],
  operator_actions: ['Escalate unresolved questions to the DPO.'],
  no_claims: {
    authority_filing_completed: false,
    authority_approval_obtained: false,
    cnpd_filing_completed: false,
    edpb_filing_completed: false,
    cnpd_or_edpb_approval_obtained: false,
    legal_review_accepted: false,
    legal_validation_completed: false,
    external_validation_completed: false,
    external_legal_validation_completed: false,
    external_delivery_completed: false,
    dpia_completed: false,
    dpia_completion_certified: false,
    compliance_certification_completed: false,
    transfer_approval_claimed: false,
    transfer_execution_claimed: false,
    authority_notification_claimed: false,
    subject_notification_claimed: false,
    automated_risk_scoring_performed: false,
    risk_score_authority_claimed: false,
    automated_legal_decision_made: false,
    register_mutation_performed: false,
    external_call_performed: false,
    raw_register_contents_included: false,
    processor_names_included: false,
    data_subjects_included: false,
    recipients_included: false,
    personal_data_included: false,
    secrets_included: false,
  },
};

function resetQuery(query: { data: unknown; isLoading: boolean; error: unknown }, data: unknown) {
  query.data = data;
  query.isLoading = false;
  query.error = null;
}

beforeEach(() => {
  resetQuery(hooks.processors, []);
  resetQuery(hooks.dpiaTemplate, null);
  resetQuery(hooks.dpias, []);
  resetQuery(hooks.breaches, []);
  resetQuery(hooks.transfers, []);
  resetQuery(hooks.retentionPolicies, []);
  resetQuery(hooks.dueCandidates, null);
  resetQuery(hooks.candidateResolutions, []);
  resetQuery(hooks.executions, []);
  for (const mutation of [
    hooks.createProcessor,
    hooks.patchProcessor,
    hooks.createDpia,
    hooks.patchDpia,
    hooks.createBreach,
    hooks.patchBreach,
    hooks.createTransfer,
    hooks.patchTransfer,
    hooks.createRetention,
    hooks.patchRetention,
    hooks.dryRun,
    hooks.recordResolution,
    hooks.closeReview,
  ]) {
    mutation.mutateAsync.mockReset();
    mutation.mutateAsync.mockResolvedValue({});
    mutation.isPending = false;
    mutation.data = null;
  }
  hooks.executionHook.mockReset();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('PrivacyComplianceSection', () => {
  it('fails closed for a reader without user.manage or settings.manage', () => {
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <PrivacyComplianceSection />
      </StaticPermissionsProvider>,
    );

    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Novo registo' })).toBeNull();
    expect(hooks.executionHook).toHaveBeenCalledWith('all', false);
  });

  it('renders independent loading, error, and empty register states', () => {
    hooks.processors.isLoading = true;
    hooks.dpias.error = new Error('DPIA register unavailable');
    renderWithProviders(<PrivacyComplianceSection />);

    expect(screen.getByText('DPIA register unavailable')).toBeTruthy();
    expect(screen.getAllByText('Sem registos').length).toBeGreaterThanOrEqual(2);
    expect(document.querySelectorAll('.skeleton').length).toBeGreaterThan(0);
  });

  it('filters every register by searchable metadata and patches processor risk/status inline', async () => {
    hooks.processors.data = [processor];
    hooks.dpias.data = [dpia];
    hooks.breaches.data = [breach];
    hooks.transfers.data = [transfer];
    renderWithProviders(<PrivacyComplianceSection />);

    // `updated_at` on this fixture is deliberately unparseable. The old local formatter echoed
    // such a value straight back to the page — that leak is the whole reason the shared date
    // family exists — so the contract is now an em-dash placeholder and, crucially, no trace of
    // the raw string anywhere in the document.
    expect(screen.queryByText('invalid-local-date')).toBeNull();
    expect(document.body.textContent).not.toContain('invalid-local-date');
    expect(screen.getAllByText('—').length).toBeGreaterThan(0);
    fireEvent.change(screen.getByLabelText('Risco de Alpha Processor'), {
      target: { value: 'high' },
    });
    fireEvent.change(screen.getByLabelText('Estado de Alpha Processor'), {
      target: { value: 'active' },
    });
    await waitFor(() => {
      expect(hooks.patchProcessor.mutateAsync).toHaveBeenCalledWith({
        id: 'processor-1',
        body: { risk_level: 'high' },
      });
      expect(hooks.patchProcessor.mutateAsync).toHaveBeenCalledWith({
        id: 'processor-1',
        body: { status: 'active' },
      });
    });

    const searchIds = [
      'privacy-processor-search',
      'privacy-dpia-search',
      'privacy-breach-search',
      'privacy-transfer-search',
    ];
    for (const id of searchIds) {
      fireEvent.change(document.getElementById(id)!, { target: { value: 'no such record' } });
    }
    expect(screen.getAllByText('Sem resultados').length).toBe(4);

    fireEvent.change(document.getElementById('privacy-breach-search')!, {
      target: { value: 'SIEM' },
    });
    fireEvent.change(document.getElementById('privacy-transfer-search')!, {
      target: { value: 'ticket-scoped' },
    });
    expect(screen.getByText('Account compromise')).toBeTruthy();
    expect(screen.getByText('UK support access')).toBeTruthy();
  });

  it('edits breach and transfer records into trimmed API bodies with local evidence only', async () => {
    hooks.breaches.data = [breach];
    hooks.transfers.data = [transfer];
    renderWithProviders(<PrivacyComplianceSection />);

    const breachRow = screen.getByText('Account compromise').closest('tr') as HTMLElement;
    fireEvent.click(within(breachRow).getByRole('button', { name: 'Editar' }));
    expect((screen.getByLabelText('Título do playbook') as HTMLInputElement).value).toBe(
      'Account compromise',
    );
    fireEvent.change(screen.getByLabelText('Funções notificadas'), {
      target: { value: 'DPO, Security lead' },
    });
    fireEvent.change(screen.getByLabelText('Tipo de evidência'), { target: { value: 'review' } });
    fireEvent.change(screen.getByLabelText('Notas de evidência'), {
      target: { value: '  Reviewed locally  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));
    await waitFor(() => {
      expect(hooks.patchBreach.mutateAsync).toHaveBeenCalledWith({
        id: 'breach-1',
        body: expect.objectContaining({
          notification_roles: ['DPO', 'Security lead'],
          evidence_receipt: expect.objectContaining({
            evidence_type: 'review',
            notes: 'Reviewed locally',
          }),
        }),
      });
    });

    const transferRow = screen.getByText('UK support access').closest('tr') as HTMLElement;
    fireEvent.click(within(transferRow).getByRole('button', { name: 'Editar' }));
    fireEvent.change(screen.getByLabelText('Salvaguardas'), {
      target: { value: 'Ticket-scoped access\nMFA' },
    });
    fireEvent.change(screen.getByLabelText('Notas de evidência'), {
      target: { value: '  Review receipt  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));
    await waitFor(() => {
      expect(hooks.patchTransfer.mutateAsync).toHaveBeenCalledWith({
        id: 'transfer-1',
        body: expect.objectContaining({
          safeguards: ['Ticket-scoped access', 'MFA'],
          evidence_receipt: expect.objectContaining({ notes: 'Review receipt' }),
        }),
      });
    });
  });

  it('validates and creates breach and transfer controls, preserving optional-field semantics', async () => {
    renderWithProviders(<PrivacyComplianceSection />);

    const breachPanel = screen
      .getByText('Playbooks de resposta a violações')
      .closest<HTMLElement>('.panel')!;
    fireEvent.click(within(breachPanel).getByRole('button', { name: 'Novo registo' }));
    const createBreach = screen.getByRole('button', { name: 'Criar registo' }) as HTMLButtonElement;
    expect(createBreach.disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Título do playbook'), {
      target: { value: '  Leak  ' },
    });
    fireEvent.change(screen.getByLabelText('Âmbito'), { target: { value: '  files  ' } });
    fireEvent.change(screen.getByLabelText('Canais de deteção'), {
      target: { value: 'DLP, user report' },
    });
    fireEvent.change(screen.getByLabelText('Passos de contenção'), {
      target: { value: 'Disable link\nRotate token' },
    });
    fireEvent.change(document.getElementById('privacy-breach-new-risk')!, {
      target: { value: 'high' },
    });
    fireEvent.change(document.getElementById('privacy-breach-new-status')!, {
      target: { value: 'under_review' },
    });
    fireEvent.click(createBreach);
    await waitFor(() => {
      expect(hooks.createBreach.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Leak',
          scope: 'files',
          detection_channels: ['DLP', 'user report'],
          containment_steps: ['Disable link', 'Rotate token'],
          authority_notification_window: undefined,
          evidence_receipt: undefined,
        }),
      );
    });

    const transferPanel = screen
      .getByText('Controlos de transferência')
      .closest<HTMLElement>('.panel')!;
    fireEvent.click(within(transferPanel).getByRole('button', { name: 'Novo registo' }));
    const values: [string, string][] = [
      ['Nome do controlo', 'US incident support'],
      ['Finalidade', 'Incident response'],
      ['Base legal', 'SCC'],
      ['Categorias de dados', 'Support messages'],
      ['Destinatário', 'US Support Inc'],
      ['País de destino', 'United States'],
      ['Mecanismo de transferência', 'SCC 2021'],
      ['Salvaguardas', 'MFA, ticket scope'],
    ];
    for (const [label, value] of values) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));
    await waitFor(() => {
      expect(hooks.createTransfer.mutateAsync).toHaveBeenCalledWith(
        expect.objectContaining({
          data_categories: ['Support messages'],
          safeguards: ['MFA', 'ticket scope'],
          review_notes: undefined,
          evidence_receipt: undefined,
        }),
      );
    });
  });

  it('surfaces mutation failures and leaves the operator form open for correction', async () => {
    hooks.createProcessor.mutateAsync.mockRejectedValueOnce(new Error('processor write denied'));
    renderWithProviders(<PrivacyComplianceSection />);
    const processorPanel = screen.getByText('Processadores GDPR').closest<HTMLElement>('.panel')!;
    fireEvent.click(within(processorPanel).getByRole('button', { name: 'Novo registo' }));
    const values: [string, string][] = [
      ['Nome do processador', 'New Processor'],
      ['Finalidade', 'Hosting'],
      ['Base legal', 'Contract'],
      ['Categorias de dados', 'Identity'],
    ];
    for (const [label, value] of values) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    fireEvent.click(screen.getByRole('button', { name: 'Criar registo' }));

    expect(await screen.findByText('processor write denied')).toBeTruthy();
    expect(screen.getByLabelText('Nome do processador')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));
    expect(screen.queryByLabelText('Nome do processador')).toBeNull();
  });

  it('covers guidance loading, error, empty, and complete static-pack states', () => {
    hooks.dpiaTemplate.isLoading = true;
    const first = renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Orientação' }));
    expect(document.querySelectorAll('.skeleton').length).toBeGreaterThan(0);
    first.unmount();

    hooks.dpiaTemplate.isLoading = false;
    hooks.dpiaTemplate.error = new Error('guidance unavailable');
    const second = renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Orientação' }));
    expect(screen.getByText('guidance unavailable')).toBeTruthy();
    second.unmount();

    hooks.dpiaTemplate.error = null;
    const third = renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Orientação' }));
    expect(screen.getByText('Modelo indisponível')).toBeTruthy();
    third.unmount();

    hooks.dpiaTemplate.data = dpiaTemplate;
    renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Orientação' }));
    expect(screen.getByText('Risk prompts')).toBeTruthy();
    expect(screen.getByText('What can harm a data subject?')).toBeTruthy();
    expect(screen.getByText(/Evidence reference/)).toBeTruthy();
    expect(screen.getByText('Escalate unresolved questions to the DPO.')).toBeTruthy();
    fireEvent.click(screen.getByText('Flags sem alegação'));
    expect(screen.getByText(/authority_filing_completed:/)).toBeTruthy();
  });

  it('filters and edits retention policy metadata and performs a non-destructive dry run', async () => {
    hooks.retentionPolicies.data = [retentionPolicy];
    hooks.dryRun.mutateAsync.mockResolvedValueOnce({});
    renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Retenção' }));

    expect(screen.getByText('Closed books archive')).toBeTruthy();
    fireEvent.change(document.getElementById('privacy-retention-search')!, {
      target: { value: 'not found' },
    });
    expect(screen.getByText('Sem resultados')).toBeTruthy();
    fireEvent.change(document.getElementById('privacy-retention-search')!, {
      target: { value: 'P10Y' },
    });
    const row = screen.getByText('Closed books archive').closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: 'Editar' }));
    fireEvent.change(document.getElementById('privacy-retention-edit-status')!, {
      target: { value: 'active' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar alterações' }));
    await waitFor(() => {
      expect(hooks.patchRetention.mutateAsync).toHaveBeenCalledWith({
        id: 'retention-1',
        body: expect.objectContaining({
          status: 'active',
          active: false,
          notes: 'Manual legal review',
        }),
      });
    });

    fireEvent.change(screen.getByLabelText('Âmbito'), { target: { value: 'book_archive' } });
    fireEvent.change(screen.getByLabelText('Categoria'), { target: { value: 'documents' } });
    fireEvent.change(screen.getByLabelText('ID do registo'), { target: { value: '  book-7  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Simular retenção' }));
    await waitFor(() => {
      expect(hooks.dryRun.mutateAsync).toHaveBeenCalledWith({
        scope: 'book_archive',
        category: 'documents',
        record_id: 'book-7',
      });
    });
    expect(hooks.executionHook).toHaveBeenCalledWith('all', true);
  });
});
