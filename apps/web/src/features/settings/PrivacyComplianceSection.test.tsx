import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import type {
  BreachPlaybookView,
  DpiaRecordView,
  DpiaTemplateView,
  PrivacyAdvisoryReviewSummary,
  ProcessorRecordView,
  RetentionDueCandidate,
  RetentionDueCandidatesReport,
  RetentionExecutionRecord,
  RetentionLegalHoldBlocker,
  RetentionPolicyView,
  TransferControlView,
} from '../../api/types';
/**
 * Register titles and field labels are looked up by catalog KEY, not by the pt-PT words of the
 * day: the terminology moved twice (GDPR→RGPD, DPIA→AIPD) without this surface changing, and
 * what these cases assert is that the right register reached the right panel.
 */
import { ptPT } from '../../i18n/locales/pt-PT';
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
  // Real backend section/checklist ids so the client resolves them to translated catalog keys.
  // The English strings here are the wire copy the panel deliberately overrides with pt-PT.
  sections: [
    {
      id: 'risk_prompts',
      title: 'Risk prompts',
      description: 'Human review prompts only.',
      prompts: ['What rights and freedoms impacts should be reviewed?'],
      checklist: [
        {
          id: 'risk_review_note',
          label: 'Human risk review note',
          field_type: 'review_note',
          required: true,
        },
      ],
    },
  ],
  operator_actions: ['Fill placeholders locally with human-written notes.'],
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

const legalHoldBlocker: RetentionLegalHoldBlocker = {
  policy_id: 'retention-1',
  name: 'Board preservation hold',
  schedule_id: 'legal-10y',
  retention_period: 'P10Y',
  reason: 'legal hold active on archived book',
};

function dueCandidate(
  id: string,
  legal_hold_blockers: RetentionLegalHoldBlocker[],
): RetentionDueCandidate {
  return {
    candidate_id: id,
    candidate_fingerprint: id.padEnd(64, '0'),
    scope: 'book_archive',
    category: 'documents',
    record_id: `archive-${id}`,
    book_id: `book-${id}`,
    entity_id: 'entity-1',
    closing_date: '2024-06-01',
    due_date: '2026-06-01',
    overdue: true,
    policy_id: 'retention-1',
    policy_name: 'Closed books archive',
    schedule_id: 'legal-10y',
    retention_period: 'P10Y',
    disposal_action: 'review',
    destructive_action: false,
    legal_hold_blockers,
    required_approvals: [],
    blockers: [],
    findings: [],
    outcome: 'manual_review_required',
    status: 'awaiting_manual_review',
    candidate_evidence_state: 'review_queued',
    evidence_next_step: 'Review evidence only; no deletion or anonymization is performed.',
    would_execute: false,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    candidate_resolution_record_count: 0,
    next_step: 'Review evidence only; no deletion or anonymization is performed.',
  };
}

function dueCandidatesReport(candidates: RetentionDueCandidate[]): RetentionDueCandidatesReport {
  return {
    generated_at: '2026-07-09T14:00:00Z',
    scope: 'book_archive',
    category: 'documents',
    candidate_count: candidates.length,
    suppressed_candidate_count: 0,
    suppressed_by_bounded_evidence_count: 0,
    candidate_resolution_record_count: 0,
    candidates_with_resolution_count: 0,
    candidates,
  };
}

function executionRecord(
  id: string,
  overrides: Partial<RetentionExecutionRecord> = {},
): RetentionExecutionRecord {
  return {
    id,
    requested_at: '2026-07-08T09:00:00Z',
    actor: 'owner',
    execution_intent: 'review_only',
    execution_status: 'awaiting_review',
    operator_review_decision: 'review_required',
    decision_state: 'open',
    review_closure_evidence: [],
    requested_policy: {
      id: 'retention-1',
      found: true,
      name: 'Closed books archive',
      scope: 'book_archive',
      category: 'documents',
      schedule_id: 'legal-10y',
      retention_period: 'P10Y',
      disposal_action: 'review',
      status: 'active',
      active: true,
      stale: false,
      matches_candidate: true,
      destructive_action: false,
    },
    candidate: { scope: 'book_archive', category: 'documents', record_id: `archive-${id}` },
    matched_records_summary: {
      scope: 'book_archive',
      category: 'documents',
      record_id: `archive-${id}`,
      record_count: 1,
      policy_match_count: 1,
      destructive_policy_count: 0,
      policy_ids: ['retention-1'],
    },
    legal_hold_blockers: [],
    audit_evidence: [],
    outcome: 'manual_review_required',
    block_reason: '',
    evidence_state: 'review_queued',
    evidence_next_step: 'Review evidence only; no deletion or anonymization is performed.',
    workflow: {
      status: 'awaiting_manual_review',
      blockers: [],
      required_approvals: [],
      next_step: 'Review evidence only.',
    },
    execution_result: {
      bounded_executor: true,
      targets_considered: [],
      targets_acted: [],
      targets_skipped: [],
      reason_codes: [],
      next_step: 'Review evidence only.',
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      blocker_metadata: [],
    },
    would_execute: false,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    legal_hold_mutated: false,
    retention_policy_mutated: false,
    ...overrides,
  };
}

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

  /**
   * The breach-playbook and transfer-control editors were inline `<Card>`s rendered ABOVE their
   * list — they shoved the table down the page, had no address, and browser Back reached neither.
   * They are pages now (t55-e3); the body-shape assertions that used to live here moved with the
   * forms, to `privacy/BreachPlaybookPage.test.tsx` and `privacy/TransferControlPage.test.tsx`.
   * What stays here is the list's half of the contract: it links, and it authors nothing.
   */
  it('offers the breach and transfer editors as addresses, not as inline forms', () => {
    hooks.breaches.data = [breach];
    hooks.transfers.data = [transfer];
    renderWithProviders(<PrivacyComplianceSection />);

    const breachPanel = screen
      .getByText('Playbooks de resposta a violações')
      .closest<HTMLElement>('.panel')!;
    expect(
      within(breachPanel).getByRole('link', { name: 'Novo registo' }).getAttribute('href'),
    ).toBe('/settings/privacy/breach-playbooks/new');
    expect(within(breachPanel).queryByRole('button', { name: 'Novo registo' })).toBeNull();

    // Two affordances per row, ONE address: the primary cell and the explicit action. Both are
    // real links, so they can be middle-clicked, copied and bookmarked.
    const breachRow = screen.getByText('Account compromise').closest('tr') as HTMLElement;
    expect(
      within(breachRow).getByRole('link', { name: 'Account compromise' }).getAttribute('href'),
    ).toBe('/settings/privacy/breach-playbooks/breach-1');
    expect(within(breachRow).getByRole('link', { name: 'Editar' }).getAttribute('href')).toBe(
      '/settings/privacy/breach-playbooks/breach-1',
    );
    expect(within(breachRow).queryByRole('button', { name: 'Editar' })).toBeNull();

    const transferPanel = screen
      .getByText('Controlos de transferência')
      .closest<HTMLElement>('.panel')!;
    expect(
      within(transferPanel).getByRole('link', { name: 'Novo registo' }).getAttribute('href'),
    ).toBe('/settings/privacy/transfer-controls/new');

    const transferRow = screen.getByText('UK support access').closest('tr') as HTMLElement;
    expect(
      within(transferRow).getByRole('link', { name: 'UK support access' }).getAttribute('href'),
    ).toBe('/settings/privacy/transfer-controls/transfer-1');
    expect(within(transferRow).getByRole('link', { name: 'Editar' }).getAttribute('href')).toBe(
      '/settings/privacy/transfer-controls/transfer-1',
    );
  });

  it('holds no breach or transfer draft: the list can no longer create or patch either', () => {
    // 🔒 REGRESSION GUARD. The inline form's state left a create/patch path inside the LIST. The
    // record pages own that path now and re-check `privacy.manage` themselves; the panels must not
    // grow a second one back — not as a card, not as a dialog.
    hooks.breaches.data = [breach];
    hooks.transfers.data = [transfer];
    renderWithProviders(<PrivacyComplianceSection />);

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByLabelText('Título do playbook')).toBeNull();
    expect(screen.queryByLabelText('Nome do controlo')).toBeNull();
    expect(document.getElementById('privacy-breach-new-status')).toBeNull();
    expect(document.getElementById('privacy-breach-edit-status')).toBeNull();
    expect(document.getElementById('privacy-transfer-new-status')).toBeNull();
    expect(document.getElementById('privacy-transfer-edit-status')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Guardar alterações' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Criar registo' })).toBeNull();
    expect(hooks.createBreach.mutateAsync).not.toHaveBeenCalled();
    expect(hooks.patchBreach.mutateAsync).not.toHaveBeenCalled();
    expect(hooks.createTransfer.mutateAsync).not.toHaveBeenCalled();
    expect(hooks.patchTransfer.mutateAsync).not.toHaveBeenCalled();
  });

  it('offers both registers as addresses and keeps no editor in the list at all', () => {
    hooks.processors.data = [processor];
    hooks.dpias.data = [dpia];
    renderWithProviders(<PrivacyComplianceSection />);

    // 🔒 REGRESSION GUARD. The register editor used to be a portalled window that closed on
    // Escape and on a backdrop click with no confirmation — one stray click discarded a
    // nine-field DPIA silently. Nothing dialog-shaped may come back to this list, and no
    // authoring form may render inline either.
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(screen.queryByLabelText(ptPT['settings.privacy.register.field.dpiaTitle'])).toBeNull();
    expect(screen.queryByLabelText('Nome do processador')).toBeNull();

    const processorPanel = screen
      .getByText(ptPT['settings.privacy.register.processor.title'])
      .closest<HTMLElement>('.panel')!;
    expect(
      within(processorPanel).getByRole('link', { name: 'Novo registo' }).getAttribute('href'),
    ).toBe('/settings/privacy/processors/new');
    expect(within(processorPanel).queryByRole('button', { name: 'Novo registo' })).toBeNull();

    const dpiaPanel = screen
      .getByText(ptPT['settings.privacy.register.dpia.title'])
      .closest<HTMLElement>('.panel')!;
    expect(within(dpiaPanel).getByRole('link', { name: 'Novo registo' }).getAttribute('href')).toBe(
      '/settings/privacy/dpias/new',
    );

    // Two affordances per row, ONE address: the primary cell and the explicit action. Both are
    // real links, so they can be middle-clicked, copied and bookmarked.
    const dpiaRow = screen.getByText('High-risk profiling').closest('tr') as HTMLElement;
    expect(
      within(dpiaRow).getByRole('link', { name: 'High-risk profiling' }).getAttribute('href'),
    ).toBe('/settings/privacy/dpias/dpia-1');
    expect(within(dpiaRow).getByRole('link', { name: 'Editar' }).getAttribute('href')).toBe(
      '/settings/privacy/dpias/dpia-1',
    );
    expect(within(dpiaRow).queryByRole('button', { name: 'Editar' })).toBeNull();

    const processorRow = screen.getByText('Alpha Processor').closest('tr') as HTMLElement;
    expect(
      within(processorRow).getByRole('link', { name: 'Alpha Processor' }).getAttribute('href'),
    ).toBe('/settings/privacy/processors/processor-1');

    // The list creates nothing any more; that mutation belongs to the record page.
    expect(hooks.createProcessor.mutateAsync).not.toHaveBeenCalled();
    expect(hooks.createDpia.mutateAsync).not.toHaveBeenCalled();
  });

  it('covers guidance loading, error, empty, and translated static-pack states', () => {
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
    // The guidance template's wire copy is English; the panel resolves each stable id to the
    // pt-PT catalog key, so the reader sees Portuguese, not the backend's English strings.
    expect(screen.getByText('Perguntas de risco')).toBeTruthy();
    expect(screen.queryByText('Risk prompts')).toBeNull();
    expect(
      screen.getByText('Que impactos nos direitos e liberdades devem ser revistos?'),
    ).toBeTruthy();
    expect(screen.getByText(/Nota de revisão humana do risco/)).toBeTruthy();
    // `field_type` is a wire identifier shown verbatim in `mono` — never translated.
    expect(screen.getByText('review_note')).toBeTruthy();
    // Operator actions are translated too, positionally.
    expect(
      screen.getByText(
        'Preencha os marcadores localmente com notas redigidas por pessoas, fora da resposta deste modelo.',
      ),
    ).toBeTruthy();
    expect(screen.queryByText('Fill placeholders locally with human-written notes.')).toBeNull();
    fireEvent.click(screen.getByText('Flags sem alegação'));
    // t102: the disclosure is a two-column table now, not a `key: value` tag row, so the flag
    // identifier is a cell of its own and no longer carries a trailing colon.
    const claimRow = screen.getByText('authority_filing_completed').closest('tr');
    expect(claimRow).toBeTruthy();
    expect(within(claimRow as HTMLElement).getByText('Não alegado')).toBeTruthy();
  });

  it('filters retention policies and performs a non-destructive dry run', async () => {
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

  /**
   * t55-e4 — the retention-policy editor is a PAGE now
   * (`/settings/privacy/retention-policies/{new,:id}`), not an inline `<Card>` shoved above the
   * list. The panel lists and links; it no longer holds a draft.
   */
  it('offers the retention editor as addresses, not as an inline form', () => {
    hooks.retentionPolicies.data = [retentionPolicy];
    renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Retenção' }));

    const row = screen.getByText('Closed books archive').closest('tr') as HTMLElement;
    // Two affordances, ONE address: the primary cell and the Editar action.
    expect(
      within(row).getByRole('link', { name: 'Closed books archive' }).getAttribute('href'),
    ).toBe('/settings/privacy/retention-policies/retention-1');
    expect(within(row).getByRole('link', { name: 'Editar' }).getAttribute('href')).toBe(
      '/settings/privacy/retention-policies/retention-1',
    );
    // Neither affordance is a button any more — a button has no address to paste or middle-click.
    expect(within(row).queryByRole('button', { name: 'Editar' })).toBeNull();

    const panel = screen.getByText('Políticas de retenção').closest('section') as HTMLElement;
    expect(within(panel).getByRole('link', { name: 'Novo registo' }).getAttribute('href')).toBe(
      '/settings/privacy/retention-policies/new',
    );
    expect(within(panel).queryByRole('button', { name: 'Novo registo' })).toBeNull();
  });

  it('holds no retention draft: opening the list can no longer create or patch a policy', () => {
    // 🔒 REGRESSION GUARD. The inline form's state left a create/patch path inside the LIST, on a
    // panel the section renders under its own `retention.manage` check. The record page owns that
    // path now and re-checks the verb itself; the panel must not grow a second one back.
    hooks.retentionPolicies.data = [retentionPolicy];
    renderWithProviders(<PrivacyComplianceSection />);
    fireEvent.click(screen.getByRole('button', { name: 'Retenção' }));

    expect(document.getElementById('privacy-retention-edit-status')).toBeNull();
    expect(document.getElementById('privacy-retention-new-status')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Guardar alterações' })).toBeNull();
    expect(hooks.createRetention.mutateAsync).not.toHaveBeenCalled();
    expect(hooks.patchRetention.mutateAsync).not.toHaveBeenCalled();
  });

  /**
   * The legal-hold panel used to be a `<dl className="deflist">` auto-fit grid and had no test
   * coverage at all. These two cases are the whole CI guard for it (t54-e3).
   */
  function legalHoldTable(): HTMLElement {
    fireEvent.click(screen.getByRole('button', { name: 'Retenção' }));
    // The table is captionless by design — the Card title names it — so it is reached through the
    // panel, the same way SettingsPage.test.tsx reaches it.
    const panel = screen
      .getByText('Estado local de legal hold e descarte')
      .closest('section') as HTMLElement;
    return within(panel).getByRole('table');
  }

  function legalHoldRow(table: HTMLElement, label: string): HTMLElement {
    return within(table).getByRole('rowheader', { name: label }).closest('tr') as HTMLElement;
  }

  it('derives the legal-hold counts from the due-candidates report and the execution records', () => {
    // 3 candidates, 2 of them held. 3 held executions (one held via the workflow blocker rather
    // than the outcome), 2 of which have had their review closed — so 2 / 3 / 1, three distinct
    // numbers, which a row wired to the wrong summary field cannot accidentally satisfy.
    hooks.dueCandidates.data = dueCandidatesReport([
      dueCandidate('cand-1', [legalHoldBlocker]),
      dueCandidate('cand-2', [legalHoldBlocker]),
      dueCandidate('cand-3', []),
    ]);
    hooks.executions.data = [
      executionRecord('exec-1', {
        outcome: 'blocked_legal_hold',
        execution_status: 'blocked',
        decision_state: 'review_closed',
      }),
      executionRecord('exec-2', {
        legal_hold_blockers: [legalHoldBlocker],
        execution_status: 'blocked',
        decision_state: 'review_closed',
      }),
      executionRecord('exec-3', {
        execution_status: 'blocked',
        workflow: {
          status: 'blocked',
          blockers: [{ code: 'legal_hold_release', message: 'Release the legal hold first.' }],
          required_approvals: [],
          next_step: 'Release the legal hold first.',
        },
      }),
      executionRecord('exec-4'),
    ];
    renderWithProviders(<PrivacyComplianceSection />);
    const table = legalHoldTable();

    const rowValue = (label: string) =>
      within(legalHoldRow(table, label)).getAllByRole('cell')[0].textContent;
    expect(rowValue('Candidatos bloqueados por legal hold')).toBe('2');
    expect(rowValue('Registos de execução bloqueados por legal hold')).toBe('3');
    expect(rowValue('Revisões bloqueadas ainda abertas')).toBe('1');

    // Six body rows: the three counts above and the three no-claim flags below. The flags used to
    // share one `·`-joined cell with the counts' sibling; that blob must not come back.
    expect(table.querySelectorAll('tbody tr')).toHaveLength(6);
    expect(table.textContent).not.toContain('destructive_disposal_completed: ');
    expect(table.textContent).not.toContain('·');
  });

  it('states the three no_claims flags verbatim, untranslated, and false', () => {
    // 🔒 REGRESSION GUARD — read before "improving" this test or the rows it covers.
    //
    // These three identifiers name legal claims the product does NOT make. The gap is the
    // decision, deliberately taken. The dangerous change here is a well-meaning one — an i18n
    // sweep that translates them, a badge cleanup that turns them into a green/red verdict, a
    // tidy-up that sentence-cases them — and any of those silently converts a disclaimer into an
    // assurance about legal compliance. That is a misstatement on an evidentiary surface, not a
    // styling regression. If this test fails, the fix is almost certainly to revert the change,
    // not to relax the assertion.
    renderWithProviders(<PrivacyComplianceSection />);
    const table = legalHoldTable();

    for (const flag of [
      'destructive_disposal_completed',
      'disposal_approved',
      'legal_compliance_claimed',
    ]) {
      const header = within(table).getByRole('rowheader', { name: flag });
      // Exact text: catches translation, sentence-casing, and a re-appended `: ` suffix alike.
      expect(header.textContent).toBe(flag);
      const cells = within(header.closest('tr') as HTMLElement).getAllByRole('cell');
      expect(cells).toHaveLength(1);
      expect(cells[0].textContent).toBe('false');
    }

    // Not a badge, and not a translated claim-state. The sibling guidance table renders its own
    // no-claims flags as a `Não alegado` chip; this panel deliberately does not, because a bare
    // `false` asserts nothing beyond itself.
    expect(table.querySelectorAll('.badge')).toHaveLength(0);
    expect(within(table).queryByText('Não alegado')).toBeNull();
  });
});
