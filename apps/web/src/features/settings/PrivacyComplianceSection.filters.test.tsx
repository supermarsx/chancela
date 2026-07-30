/**
 * The five privacy registers' STRUCTURED filters, and the clear control that undoes them.
 *
 * `PrivacyComplianceSection.test.tsx` covers the free-text search on each register. The dropdown
 * axes — status, risk, presence of subprocessors or evidence, review state, destination country,
 * disposal action, legal hold — are a different mechanism, and the failure they hide is the worst
 * kind for a compliance register: a filter wired to the wrong field silently shows a *shorter*
 * list, and a shorter list of processing records reads as "we have fewer of these" rather than as
 * a bug.
 *
 * Each fixture pair differs on exactly one axis, so a filter that read a neighbouring field would
 * return the wrong row rather than an empty list. `clearFilters` is asserted per register too: it
 * is one function per panel, none of them shared, so a new axis that is not added to its clear is
 * a filter the operator cannot switch off.
 *
 * Rows are addressed by their fixture NAME (data this file wrote) and controls by their stable
 * element id — never by translated option copy.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import type {
  BreachPlaybookView,
  DpiaRecordView,
  PrivacyAdvisoryReviewSummary,
  ProcessorRecordView,
  RetentionPolicyView,
  TransferControlView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import { PrivacyComplianceSection } from './PrivacyComplianceSection';

const hooks = vi.hoisted(() => {
  const query = () => ({ data: [] as unknown[], isLoading: false, error: null as unknown });
  const mutation = () => ({ mutateAsync: vi.fn(), isPending: false, data: null as unknown });
  return {
    processors: query(),
    dpias: query(),
    breaches: query(),
    transfers: query(),
    retentionPolicies: query(),
    executions: query(),
    candidateResolutions: query(),
    dpiaTemplate: { data: null as unknown, isLoading: false, error: null as unknown },
    dueCandidates: { data: null as unknown, isLoading: false, error: null as unknown },
    mutation: mutation(),
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
    usePrivacyRetentionExecutions: () => hooks.executions,
    useCreatePrivacyProcessor: () => hooks.mutation,
    usePatchPrivacyProcessor: () => hooks.mutation,
    useCreatePrivacyDpia: () => hooks.mutation,
    usePatchPrivacyDpia: () => hooks.mutation,
    useCreatePrivacyBreachPlaybook: () => hooks.mutation,
    usePatchPrivacyBreachPlaybook: () => hooks.mutation,
    useCreatePrivacyTransferControl: () => hooks.mutation,
    usePatchPrivacyTransferControl: () => hooks.mutation,
    useCreatePrivacyRetentionPolicy: () => hooks.mutation,
    usePatchPrivacyRetentionPolicy: () => hooks.mutation,
    useDryRunPrivacyRetentionPolicy: () => hooks.mutation,
    useRecordPrivacyRetentionCandidateResolution: () => hooks.mutation,
    useClosePrivacyRetentionExecutionReview: () => hooks.mutation,
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
  receipt_count: 0,
  review_receipt_count: 0,
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

const stamps = {
  created_at: '2026-07-01T09:00:00Z',
  created_by: 'owner',
  updated_at: '2026-07-02T09:00:00Z',
  updated_by: 'owner',
};

function processor(overrides: Partial<ProcessorRecordView>): ProcessorRecordView {
  return {
    id: 'processor-x',
    name: 'Processador X',
    purpose: 'Alojamento',
    legal_basis: 'Contrato',
    data_categories: ['Identidade'],
    subprocessors: [],
    risk_level: 'low',
    status: 'draft',
    ...stamps,
    ...overrides,
  };
}

function dpiaRecord(overrides: Partial<DpiaRecordView>): DpiaRecordView {
  return {
    id: 'dpia-x',
    title: 'AIPD X',
    purpose: 'Triagem',
    legal_basis: 'Interesse legítimo',
    data_categories: ['Comportamento'],
    subprocessors: [],
    risk_level: 'low',
    status: 'draft',
    evidence_receipts: [],
    advisory_review: {
      ...advisory(),
      authority_filing_claimed: false,
      legal_acceptance_claimed: false,
      legal_certification_claimed: false,
      external_delivery_claimed: false,
      completion_claimed: false,
      compliance_certification_claimed: false,
    },
    ...stamps,
    ...overrides,
  };
}

function breachPlaybook(overrides: Partial<BreachPlaybookView>): BreachPlaybookView {
  return {
    id: 'breach-x',
    title: 'Manual X',
    scope: 'identidade',
    detection_channels: ['SIEM'],
    containment_steps: ['Revogar sessões'],
    notification_roles: ['EPD'],
    authority_notification_window: '72 horas quando aplicável',
    subject_notification_guidance: 'Só após revisão humana',
    risk_level: 'low',
    status: 'draft',
    review_notes: '',
    evidence_receipts: [],
    advisory_review: advisory(),
    ...stamps,
    ...overrides,
  };
}

function transferControl(overrides: Partial<TransferControlView>): TransferControlView {
  return {
    id: 'transfer-x',
    name: 'Transferência X',
    purpose: 'Investigação',
    legal_basis: 'Contrato',
    data_categories: ['Mensagens'],
    recipient: 'Destinatário',
    destination_country: 'Reino Unido',
    transfer_mechanism: 'Decisão de adequação',
    safeguards: [],
    risk_level: 'low',
    status: 'draft',
    review_notes: '',
    evidence_receipts: [],
    advisory_review: advisory(),
    ...stamps,
    ...overrides,
  };
}

function retentionPolicy(overrides: Partial<RetentionPolicyView>): RetentionPolicyView {
  return {
    id: 'retention-x',
    name: 'Política X',
    scope: 'book_archive',
    category: 'documents',
    schedule_id: 'legal-10y',
    retention_period: 'P10Y',
    legal_basis: 'Lei societária',
    disposal_action: 'archive',
    status: 'draft',
    active: false,
    notes: '',
    ...stamps,
    ...overrides,
  };
}

function resetQuery(query: { data: unknown; isLoading: boolean; error: unknown }, data: unknown) {
  query.data = data;
  query.isLoading = false;
  query.error = null;
}

/** A filter control, addressed by the stable element id the panel gives it. */
function control(id: string): HTMLSelectElement | HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no filter control #${id}`);
  return el as HTMLSelectElement | HTMLInputElement;
}

function setFilter(id: string, value: string) {
  fireEvent.change(control(id), { target: { value } });
}

/** The clear control of the SAME filter bar this control belongs to. */
function clearFor(id: string): HTMLButtonElement {
  const bar = control(id).closest('[role="search"]');
  if (!bar) throw new Error(`#${id} is not inside a filter bar`);
  const button = bar.querySelector<HTMLButtonElement>('.privacy-filterbar__clear');
  if (!button) throw new Error(`the bar holding #${id} has no clear control`);
  return button;
}

/** The retention family lives behind its own sub-tab, reached by the SubNav item's catalog key. */
function openRetentionTab() {
  fireEvent.click(
    screen.getByRole('button', { name: ptPT['settings.privacy.subtab.retention.label'] }),
  );
}

function shows(name: string): boolean {
  return screen.queryAllByText(name).length > 0;
}

beforeEach(() => {
  resetQuery(hooks.processors, []);
  resetQuery(hooks.dpias, []);
  resetQuery(hooks.breaches, []);
  resetQuery(hooks.transfers, []);
  resetQuery(hooks.retentionPolicies, []);
  resetQuery(hooks.executions, []);
  resetQuery(hooks.candidateResolutions, []);
  resetQuery(hooks.dpiaTemplate, null);
  resetQuery(hooks.dueCandidates, null);
  hooks.mutation.mutateAsync.mockReset();
  hooks.mutation.mutateAsync.mockResolvedValue({});
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('processor register filters', () => {
  beforeEach(() => {
    hooks.processors.data = [
      processor({
        id: 'p1',
        name: 'Ativo com subcontratante',
        status: 'active',
        risk_level: 'high',
        subprocessors: ['Sinais Lda'],
      }),
      processor({
        id: 'p2',
        name: 'Rascunho sem subcontratante',
        status: 'draft',
        risk_level: 'low',
      }),
    ];
  });

  it('narrows by status, by risk and by the PRESENCE of subprocessors, independently', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-processor-status-filter', 'active');
    expect(shows('Ativo com subcontratante')).toBe(true);
    expect(shows('Rascunho sem subcontratante')).toBe(false);

    fireEvent.click(clearFor('privacy-processor-status-filter'));
    setFilter('privacy-processor-risk-filter', 'low');
    expect(shows('Rascunho sem subcontratante')).toBe(true);
    expect(shows('Ativo com subcontratante')).toBe(false);

    fireEvent.click(clearFor('privacy-processor-risk-filter'));
    setFilter('privacy-processor-subprocessor-filter', 'with');
    expect(shows('Ativo com subcontratante')).toBe(true);
    expect(shows('Rascunho sem subcontratante')).toBe(false);

    setFilter('privacy-processor-subprocessor-filter', 'without');
    expect(shows('Rascunho sem subcontratante')).toBe(true);
    expect(shows('Ativo com subcontratante')).toBe(false);
  });

  it('combines axes rather than replacing one with the next', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-processor-status-filter', 'active');
    // A combination no record satisfies must produce nothing, not fall back to the last axis.
    setFilter('privacy-processor-risk-filter', 'low');
    expect(shows('Ativo com subcontratante')).toBe(false);
    expect(shows('Rascunho sem subcontratante')).toBe(false);
  });

  it('clears every axis at once, and offers nothing to clear until one is set', () => {
    renderWithProviders(<PrivacyComplianceSection />);
    const clear = clearFor('privacy-processor-status-filter');

    expect(clear.disabled).toBe(true);

    setFilter('privacy-processor-status-filter', 'active');
    setFilter('privacy-processor-risk-filter', 'high');
    setFilter('privacy-processor-subprocessor-filter', 'with');
    fireEvent.change(control('privacy-processor-search'), { target: { value: 'Ativo' } });
    expect(clear.disabled).toBe(false);

    fireEvent.click(clear);

    expect((control('privacy-processor-status-filter') as HTMLSelectElement).value).toBe('all');
    expect((control('privacy-processor-risk-filter') as HTMLSelectElement).value).toBe('all');
    expect((control('privacy-processor-subprocessor-filter') as HTMLSelectElement).value).toBe(
      'all',
    );
    expect((control('privacy-processor-search') as HTMLInputElement).value).toBe('');
    expect(clear.disabled).toBe(true);
    expect(shows('Ativo com subcontratante')).toBe(true);
    expect(shows('Rascunho sem subcontratante')).toBe(true);
  });
});

describe('DPIA register filters', () => {
  beforeEach(() => {
    hooks.dpias.data = [
      dpiaRecord({
        id: 'd1',
        title: 'Com prova e revisão vencida',
        evidence_receipts: [
          {
            id: 'r1',
            evidence_type: 'review',
            recorded_at: '2026-07-02T11:00:00Z',
            recorded_by: 'dpo',
            notes: '',
            authority_filing_completed: false,
            legal_review_accepted: false,
            legal_certification_completed: false,
            external_delivery_completed: false,
            dpia_completed: false,
            compliance_certification_completed: false,
          },
        ],
        advisory_review: {
          ...advisory({ status: 'overdue', days_until_due: -4 }),
          authority_filing_claimed: false,
          legal_acceptance_claimed: false,
          legal_certification_claimed: false,
          external_delivery_claimed: false,
          completion_claimed: false,
          compliance_certification_claimed: false,
        },
      }),
      dpiaRecord({ id: 'd2', title: 'Sem prova e revisão em dia' }),
    ];
  });

  it('narrows by the presence of evidence receipts', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-dpia-evidence-filter', 'with');
    expect(shows('Com prova e revisão vencida')).toBe(true);
    expect(shows('Sem prova e revisão em dia')).toBe(false);

    setFilter('privacy-dpia-evidence-filter', 'without');
    expect(shows('Sem prova e revisão em dia')).toBe(true);
    expect(shows('Com prova e revisão vencida')).toBe(false);
  });

  it('narrows by advisory review state, which is not the record status', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-dpia-review-filter', 'overdue');
    expect(shows('Com prova e revisão vencida')).toBe(true);
    expect(shows('Sem prova e revisão em dia')).toBe(false);

    // Both records are `draft`: a review filter reading `status` would have kept both.
    setFilter('privacy-dpia-review-filter', 'current');
    expect(shows('Sem prova e revisão em dia')).toBe(true);
    expect(shows('Com prova e revisão vencida')).toBe(false);
  });

  it('clears its own axes, including the two only the DPIA register has', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-dpia-evidence-filter', 'with');
    setFilter('privacy-dpia-review-filter', 'overdue');
    fireEvent.click(clearFor('privacy-dpia-review-filter'));

    expect((control('privacy-dpia-evidence-filter') as HTMLSelectElement).value).toBe('all');
    expect((control('privacy-dpia-review-filter') as HTMLSelectElement).value).toBe('all');
    expect(shows('Sem prova e revisão em dia')).toBe(true);
  });
});

describe('breach playbook register filters', () => {
  beforeEach(() => {
    hooks.breaches.data = [
      breachPlaybook({
        id: 'b1',
        title: 'Com simulacro registado',
        status: 'active',
        risk_level: 'critical',
        evidence_receipts: [
          {
            id: 'br1',
            evidence_type: 'drill',
            recorded_at: '2026-07-02T11:00:00Z',
            recorded_by: 'dpo',
            notes: '',
            authority_notified: false,
            subjects_notified: false,
          },
        ],
        advisory_review: advisory({ status: 'due_soon', days_until_due: 5 }),
      }),
      breachPlaybook({ id: 'b2', title: 'Sem qualquer prova' }),
    ];
  });

  it('narrows by status, risk, review state and evidence presence', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-breach-status', 'active');
    expect(shows('Sem qualquer prova')).toBe(false);
    fireEvent.click(clearFor('privacy-breach-status'));

    setFilter('privacy-breach-risk', 'critical');
    expect(shows('Com simulacro registado')).toBe(true);
    expect(shows('Sem qualquer prova')).toBe(false);
    fireEvent.click(clearFor('privacy-breach-risk'));

    setFilter('privacy-breach-review-filter', 'due_soon');
    expect(shows('Com simulacro registado')).toBe(true);
    expect(shows('Sem qualquer prova')).toBe(false);
    fireEvent.click(clearFor('privacy-breach-review-filter'));

    setFilter('privacy-breach-evidence-filter', 'without');
    expect(shows('Sem qualquer prova')).toBe(true);
    expect(shows('Com simulacro registado')).toBe(false);
  });

  it('restores the whole register when cleared', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-breach-evidence-filter', 'with');
    setFilter('privacy-breach-status', 'active');
    fireEvent.click(clearFor('privacy-breach-status'));

    expect(shows('Com simulacro registado')).toBe(true);
    expect(shows('Sem qualquer prova')).toBe(true);
    expect(clearFor('privacy-breach-status').disabled).toBe(true);
  });
});

describe('transfer control register filters', () => {
  beforeEach(() => {
    hooks.transfers.data = [
      transferControl({
        id: 't1',
        name: 'Acesso do Reino Unido',
        destination_country: 'Reino Unido',
        status: 'active',
        advisory_review: advisory({ status: 'no_receipt', last_reviewed_at: undefined }),
      }),
      transferControl({ id: 't2', name: 'Acesso do Brasil', destination_country: 'Brasil' }),
    ];
  });

  it('offers only the destinations the loaded rows actually have, and filters by one', () => {
    renderWithProviders(<PrivacyComplianceSection />);
    const destination = control('privacy-transfer-destination-filter') as HTMLSelectElement;

    const offered = [...destination.options].map((option) => option.value);
    // `all` plus exactly the two loaded countries — never a static country list, which would
    // offer destinations no record uses.
    expect(offered).toEqual(['all', 'Brasil', 'Reino Unido']);

    setFilter('privacy-transfer-destination-filter', 'Brasil');
    expect(shows('Acesso do Brasil')).toBe(true);
    expect(shows('Acesso do Reino Unido')).toBe(false);
  });

  it('narrows by review state and clears both axes together', () => {
    renderWithProviders(<PrivacyComplianceSection />);

    setFilter('privacy-transfer-review-filter', 'no_receipt');
    expect(shows('Acesso do Reino Unido')).toBe(true);
    expect(shows('Acesso do Brasil')).toBe(false);

    setFilter('privacy-transfer-destination-filter', 'Reino Unido');
    fireEvent.click(clearFor('privacy-transfer-review-filter'));

    expect((control('privacy-transfer-review-filter') as HTMLSelectElement).value).toBe('all');
    expect((control('privacy-transfer-destination-filter') as HTMLSelectElement).value).toBe('all');
    expect(shows('Acesso do Brasil')).toBe(true);
  });
});

describe('retention policy register filters', () => {
  beforeEach(() => {
    hooks.retentionPolicies.data = [
      retentionPolicy({
        id: 'r1',
        name: 'Arquivo ativo',
        status: 'active',
        active: true,
        disposal_action: 'archive',
      }),
      retentionPolicy({
        id: 'r2',
        name: 'Revisão suspensa',
        status: 'suspended',
        active: false,
        disposal_action: 'review',
      }),
    ];
  });

  it('narrows by status, by disposal action and by whether the policy is in force', () => {
    renderWithProviders(<PrivacyComplianceSection />);
    openRetentionTab();

    setFilter('privacy-retention-status', 'suspended');
    expect(shows('Revisão suspensa')).toBe(true);
    expect(shows('Arquivo ativo')).toBe(false);
    fireEvent.click(clearFor('privacy-retention-status'));

    // The disposal action is what a policy DOES; conflating it with the status would be the
    // difference between "archive" and "review" on a destructive schedule.
    setFilter('privacy-retention-disposal-filter', 'archive');
    expect(shows('Arquivo ativo')).toBe(true);
    expect(shows('Revisão suspensa')).toBe(false);
    fireEvent.click(clearFor('privacy-retention-disposal-filter'));

    setFilter('privacy-retention-active-filter', 'without');
    expect(shows('Revisão suspensa')).toBe(true);
    expect(shows('Arquivo ativo')).toBe(false);
  });

  it('clears every retention axis together', () => {
    renderWithProviders(<PrivacyComplianceSection />);
    openRetentionTab();

    setFilter('privacy-retention-status', 'active');
    setFilter('privacy-retention-disposal-filter', 'archive');
    setFilter('privacy-retention-active-filter', 'with');
    fireEvent.click(clearFor('privacy-retention-status'));

    expect((control('privacy-retention-status') as HTMLSelectElement).value).toBe('all');
    expect((control('privacy-retention-disposal-filter') as HTMLSelectElement).value).toBe('all');
    expect((control('privacy-retention-active-filter') as HTMLSelectElement).value).toBe('all');
    expect(shows('Arquivo ativo')).toBe(true);
    expect(shows('Revisão suspensa')).toBe(true);
  });
});
