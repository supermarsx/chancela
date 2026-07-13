import { useMemo, useState, type FormEvent } from 'react';
import {
  useCreatePrivacyBreachPlaybook,
  useCreatePrivacyDpia,
  useCreatePrivacyProcessor,
  useCreatePrivacyRetentionPolicy,
  useCreatePrivacyTransferControl,
  useClosePrivacyRetentionExecutionReview,
  useDryRunPrivacyRetentionPolicy,
  usePatchPrivacyBreachPlaybook,
  usePatchPrivacyDpia,
  usePatchPrivacyProcessor,
  usePatchPrivacyRetentionPolicy,
  usePatchPrivacyTransferControl,
  usePrivacyBreachPlaybooks,
  usePrivacyDpias,
  usePrivacyRetentionDueCandidates,
  usePrivacyProcessors,
  usePrivacyRetentionExecutions,
  usePrivacyRetentionPolicies,
  usePrivacyTransferControls,
} from '../../api/hooks';
import {
  type BreachPlaybookView,
  type BreachEvidenceKind,
  type CloseRetentionExecutionReviewBody,
  type CreateBreachPlaybookBody,
  PRIVACY_RECORD_STATUSES,
  PRIVACY_RISK_LEVELS,
  RETENTION_DISPOSAL_ACTIONS,
  RETENTION_EXECUTION_STATUSES,
  RETENTION_POLICY_STATUSES,
  type CreateDpiaRecordBody,
  type CreateProcessorRecordBody,
  type CreateRetentionPolicyBody,
  type CreateTransferControlBody,
  type DpiaEvidenceKind,
  type DpiaRecordView,
  type PatchBreachPlaybookBody,
  type PatchDpiaRecordBody,
  type PatchProcessorRecordBody,
  type PatchRetentionPolicyBody,
  type PatchTransferControlBody,
  type PrivacyAdvisoryReviewStatus,
  type PrivacyAdvisoryReviewSummary,
  type PrivacyRecordStatus,
  type PrivacyRiskLevel,
  type ProcessorRecordView,
  type RetentionDisposalAction,
  type RetentionDryRunBody,
  type RetentionDryRunReport,
  type RetentionDueCandidate,
  type RetentionDueCandidatesReport,
  type RetentionDueCandidateFinding,
  type RetentionEvidenceState,
  type RetentionExecutionOutcome,
  type RetentionExecutionRecord,
  type RetentionExecutionStatus,
  type RetentionPolicyStatus,
  type RetentionPolicyView,
  type RetentionReviewClosureDecision,
  type TransferControlView,
} from '../../api/types';
import { useT, type MessageKey, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  SkeletonTable,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { PermissionDeniedNote, useCan } from '../session/permissions';

type RegisterKind = 'processor' | 'dpia';
type RegisterRecord = ProcessorRecordView | DpiaRecordView;
type PrivacyCreateBody = CreateProcessorRecordBody | CreateDpiaRecordBody;
type PrivacyPatchBody = PatchProcessorRecordBody | PatchDpiaRecordBody;

interface RegisterFormState {
  primary: string;
  purpose: string;
  legalBasis: string;
  dataCategories: string;
  subprocessors: string;
  riskLevel: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  evidenceType: DpiaEvidenceKind;
  evidenceNotes: string;
}

interface BreachPlaybookFormState {
  title: string;
  scope: string;
  detectionChannels: string;
  containmentSteps: string;
  notificationRoles: string;
  authorityNotificationWindow: string;
  subjectNotificationGuidance: string;
  riskLevel: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  reviewNotes: string;
  evidenceType: BreachEvidenceKind;
  evidenceNotes: string;
}

interface TransferControlFormState {
  name: string;
  purpose: string;
  legalBasis: string;
  dataCategories: string;
  recipient: string;
  destinationCountry: string;
  transferMechanism: string;
  safeguards: string;
  riskLevel: PrivacyRiskLevel;
  status: PrivacyRecordStatus;
  reviewNotes: string;
  evidenceNotes: string;
}

interface RetentionPolicyFormState {
  name: string;
  scope: string;
  category: string;
  scheduleId: string;
  retentionPeriod: string;
  legalBasis: string;
  disposalAction: RetentionDisposalAction;
  status: RetentionPolicyStatus;
  active: boolean;
  notes: string;
}

interface RetentionDryRunFormState {
  scope: string;
  category: string;
  recordId: string;
}

const EMPTY_FORM: RegisterFormState = {
  primary: '',
  purpose: '',
  legalBasis: '',
  dataCategories: '',
  subprocessors: '',
  riskLevel: 'medium',
  status: 'draft',
  evidenceType: 'review',
  evidenceNotes: '',
};

const EMPTY_BREACH_FORM: BreachPlaybookFormState = {
  title: '',
  scope: '',
  detectionChannels: '',
  containmentSteps: '',
  notificationRoles: '',
  authorityNotificationWindow: '',
  subjectNotificationGuidance: '',
  riskLevel: 'high',
  status: 'draft',
  reviewNotes: '',
  evidenceType: 'review',
  evidenceNotes: '',
};

const EMPTY_TRANSFER_FORM: TransferControlFormState = {
  name: '',
  purpose: '',
  legalBasis: '',
  dataCategories: '',
  recipient: '',
  destinationCountry: '',
  transferMechanism: '',
  safeguards: '',
  riskLevel: 'medium',
  status: 'draft',
  reviewNotes: '',
  evidenceNotes: '',
};

const EMPTY_RETENTION_FORM: RetentionPolicyFormState = {
  name: '',
  scope: '',
  category: '',
  scheduleId: '',
  retentionPeriod: '',
  legalBasis: '',
  disposalAction: 'review',
  status: 'draft',
  active: true,
  notes: '',
};

const EMPTY_RETENTION_DRY_RUN_FORM: RetentionDryRunFormState = {
  scope: '',
  category: '',
  recordId: '',
};

const STATUS_LABELS: Record<PrivacyRecordStatus, string> = {
  draft: 'Rascunho',
  active: 'Ativo',
  under_review: 'Em revisão',
  retired: 'Retirado',
};

const RISK_LABELS: Record<PrivacyRiskLevel, string> = {
  low: 'Baixo',
  medium: 'Médio',
  high: 'Elevado',
  critical: 'Crítico',
};

const ADVISORY_REVIEW_LABELS: Record<PrivacyAdvisoryReviewStatus, string> = {
  no_receipt: 'Sem recibo local',
  current: 'Revisão atual',
  due_soon: 'Revisão breve',
  overdue: 'Revisão vencida',
  under_review: 'Em revisão local',
};

const RETENTION_STATUS_LABEL_KEYS: Record<RetentionPolicyStatus, MessageKey> = {
  draft: 'settings.privacy.retention.status.draft',
  active: 'settings.privacy.retention.status.active',
  suspended: 'settings.privacy.retention.status.suspended',
  retired: 'settings.privacy.retention.status.retired',
};

const RETENTION_DISPOSAL_LABEL_KEYS: Record<RetentionDisposalAction, MessageKey> = {
  review: 'settings.privacy.retention.disposal.review',
  archive: 'settings.privacy.retention.disposal.archive',
  anonymize: 'settings.privacy.retention.disposal.anonymize',
  delete: 'settings.privacy.retention.disposal.delete',
  legal_hold: 'settings.privacy.retention.disposal.legal_hold',
  no_action: 'settings.privacy.retention.disposal.no_action',
};

const RETENTION_EXECUTION_STATUS_LABELS: Record<RetentionExecutionStatus, string> = {
  awaiting_review: 'A aguardar revisão',
  blocked: 'Bloqueado',
  executed: 'Executado',
};

const RETENTION_BOUNDED_EVIDENCE_SUPPRESSED_STATES: ReadonlySet<RetentionEvidenceState> = new Set([
  'blocked',
  'bounded_archive_recorded',
  'bounded_no_action_recorded',
  'prior_bounded_evidence_available',
]);

const RETENTION_REVIEW_CLOSURE_FALSE_FLAGS = {
  destructive_disposal_completed: false,
  full_erasure_completed: false,
  legal_hold_mutated: false,
  retention_policy_mutated: false,
} as const;

const statusOptions = [
  { value: 'all', label: 'Todos os estados' },
  ...PRIVACY_RECORD_STATUSES.map((status) => ({ value: status, label: STATUS_LABELS[status] })),
];

const riskOptions = [
  { value: 'all', label: 'Todos os riscos' },
  ...PRIVACY_RISK_LEVELS.map((risk) => ({ value: risk, label: RISK_LABELS[risk] })),
];

const statusSelectOptions = PRIVACY_RECORD_STATUSES.map((status) => ({
  value: status,
  label: STATUS_LABELS[status],
}));

const riskSelectOptions = PRIVACY_RISK_LEVELS.map((risk) => ({
  value: risk,
  label: RISK_LABELS[risk],
}));

const breachEvidenceOptions: { value: BreachEvidenceKind; label: string }[] = [
  { value: 'review', label: 'Revisão' },
  { value: 'drill', label: 'Exercício' },
];

function retentionStatusLabel(t: TFunction, status: RetentionPolicyStatus): string {
  return t(RETENTION_STATUS_LABEL_KEYS[status]);
}

function retentionDisposalLabel(t: TFunction, action: RetentionDisposalAction): string {
  return t(RETENTION_DISPOSAL_LABEL_KEYS[action]);
}

function retentionExecutionStatusLabel(status: RetentionExecutionStatus): string {
  return RETENTION_EXECUTION_STATUS_LABELS[status];
}

function retentionReviewClosureDecisionForOutcome(
  outcome: RetentionExecutionOutcome,
): RetentionReviewClosureDecision {
  if (outcome === 'manual_review_required') return 'review_evidence_acknowledged';
  if (
    outcome === 'bounded_archive_recorded' ||
    outcome === 'bounded_no_action_recorded' ||
    outcome === 'already_executed'
  ) {
    return 'bounded_evidence_acknowledged';
  }
  return 'blocked_evidence_acknowledged';
}

function retentionReviewClosureNote(decision: RetentionReviewClosureDecision): string {
  if (decision === 'bounded_evidence_acknowledged') {
    return 'Revisão operacional registada para evidência delimitada; esta ação não altera registos fonte.';
  }
  if (decision === 'blocked_evidence_acknowledged') {
    return 'Revisão operacional registada para evidência bloqueada; acompanhamento separado permanece fora desta ação.';
  }
  return 'Revisão operacional registada para evidência retida; esta ação não altera registos fonte.';
}

function retentionReviewClosureBody(
  record: RetentionExecutionRecord,
): CloseRetentionExecutionReviewBody {
  const reviewClosureDecision = retentionReviewClosureDecisionForOutcome(record.outcome);
  return {
    review_closure_decision: reviewClosureDecision,
    review_closure_note: retentionReviewClosureNote(reviewClosureDecision),
    review_closure_evidence: [
      {
        label: 'fila_operacional',
        value: 'registo revisto na interface de configuracoes',
      },
      {
        label: 'alvo',
        value: record.candidate.record_id?.trim() ? record.candidate.record_id : record.id,
      },
    ],
    ...RETENTION_REVIEW_CLOSURE_FALSE_FLAGS,
  };
}

function primaryValue(kind: RegisterKind, record: RegisterRecord): string {
  return kind === 'processor'
    ? (record as ProcessorRecordView).name
    : (record as DpiaRecordView).title;
}

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function splitList(value: string): string[] {
  const items = value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return [...new Set(items)];
}

function joinList(items: string[]): string {
  return items.join('\n');
}

function formFromRecord(kind: RegisterKind, record: RegisterRecord): RegisterFormState {
  return {
    primary: primaryValue(kind, record),
    purpose: record.purpose,
    legalBasis: record.legal_basis,
    dataCategories: joinList(record.data_categories),
    subprocessors: joinList(record.subprocessors),
    riskLevel: record.risk_level,
    status: record.status,
    evidenceType: 'review',
    evidenceNotes: '',
  };
}

function breachFormFromRecord(record: BreachPlaybookView): BreachPlaybookFormState {
  return {
    title: record.title,
    scope: record.scope,
    detectionChannels: joinList(record.detection_channels),
    containmentSteps: joinList(record.containment_steps),
    notificationRoles: joinList(record.notification_roles),
    authorityNotificationWindow: record.authority_notification_window ?? '',
    subjectNotificationGuidance: record.subject_notification_guidance ?? '',
    riskLevel: record.risk_level,
    status: record.status,
    reviewNotes: record.review_notes ?? '',
    evidenceType: 'review',
    evidenceNotes: '',
  };
}

function transferFormFromRecord(record: TransferControlView): TransferControlFormState {
  return {
    name: record.name,
    purpose: record.purpose,
    legalBasis: record.legal_basis,
    dataCategories: joinList(record.data_categories),
    recipient: record.recipient,
    destinationCountry: record.destination_country,
    transferMechanism: record.transfer_mechanism,
    safeguards: joinList(record.safeguards),
    riskLevel: record.risk_level,
    status: record.status,
    reviewNotes: record.review_notes ?? '',
    evidenceNotes: '',
  };
}

function retentionFormFromRecord(record: RetentionPolicyView): RetentionPolicyFormState {
  return {
    name: record.name,
    scope: record.scope,
    category: record.category,
    scheduleId: record.schedule_id,
    retentionPeriod: record.retention_period,
    legalBasis: record.legal_basis,
    disposalAction: record.disposal_action,
    status: record.status,
    active: record.active,
    notes: record.notes ?? '',
  };
}

function createBody(kind: RegisterKind, form: RegisterFormState): PrivacyCreateBody {
  const base = {
    purpose: form.purpose.trim(),
    legal_basis: form.legalBasis.trim(),
    data_categories: splitList(form.dataCategories),
    subprocessors: splitList(form.subprocessors),
    risk_level: form.riskLevel,
    status: form.status,
  };
  if (kind === 'processor') {
    return { ...base, name: form.primary.trim() };
  }
  return {
    ...base,
    title: form.primary.trim(),
    evidence_receipt: optionalText(form.evidenceNotes)
      ? {
          evidence_type: form.evidenceType,
          notes: form.evidenceNotes.trim(),
          authority_filing_completed: false,
          legal_review_accepted: false,
          legal_certification_completed: false,
          external_delivery_completed: false,
          dpia_completed: false,
          compliance_certification_completed: false,
        }
      : undefined,
  };
}

function patchBody(kind: RegisterKind, form: RegisterFormState): PrivacyPatchBody {
  const body = createBody(kind, form);
  return body;
}

function optionalText(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function breachCreateBody(form: BreachPlaybookFormState): CreateBreachPlaybookBody {
  return {
    title: form.title.trim(),
    scope: form.scope.trim(),
    detection_channels: splitList(form.detectionChannels),
    containment_steps: splitList(form.containmentSteps),
    notification_roles: splitList(form.notificationRoles),
    authority_notification_window: optionalText(form.authorityNotificationWindow),
    subject_notification_guidance: optionalText(form.subjectNotificationGuidance),
    risk_level: form.riskLevel,
    status: form.status,
    review_notes: optionalText(form.reviewNotes),
    evidence_receipt: optionalText(form.evidenceNotes)
      ? {
          evidence_type: form.evidenceType,
          notes: form.evidenceNotes.trim(),
          authority_notified: false,
          subjects_notified: false,
        }
      : undefined,
  };
}

function transferCreateBody(form: TransferControlFormState): CreateTransferControlBody {
  return {
    name: form.name.trim(),
    purpose: form.purpose.trim(),
    legal_basis: form.legalBasis.trim(),
    data_categories: splitList(form.dataCategories),
    recipient: form.recipient.trim(),
    destination_country: form.destinationCountry.trim(),
    transfer_mechanism: form.transferMechanism.trim(),
    safeguards: splitList(form.safeguards),
    risk_level: form.riskLevel,
    status: form.status,
    review_notes: optionalText(form.reviewNotes),
    evidence_receipt: optionalText(form.evidenceNotes)
      ? {
          notes: form.evidenceNotes.trim(),
          transfer_approved: false,
          data_transfer_executed: false,
        }
      : undefined,
  };
}

function retentionCreateBody(form: RetentionPolicyFormState): CreateRetentionPolicyBody {
  return {
    name: form.name.trim(),
    scope: form.scope.trim(),
    category: form.category.trim(),
    schedule_id: form.scheduleId.trim(),
    retention_period: form.retentionPeriod.trim(),
    legal_basis: form.legalBasis.trim(),
    disposal_action: form.disposalAction,
    status: form.status,
    active: form.active,
    notes: optionalText(form.notes),
  };
}

function breachSearchText(record: BreachPlaybookView): string {
  return normalizeSearch(
    [
      record.title,
      record.scope,
      ...record.detection_channels,
      ...record.containment_steps,
      ...record.notification_roles,
      record.authority_notification_window ?? '',
      record.subject_notification_guidance ?? '',
      record.review_notes ?? '',
      record.risk_level,
      record.status,
    ].join(' '),
  );
}

function transferSearchText(record: TransferControlView): string {
  return normalizeSearch(
    [
      record.name,
      record.purpose,
      record.legal_basis,
      ...record.data_categories,
      record.recipient,
      record.destination_country,
      record.transfer_mechanism,
      ...record.safeguards,
      record.review_notes ?? '',
      record.risk_level,
      record.status,
    ].join(' '),
  );
}

function retentionSearchText(record: RetentionPolicyView): string {
  return normalizeSearch(
    [
      record.name,
      record.scope,
      record.category,
      record.schedule_id,
      record.retention_period,
      record.legal_basis,
      record.disposal_action,
      record.status,
      record.notes ?? '',
    ].join(' '),
  );
}

function retentionExecutionSearchText(record: RetentionExecutionRecord): string {
  return normalizeSearch(
    [
      record.id,
      record.actor,
      record.execution_intent,
      record.execution_status,
      record.operator_review_decision,
      record.decision_state,
      record.review_closure_decision ?? '',
      record.review_closed_by ?? '',
      record.review_closed_at ?? '',
      record.review_closure_note ?? '',
      ...(record.review_closure_evidence ?? []).flatMap((evidence) => [
        evidence.label,
        evidence.value,
      ]),
      record.outcome,
      record.evidence_state,
      record.evidence_next_step,
      record.block_reason,
      record.candidate.scope,
      record.candidate.category,
      record.candidate.record_id ?? '',
      record.requested_policy.id ?? '',
      record.requested_policy.name ?? '',
      record.requested_policy.scope ?? '',
      record.requested_policy.category ?? '',
      record.requested_policy.schedule_id ?? '',
      record.requested_policy.retention_period ?? '',
      record.requested_policy.disposal_action ?? '',
      record.workflow.status,
      record.workflow.next_step,
      ...record.workflow.blockers.flatMap((blocker) => [
        blocker.code,
        blocker.message,
        blocker.policy_id ?? '',
      ]),
      ...record.workflow.required_approvals.flatMap((approval) => [
        approval.code,
        approval.required_from,
        approval.reason,
      ]),
      ...record.legal_hold_blockers.flatMap((blocker) => [
        blocker.policy_id,
        blocker.name,
        blocker.schedule_id,
        blocker.retention_period,
        blocker.reason,
      ]),
      ...record.audit_evidence.flatMap((evidence) => [evidence.label, evidence.value]),
      record.approval?.approval_reference ?? '',
      record.approval?.approved_by ?? '',
      record.operator_notes ?? '',
      ...record.execution_result.reason_codes,
      record.execution_result.next_step,
      ...record.execution_result.blocker_metadata.flatMap((blocker) => [
        blocker.code,
        blocker.detail,
        blocker.policy_id ?? '',
      ]),
    ].join(' '),
  );
}

function retentionCandidateCanRecordNoActionEvidence(
  candidate: RetentionDueCandidate,
  queuedReview: RetentionExecutionRecord | undefined,
): boolean {
  return (
    candidate.disposal_action === 'no_action' &&
    candidate.destructive_action === false &&
    candidate.blockers.length === 0 &&
    candidate.legal_hold_blockers.length === 0 &&
    !queuedReview &&
    !candidate.prior_execution
  );
}

function retentionCandidateHasConcreteRecordId(candidate: RetentionDueCandidate): boolean {
  return candidate.record_id.trim().length > 0;
}

function retentionCandidateHasSuppressedEvidenceState(candidate: RetentionDueCandidate): boolean {
  return RETENTION_BOUNDED_EVIDENCE_SUPPRESSED_STATES.has(candidate.candidate_evidence_state);
}

function retentionCandidateCanRecordArchiveEvidence(
  candidate: RetentionDueCandidate,
  queuedReview: RetentionExecutionRecord | undefined,
): boolean {
  return (
    candidate.disposal_action === 'archive' &&
    retentionCandidateHasConcreteRecordId(candidate) &&
    candidate.destructive_action === false &&
    candidate.blockers.length === 0 &&
    candidate.legal_hold_blockers.length === 0 &&
    !queuedReview &&
    !candidate.prior_execution &&
    !retentionCandidateHasSuppressedEvidenceState(candidate)
  );
}

function recordSearchText(kind: RegisterKind, record: RegisterRecord): string {
  const dpiaReceiptText =
    kind === 'dpia'
      ? (record as DpiaRecordView).evidence_receipts
          .map((receipt) =>
            [receipt.evidence_type, receipt.recorded_by, receipt.notes ?? ''].join(' '),
          )
          .join(' ')
      : '';
  return normalizeSearch(
    [
      primaryValue(kind, record),
      record.purpose,
      record.legal_basis,
      ...record.data_categories,
      ...record.subprocessors,
      record.risk_level,
      record.status,
      dpiaReceiptText,
    ].join(' '),
  );
}

function riskTone(risk: PrivacyRiskLevel): 'neutral' | 'warn' | 'error' | 'ok' {
  if (risk === 'low') return 'ok';
  if (risk === 'high') return 'warn';
  if (risk === 'critical') return 'error';
  return 'neutral';
}

function statusTone(status: PrivacyRecordStatus): 'neutral' | 'warn' | 'ok' {
  if (status === 'active') return 'ok';
  if (status === 'under_review') return 'warn';
  return 'neutral';
}

function advisoryReviewTone(
  status: PrivacyAdvisoryReviewStatus,
): 'neutral' | 'accent' | 'warn' | 'ok' {
  if (status === 'current') return 'ok';
  if (status === 'due_soon') return 'accent';
  if (status === 'overdue' || status === 'under_review') return 'warn';
  return 'neutral';
}

function advisoryReviewDetail(review: PrivacyAdvisoryReviewSummary): string {
  if (review.status === 'no_receipt') return 'Sem recibo de revisão/exercício local.';
  if (review.status === 'under_review') return 'Estado local em revisão, sem conclusão legal.';
  const due = review.next_review_due_at
    ? `Próxima revisão local: ${review.next_review_due_at}.`
    : '';
  const last = review.last_reviewed_at ?? review.last_drill_at;
  const lastText = last ? `Última evidência: ${formatDateTime(last)}.` : '';
  return [due, lastText, 'Sem notificação, aprovação, execução ou certificação.']
    .filter(Boolean)
    .join(' ');
}

function AdvisoryReviewBadge({ review }: { review: PrivacyAdvisoryReviewSummary }) {
  return (
    <div className="stack--tight">
      <Badge tone={advisoryReviewTone(review.status)}>
        {ADVISORY_REVIEW_LABELS[review.status]}
      </Badge>
      <span className="muted">{advisoryReviewDetail(review)}</span>
    </div>
  );
}

function retentionStatusTone(status: RetentionPolicyStatus): 'neutral' | 'warn' | 'ok' {
  if (status === 'active') return 'ok';
  if (status === 'suspended') return 'warn';
  return 'neutral';
}

function retentionExecutionStatusTone(
  status: RetentionExecutionStatus,
): 'neutral' | 'warn' | 'error' | 'ok' {
  if (status === 'executed') return 'ok';
  if (status === 'blocked') return 'error';
  return 'warn';
}

function formatDateTime(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('pt-PT', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function latestReceipt<T extends { recorded_at: string }>(receipts: T[]): T | undefined {
  return [...receipts].sort((a, b) => b.recorded_at.localeCompare(a.recorded_at))[0];
}

function renderUnknownEvidence(value: unknown): string {
  if (value === null || value === undefined) return 'Sem detalhe';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map(renderUnknownEvidence).join(', ');
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== null && item !== undefined && item !== '')
      .map(([key, item]) => `${key}: ${renderUnknownEvidence(item)}`);
    return entries.length > 0 ? entries.join(' · ') : 'Sem detalhe';
  }
  return String(value);
}

function retentionFindingText(finding: RetentionDueCandidateFinding): string {
  if (typeof finding === 'string') return finding;
  return [
    finding.severity ? `severity: ${finding.severity}` : '',
    finding.code ? `code: ${finding.code}` : '',
    finding.message ? `message: ${finding.message}` : '',
  ]
    .filter(Boolean)
    .join(' · ');
}

function retentionQueuedReviewForCandidate(
  candidate: RetentionDueCandidate,
  records: RetentionExecutionRecord[],
): RetentionExecutionRecord | undefined {
  return records
    .filter(
      (record) =>
        record.execution_intent === 'review_only' &&
        record.execution_status === 'awaiting_review' &&
        record.candidate.scope === candidate.scope &&
        record.candidate.category === candidate.category &&
        record.candidate.record_id === candidate.record_id &&
        record.requested_policy.id === candidate.policy_id,
    )
    .sort((a, b) => a.requested_at.localeCompare(b.requested_at) || a.id.localeCompare(b.id))[0];
}

interface RetentionLegalHoldDisposalStatusSummary {
  dueCandidateLegalHoldBlockers: number;
  executionLegalHoldBlocks: number;
  openBlockedReviews: number;
}

function retentionLegalHoldDisposalStatusSummary(
  report: RetentionDueCandidatesReport | null,
  records: RetentionExecutionRecord[],
): RetentionLegalHoldDisposalStatusSummary {
  const dueCandidateLegalHoldBlockers =
    report?.candidates.filter((candidate) => candidate.legal_hold_blockers.length > 0).length ?? 0;
  const legalHoldBlockedExecutions = records.filter(
    (record) =>
      record.outcome === 'blocked_legal_hold' ||
      record.legal_hold_blockers.length > 0 ||
      record.workflow.blockers.some((blocker) => blocker.code === 'legal_hold_release'),
  );
  return {
    dueCandidateLegalHoldBlockers,
    executionLegalHoldBlocks: legalHoldBlockedExecutions.length,
    openBlockedReviews: legalHoldBlockedExecutions.filter(
      (record) => record.decision_state !== 'review_closed',
    ).length,
  };
}

function RetentionLegalHoldDisposalStatusPanel({
  report,
  records,
}: {
  report: RetentionDueCandidatesReport | null;
  records: RetentionExecutionRecord[];
}) {
  const summary = retentionLegalHoldDisposalStatusSummary(report, records);
  return (
    <Card title="Estado local de legal hold e descarte">
      <div className="stack">
        <InlineWarning tone="info" title="Evidência operacional local">
          Este resumo mostra apenas estado/revisão local para operadores. Não aprova descarte, não
          resolve candidatos, não remove retenções legais e não declara cumprimento legal.
        </InlineWarning>
        <dl className="deflist">
          <div>
            <dt>Candidatos bloqueados por legal hold</dt>
            <dd>{summary.dueCandidateLegalHoldBlockers}</dd>
          </div>
          <div>
            <dt>Registos de execução bloqueados por legal hold</dt>
            <dd>{summary.executionLegalHoldBlocks}</dd>
          </div>
          <div>
            <dt>Revisões bloqueadas ainda abertas</dt>
            <dd>{summary.openBlockedReviews}</dd>
          </div>
          <div>
            <dt>Flags de limite</dt>
            <dd>
              destructive_disposal_completed: false · disposal_approved: false ·
              legal_compliance_claimed: false
            </dd>
          </div>
        </dl>
        <p className="field__hint">
          A origem destes números é a varredura GET de candidatos vencidos e a fila de execução de
          retenção já persistida; este painel não faz chamadas de mutação.
        </p>
      </div>
    </Card>
  );
}

function RegisterForm({
  kind,
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  kind: RegisterKind;
  form: RegisterFormState;
  setForm: (next: RegisterFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const idPrefix = `privacy-${kind}-${editing ? 'edit' : 'new'}`;
  const primaryLabel = kind === 'processor' ? 'Nome do processador' : 'Título da DPIA';
  const parsedCategories = splitList(form.dataCategories);
  const canSubmit =
    form.primary.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    parsedCategories.length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={primaryLabel} htmlFor={`${idPrefix}-primary`}>
        <Input
          id={`${idPrefix}-primary`}
          value={form.primary}
          onChange={(e) => setForm({ ...form, primary: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field label="Finalidade" htmlFor={`${idPrefix}-purpose`}>
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>

      <Field label="Base legal" htmlFor={`${idPrefix}-legal-basis`}>
        <Input
          id={`${idPrefix}-legal-basis`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field
        label="Categorias de dados"
        htmlFor={`${idPrefix}-data-categories`}
        hint="Uma categoria por linha ou separada por vírgulas."
      >
        <TextArea
          id={`${idPrefix}-data-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>

      <Field
        label="Subprocessadores"
        htmlFor={`${idPrefix}-subprocessors`}
        hint="Opcional. Uma entidade por linha ou separada por vírgulas."
      >
        <TextArea
          id={`${idPrefix}-subprocessors`}
          value={form.subprocessors}
          onChange={(e) => setForm({ ...form, subprocessors: e.target.value })}
          rows={3}
        />
      </Field>

      <div className="api-key-rate-grid">
        <Field label="Risco" htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptions}
          />
        </Field>
        <Field label="Estado" htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptions}
          />
        </Field>
      </div>

      {kind === 'dpia' ? (
        <>
          <InlineWarning tone="info" title="Evidência de operador">
            Esta evidência regista apenas revisão ou exercício local da DPIA. Não submete à
            autoridade, não aceita revisão legal, não entrega externamente, não conclui a DPIA e não
            certifica conformidade.
          </InlineWarning>
          <div className="api-key-rate-grid">
            <Field label="Tipo de evidência" htmlFor={`${idPrefix}-evidence-type`}>
              <Select
                id={`${idPrefix}-evidence-type`}
                value={form.evidenceType}
                onChange={(e) =>
                  setForm({ ...form, evidenceType: e.target.value as DpiaEvidenceKind })
                }
                options={breachEvidenceOptions}
              />
            </Field>
            <Field label="Notas de evidência" htmlFor={`${idPrefix}-evidence-notes`}>
              <TextArea
                id={`${idPrefix}-evidence-notes`}
                value={form.evidenceNotes}
                onChange={(e) => setForm({ ...form, evidenceNotes: e.target.value })}
                rows={2}
              />
            </Field>
          </div>
        </>
      ) : null}

      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          Cancelar
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving ? 'A guardar' : editing ? 'Guardar alterações' : 'Criar registo'}
        </Button>
      </div>
    </form>
  );
}

function RegisterPanel({
  kind,
  title,
  lede,
  records,
  loading,
  error,
  saving,
  onCreate,
  onPatch,
}: {
  kind: RegisterKind;
  title: string;
  lede: string;
  records: RegisterRecord[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: PrivacyCreateBody) => Promise<RegisterRecord>;
  onPatch: (id: string, body: PrivacyPatchBody) => Promise<RegisterRecord>;
}) {
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [form, setForm] = useState<RegisterFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      return q.length === 0 || recordSearchText(kind, record).includes(q);
    });
  }, [kind, records, riskFilter, search, statusFilter]);

  function startCreate() {
    setEditingId(null);
    setForm(EMPTY_FORM);
  }

  function startEdit(record: RegisterRecord) {
    setEditingId(record.id);
    setForm(formFromRecord(kind, record));
  }

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, patchBody(kind, form));
        toast.success('Registo de privacidade atualizado.');
      } else {
        await onCreate(createBody(kind, form));
        toast.success('Registo de privacidade criado.');
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  async function patchOne(id: string, body: PrivacyPatchBody) {
    try {
      await onPatch(id, body);
      toast.success('Registo de privacidade atualizado.');
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? 'Editar registo' : 'Novo registo'}>
          <RegisterForm
            kind={kind}
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}

      <Card
        title={title}
        actions={
          <Button type="button" variant="primary" icon={<Icon.Plus />} onClick={startCreate}>
            Novo registo
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{lede}</p>

          <div className="filter">
            <Field label="Pesquisar" htmlFor={`privacy-${kind}-search`}>
              <Input
                id={`privacy-${kind}-search`}
                value={search}
                placeholder="Nome, finalidade, base legal ou categoria"
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label="Estado" htmlFor={`privacy-${kind}-status-filter`}>
              <Select
                id={`privacy-${kind}-status-filter`}
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusOptions}
              />
            </Field>
            <Field label="Risco" htmlFor={`privacy-${kind}-risk-filter`}>
              <Select
                id={`privacy-${kind}-risk-filter`}
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskOptions}
              />
            </Field>
          </div>

          {loading ? (
            <SkeletonTable cols={9} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title="Sem registos">
              <p>Ainda não existem registos nesta área de privacidade.</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title="Sem resultados">
              <p>Altere a pesquisa ou os filtros para voltar a ver registos.</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{kind === 'processor' ? 'Processador' : 'DPIA'}</th>
                  <th>Finalidade</th>
                  <th>Categorias</th>
                  <th>Subprocessadores</th>
                  {kind === 'dpia' ? <th>Evidência</th> : null}
                  <th>Risco</th>
                  <th>Estado</th>
                  <th>Atualizado</th>
                  <th>Ação</th>
                </tr>
              }
            >
              {filtered.map((record) => {
                const label = primaryValue(kind, record);
                const dpiaRecord = kind === 'dpia' ? (record as DpiaRecordView) : null;
                const dpiaReceipt = dpiaRecord ? latestReceipt(dpiaRecord.evidence_receipts) : null;
                return (
                  <tr key={record.id}>
                    <td>{label}</td>
                    <td>{record.purpose}</td>
                    <td>{record.data_categories.join(', ')}</td>
                    <td>
                      {record.subprocessors.length > 0 ? record.subprocessors.join(', ') : '—'}
                    </td>
                    {dpiaRecord ? (
                      <td>
                        {dpiaReceipt ? (
                          <>
                            {dpiaReceipt.evidence_type === 'drill' ? 'Exercício' : 'Revisão'} por{' '}
                            {dpiaReceipt.recorded_by}
                            <br />
                            <span className="muted">
                              {formatDateTime(dpiaReceipt.recorded_at)} · Sem submissão à autoridade
                              · Sem certificação de conformidade
                            </span>
                          </>
                        ) : (
                          <span className="muted">Sem recibo</span>
                        )}
                      </td>
                    ) : null}
                    <td>
                      <span className="row-wrap">
                        <Badge tone={riskTone(record.risk_level)}>
                          {RISK_LABELS[record.risk_level]}
                        </Badge>
                        <Select
                          aria-label={`Risco de ${label}`}
                          value={record.risk_level}
                          disabled={saving}
                          onChange={(e) =>
                            patchOne(record.id, {
                              risk_level: e.target.value as PrivacyRiskLevel,
                            })
                          }
                          options={riskSelectOptions}
                        />
                      </span>
                    </td>
                    <td>
                      <span className={dpiaRecord ? 'stack--tight' : 'row-wrap'}>
                        <Badge tone={statusTone(record.status)}>
                          {STATUS_LABELS[record.status]}
                        </Badge>
                        {dpiaRecord ? (
                          <AdvisoryReviewBadge review={dpiaRecord.advisory_review} />
                        ) : null}
                        <Select
                          aria-label={`Estado de ${label}`}
                          value={record.status}
                          disabled={saving}
                          onChange={(e) =>
                            patchOne(record.id, {
                              status: e.target.value as PrivacyRecordStatus,
                            })
                          }
                          options={statusSelectOptions}
                        />
                      </span>
                    </td>
                    <td>
                      {formatDateTime(record.updated_at)}
                      <br />
                      <span className="muted">{record.updated_by}</span>
                    </td>
                    <td className="users-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Pencil />}
                        disabled={saving}
                        onClick={() => startEdit(record)}
                      >
                        Editar
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}
        </div>
      </Card>
    </div>
  );
}

function BreachPlaybookForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  form: BreachPlaybookFormState;
  setForm: (next: BreachPlaybookFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-breach-${editing ? 'edit' : 'new'}`;
  const canSubmit =
    form.title.trim().length > 0 &&
    form.scope.trim().length > 0 &&
    splitList(form.detectionChannels).length > 0 &&
    splitList(form.containmentSteps).length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.breach.field.title')} htmlFor={`${idPrefix}-title`}>
        <Input
          id={`${idPrefix}-title`}
          value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field label={t('settings.privacy.breach.field.scope')} htmlFor={`${idPrefix}-scope`}>
        <Input
          id={`${idPrefix}-scope`}
          value={form.scope}
          onChange={(e) => setForm({ ...form, scope: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.detection')}
        htmlFor={`${idPrefix}-detection`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-detection`}
          value={form.detectionChannels}
          onChange={(e) => setForm({ ...form, detectionChannels: e.target.value })}
          rows={3}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.containment')}
        htmlFor={`${idPrefix}-containment`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-containment`}
          value={form.containmentSteps}
          onChange={(e) => setForm({ ...form, containmentSteps: e.target.value })}
          rows={3}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.roles')}
        htmlFor={`${idPrefix}-roles`}
        hint={t('settings.privacy.listHintOptional')}
      >
        <TextArea
          id={`${idPrefix}-roles`}
          value={form.notificationRoles}
          onChange={(e) => setForm({ ...form, notificationRoles: e.target.value })}
          rows={2}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.authorityWindow')}
        htmlFor={`${idPrefix}-authority-window`}
      >
        <Input
          id={`${idPrefix}-authority-window`}
          value={form.authorityNotificationWindow}
          onChange={(e) => setForm({ ...form, authorityNotificationWindow: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.subjectGuidance')}
        htmlFor={`${idPrefix}-subject-guidance`}
      >
        <TextArea
          id={`${idPrefix}-subject-guidance`}
          value={form.subjectNotificationGuidance}
          onChange={(e) => setForm({ ...form, subjectNotificationGuidance: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.field.risk')} htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptions}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptions}
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.field.reviewNotes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.reviewNotes}
          onChange={(e) => setForm({ ...form, reviewNotes: e.target.value })}
          rows={3}
        />
      </Field>
      <InlineWarning tone="info" title="Evidência de operador">
        Esta evidência regista apenas revisão ou exercício. Não notifica a autoridade nem os
        titulares.
      </InlineWarning>
      <div className="api-key-rate-grid">
        <Field label="Tipo de evidência" htmlFor={`${idPrefix}-evidence-type`}>
          <Select
            id={`${idPrefix}-evidence-type`}
            value={form.evidenceType}
            onChange={(e) =>
              setForm({ ...form, evidenceType: e.target.value as BreachEvidenceKind })
            }
            options={breachEvidenceOptions}
          />
        </Field>
        <Field label="Notas de evidência" htmlFor={`${idPrefix}-evidence-notes`}>
          <TextArea
            id={`${idPrefix}-evidence-notes`}
            value={form.evidenceNotes}
            onChange={(e) => setForm({ ...form, evidenceNotes: e.target.value })}
            rows={2}
          />
        </Field>
      </div>
      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          {t('settings.privacy.action.cancel')}
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving
            ? t('settings.privacy.action.saving')
            : editing
              ? t('settings.privacy.action.save')
              : t('settings.privacy.action.create')}
        </Button>
      </div>
    </form>
  );
}

function BreachPlaybookPanel({
  records,
  loading,
  error,
  saving,
  onCreate,
  onPatch,
}: {
  records: BreachPlaybookView[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: CreateBreachPlaybookBody) => Promise<BreachPlaybookView>;
  onPatch: (id: string, body: PatchBreachPlaybookBody) => Promise<BreachPlaybookView>;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [form, setForm] = useState<BreachPlaybookFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      return q.length === 0 || breachSearchText(record).includes(q);
    });
  }, [records, riskFilter, search, statusFilter]);

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, breachCreateBody(form));
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await onCreate(breachCreateBody(form));
        toast.success(t('settings.privacy.toast.created'));
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? t('settings.privacy.form.edit') : t('settings.privacy.form.new')}>
          <BreachPlaybookForm
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}
      <Card
        title={t('settings.privacy.breach.title')}
        actions={
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Plus />}
            onClick={() => {
              setEditingId(null);
              setForm(EMPTY_BREACH_FORM);
            }}
          >
            {t('settings.privacy.action.new')}
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.breach.lede')}</p>
          <div className="filter">
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-breach-search">
              <Input
                id="privacy-breach-search"
                value={search}
                placeholder={t('settings.privacy.breach.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label={t('settings.privacy.field.status')} htmlFor="privacy-breach-status">
              <Select
                id="privacy-breach-status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusOptions}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor="privacy-breach-risk">
              <Select
                id="privacy-breach-risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskOptions}
              />
            </Field>
          </div>
          {loading ? (
            <SkeletonTable cols={8} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title={t('settings.privacy.empty.title')}>
              <p>{t('settings.privacy.empty.body')}</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title={t('settings.privacy.emptyResults.title')}>
              <p>{t('settings.privacy.emptyResults.body')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.breach.column.playbook')}</th>
                  <th>{t('settings.privacy.breach.column.scope')}</th>
                  <th>{t('settings.privacy.breach.column.detection')}</th>
                  <th>{t('settings.privacy.breach.column.containment')}</th>
                  <th>Evidência</th>
                  <th>{t('settings.privacy.field.risk')}</th>
                  <th>{t('settings.privacy.field.status')}</th>
                  <th>{t('settings.privacy.table.action')}</th>
                </tr>
              }
            >
              {filtered.map((record) => {
                const receipt = latestReceipt(record.evidence_receipts);
                return (
                  <tr key={record.id}>
                    <td>{record.title}</td>
                    <td>{record.scope}</td>
                    <td>{record.detection_channels.join(', ')}</td>
                    <td>{record.containment_steps.join(', ')}</td>
                    <td>
                      {receipt ? (
                        <>
                          {receipt.evidence_type === 'drill' ? 'Exercício' : 'Revisão'} por{' '}
                          {receipt.recorded_by}
                          <br />
                          <span className="muted">
                            {formatDateTime(receipt.recorded_at)} · Sem notificação à autoridade ·
                            Sem notificação aos titulares
                          </span>
                        </>
                      ) : (
                        <span className="muted">Sem recibo</span>
                      )}
                    </td>
                    <td>
                      <Badge tone={riskTone(record.risk_level)}>
                        {RISK_LABELS[record.risk_level]}
                      </Badge>
                    </td>
                    <td>
                      <div className="stack--tight">
                        <Badge tone={statusTone(record.status)}>
                          {STATUS_LABELS[record.status]}
                        </Badge>
                        <AdvisoryReviewBadge review={record.advisory_review} />
                      </div>
                    </td>
                    <td className="users-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Pencil />}
                        disabled={saving}
                        onClick={() => {
                          setEditingId(record.id);
                          setForm(breachFormFromRecord(record));
                        }}
                      >
                        {t('settings.privacy.action.edit')}
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}
        </div>
      </Card>
    </div>
  );
}

function TransferControlForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  form: TransferControlFormState;
  setForm: (next: TransferControlFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-transfer-${editing ? 'edit' : 'new'}`;
  const canSubmit =
    form.name.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    form.recipient.trim().length > 0 &&
    form.destinationCountry.trim().length > 0 &&
    form.transferMechanism.trim().length > 0 &&
    splitList(form.dataCategories).length > 0 &&
    splitList(form.safeguards).length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.transfer.field.name')} htmlFor={`${idPrefix}-name`}>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field label={t('settings.privacy.transfer.field.purpose')} htmlFor={`${idPrefix}-purpose`}>
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>
      <Field label={t('settings.privacy.transfer.field.legalBasis')} htmlFor={`${idPrefix}-legal`}>
        <Input
          id={`${idPrefix}-legal`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.transfer.field.categories')}
        htmlFor={`${idPrefix}-categories`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.transfer.field.recipient')}
          htmlFor={`${idPrefix}-recipient`}
        >
          <Input
            id={`${idPrefix}-recipient`}
            value={form.recipient}
            onChange={(e) => setForm({ ...form, recipient: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.transfer.field.destination')}
          htmlFor={`${idPrefix}-destination`}
        >
          <Input
            id={`${idPrefix}-destination`}
            value={form.destinationCountry}
            onChange={(e) => setForm({ ...form, destinationCountry: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field
        label={t('settings.privacy.transfer.field.mechanism')}
        htmlFor={`${idPrefix}-mechanism`}
      >
        <Input
          id={`${idPrefix}-mechanism`}
          value={form.transferMechanism}
          onChange={(e) => setForm({ ...form, transferMechanism: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.transfer.field.safeguards')}
        htmlFor={`${idPrefix}-safeguards`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-safeguards`}
          value={form.safeguards}
          onChange={(e) => setForm({ ...form, safeguards: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.field.risk')} htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptions}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptions}
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.field.reviewNotes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.reviewNotes}
          onChange={(e) => setForm({ ...form, reviewNotes: e.target.value })}
          rows={3}
        />
      </Field>
      <InlineWarning tone="info" title="Evidência de operador">
        Esta evidência regista apenas revisão do controlo. Não aprova transferências, não executa
        transferências de dados e não certifica conformidade legal.
      </InlineWarning>
      <Field label="Notas de evidência" htmlFor={`${idPrefix}-evidence-notes`}>
        <TextArea
          id={`${idPrefix}-evidence-notes`}
          value={form.evidenceNotes}
          onChange={(e) => setForm({ ...form, evidenceNotes: e.target.value })}
          rows={2}
        />
      </Field>
      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          {t('settings.privacy.action.cancel')}
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving
            ? t('settings.privacy.action.saving')
            : editing
              ? t('settings.privacy.action.save')
              : t('settings.privacy.action.create')}
        </Button>
      </div>
    </form>
  );
}

function TransferControlPanel({
  records,
  loading,
  error,
  saving,
  onCreate,
  onPatch,
}: {
  records: TransferControlView[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: CreateTransferControlBody) => Promise<TransferControlView>;
  onPatch: (id: string, body: PatchTransferControlBody) => Promise<TransferControlView>;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [form, setForm] = useState<TransferControlFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      return q.length === 0 || transferSearchText(record).includes(q);
    });
  }, [records, riskFilter, search, statusFilter]);

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, transferCreateBody(form));
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await onCreate(transferCreateBody(form));
        toast.success(t('settings.privacy.toast.created'));
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? t('settings.privacy.form.edit') : t('settings.privacy.form.new')}>
          <TransferControlForm
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}
      <Card
        title={t('settings.privacy.transfer.title')}
        actions={
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Plus />}
            onClick={() => {
              setEditingId(null);
              setForm(EMPTY_TRANSFER_FORM);
            }}
          >
            {t('settings.privacy.action.new')}
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.transfer.lede')}</p>
          <div className="filter">
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-transfer-search">
              <Input
                id="privacy-transfer-search"
                value={search}
                placeholder={t('settings.privacy.transfer.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label={t('settings.privacy.field.status')} htmlFor="privacy-transfer-status">
              <Select
                id="privacy-transfer-status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusOptions}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor="privacy-transfer-risk">
              <Select
                id="privacy-transfer-risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskOptions}
              />
            </Field>
          </div>
          {loading ? (
            <SkeletonTable cols={8} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title={t('settings.privacy.empty.title')}>
              <p>{t('settings.privacy.empty.body')}</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title={t('settings.privacy.emptyResults.title')}>
              <p>{t('settings.privacy.emptyResults.body')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.transfer.column.name')}</th>
                  <th>{t('settings.privacy.transfer.column.destination')}</th>
                  <th>{t('settings.privacy.transfer.column.mechanism')}</th>
                  <th>{t('settings.privacy.transfer.column.categories')}</th>
                  <th>{t('settings.privacy.transfer.column.safeguards')}</th>
                  <th>Evidência</th>
                  <th>{t('settings.privacy.field.risk')}</th>
                  <th>{t('settings.privacy.field.status')}</th>
                  <th>{t('settings.privacy.table.action')}</th>
                </tr>
              }
            >
              {filtered.map((record) => {
                const receipt = latestReceipt(record.evidence_receipts);
                return (
                  <tr key={record.id}>
                    <td>{record.name}</td>
                    <td>
                      {record.destination_country}
                      <br />
                      <span className="muted">{record.recipient}</span>
                    </td>
                    <td>{record.transfer_mechanism}</td>
                    <td>{record.data_categories.join(', ')}</td>
                    <td>{record.safeguards.join(', ')}</td>
                    <td>
                      {receipt ? (
                        <>
                          Revisão por {receipt.recorded_by}
                          <br />
                          <span className="muted">
                            {formatDateTime(receipt.recorded_at)} · Sem aprovação · Sem execução de
                            transferência
                          </span>
                        </>
                      ) : (
                        <span className="muted">Sem recibo</span>
                      )}
                    </td>
                    <td>
                      <Badge tone={riskTone(record.risk_level)}>
                        {RISK_LABELS[record.risk_level]}
                      </Badge>
                    </td>
                    <td>
                      <div className="stack--tight">
                        <Badge tone={statusTone(record.status)}>
                          {STATUS_LABELS[record.status]}
                        </Badge>
                        <AdvisoryReviewBadge review={record.advisory_review} />
                      </div>
                    </td>
                    <td className="users-actions">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Pencil />}
                        disabled={saving}
                        onClick={() => {
                          setEditingId(record.id);
                          setForm(transferFormFromRecord(record));
                        }}
                      >
                        {t('settings.privacy.action.edit')}
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </Table>
          )}
        </div>
      </Card>
    </div>
  );
}

function RetentionPolicyForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  onSubmit,
}: {
  form: RetentionPolicyFormState;
  setForm: (next: RetentionPolicyFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-retention-${editing ? 'edit' : 'new'}`;
  const retentionStatusOptions = RETENTION_POLICY_STATUSES.map((status) => ({
    value: status,
    label: retentionStatusLabel(t, status),
  }));
  const retentionDisposalOptions = RETENTION_DISPOSAL_ACTIONS.map((action) => ({
    value: action,
    label: retentionDisposalLabel(t, action),
  }));
  const canSubmit =
    form.name.trim().length > 0 &&
    form.scope.trim().length > 0 &&
    form.category.trim().length > 0 &&
    form.scheduleId.trim().length > 0 &&
    form.retentionPeriod.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    !saving;

  return (
    <form
      className="form"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.retention.field.name')} htmlFor={`${idPrefix}-name`}>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.retention.field.scope')} htmlFor={`${idPrefix}-scope`}>
          <Input
            id={`${idPrefix}-scope`}
            value={form.scope}
            onChange={(e) => setForm({ ...form, scope: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.retention.field.category')}
          htmlFor={`${idPrefix}-category`}
        >
          <Input
            id={`${idPrefix}-category`}
            value={form.category}
            onChange={(e) => setForm({ ...form, category: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.retention.field.scheduleId')}
          htmlFor={`${idPrefix}-schedule`}
        >
          <Input
            id={`${idPrefix}-schedule`}
            value={form.scheduleId}
            onChange={(e) => setForm({ ...form, scheduleId: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.retention.field.retentionPeriod')}
          htmlFor={`${idPrefix}-period`}
        >
          <Input
            id={`${idPrefix}-period`}
            value={form.retentionPeriod}
            onChange={(e) => setForm({ ...form, retentionPeriod: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.retention.field.legalBasis')} htmlFor={`${idPrefix}-legal`}>
        <Input
          id={`${idPrefix}-legal`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.retention.field.disposalAction')}
          htmlFor={`${idPrefix}-action`}
        >
          <Select
            id={`${idPrefix}-action`}
            value={form.disposalAction}
            onChange={(e) =>
              setForm({ ...form, disposalAction: e.target.value as RetentionDisposalAction })
            }
            options={retentionDisposalOptions}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as RetentionPolicyStatus })}
            options={retentionStatusOptions}
          />
        </Field>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={form.active}
          onChange={(e) => setForm({ ...form, active: e.target.checked })}
        />
        {t('settings.privacy.retention.field.active')}
      </label>
      <Field label={t('settings.privacy.retention.field.notes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.notes}
          onChange={(e) => setForm({ ...form, notes: e.target.value })}
          rows={3}
        />
      </Field>
      <InlineWarning tone="info" title={t('settings.privacy.retention.notice.title')}>
        {t('settings.privacy.retention.notice.body')}
      </InlineWarning>
      <div className="form__actions">
        <Button type="button" variant="ghost" disabled={saving} onClick={onCancel}>
          {t('settings.privacy.action.cancel')}
        </Button>
        <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
          {saving
            ? t('settings.privacy.action.saving')
            : editing
              ? t('settings.privacy.action.save')
              : t('settings.privacy.action.create')}
        </Button>
      </div>
    </form>
  );
}

function RetentionDryRunPanel({
  running,
  report,
  onDryRun,
}: {
  running: boolean;
  report: RetentionDryRunReport | null;
  onDryRun: (form: RetentionDryRunFormState) => Promise<void>;
}) {
  const t = useT();
  const [form, setForm] = useState(EMPTY_RETENTION_DRY_RUN_FORM);
  const canSubmit = form.scope.trim().length > 0 && form.category.trim().length > 0 && !running;

  return (
    <Card title={t('settings.privacy.retention.dryRun.title')}>
      <form
        className="form"
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          if (canSubmit) void onDryRun(form);
        }}
      >
        <div className="api-key-rate-grid">
          <Field
            label={t('settings.privacy.retention.field.scope')}
            htmlFor="privacy-retention-dry-run-scope"
          >
            <Input
              id="privacy-retention-dry-run-scope"
              value={form.scope}
              onChange={(e) => setForm({ ...form, scope: e.target.value })}
              autoComplete="off"
            />
          </Field>
          <Field
            label={t('settings.privacy.retention.field.category')}
            htmlFor="privacy-retention-dry-run-category"
          >
            <Input
              id="privacy-retention-dry-run-category"
              value={form.category}
              onChange={(e) => setForm({ ...form, category: e.target.value })}
              autoComplete="off"
            />
          </Field>
        </div>
        <Field
          label={t('settings.privacy.retention.dryRun.field.recordId')}
          htmlFor="privacy-retention-dry-run-record"
        >
          <Input
            id="privacy-retention-dry-run-record"
            value={form.recordId}
            onChange={(e) => setForm({ ...form, recordId: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <InlineWarning tone="info" title={t('settings.privacy.retention.dryRun.notice.title')}>
          {t('settings.privacy.retention.dryRun.notice.body')}
        </InlineWarning>
        <div className="form__actions">
          <Button type="submit" variant="primary" icon={<Icon.Check />} disabled={!canSubmit}>
            {running
              ? t('settings.privacy.retention.dryRun.running')
              : t('settings.privacy.retention.dryRun.action')}
          </Button>
        </div>
      </form>
      {report ? (
        <div className="stack">
          <p>
            <strong>{t('settings.privacy.retention.dryRun.mode')}:</strong> {report.mode} ·{' '}
            <strong>{t('settings.privacy.retention.dryRun.executionSupported')}:</strong>{' '}
            {String(report.execution_supported)} · <strong>destructive_execution_supported:</strong>{' '}
            {String(report.destructive_execution_supported)}
          </p>
          <p>
            <strong>{t('settings.privacy.retention.dryRun.candidate')}:</strong>{' '}
            {report.candidate.scope} / {report.candidate.category}
            {report.candidate.record_id ? ` / ${report.candidate.record_id}` : ''}
          </p>
          {report.matches.length === 0 ? (
            <EmptyState title={t('settings.privacy.retention.dryRun.empty.title')}>
              <p>{t('settings.privacy.retention.dryRun.empty.body')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.retention.column.policy')}</th>
                  <th>{t('settings.privacy.retention.column.schedule')}</th>
                  <th>{t('settings.privacy.retention.column.disposalAction')}</th>
                  <th>{t('settings.privacy.retention.dryRun.column.result')}</th>
                </tr>
              }
            >
              {report.matches.map((match) => (
                <tr key={match.policy_id}>
                  <td>
                    {match.name}
                    <br />
                    <span className="muted">
                      {match.scope} / {match.category}
                    </span>
                  </td>
                  <td>
                    {match.schedule_id}
                    <br />
                    <span className="muted">{match.retention_period}</span>
                  </td>
                  <td>{retentionDisposalLabel(t, match.disposal_action)}</td>
                  <td>
                    {match.reason}
                    <br />
                    <span className="muted">
                      destructive_action: {String(match.destructive_action)} · would_execute:{' '}
                      {String(match.would_execute)}
                    </span>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      ) : null}
    </Card>
  );
}

function RetentionDueCandidatesPanel({
  report,
  loading,
  error,
  reviewRequestPending,
  requestingReviewCandidateId,
  executionRecords,
  onRequestReview,
}: {
  report: RetentionDueCandidatesReport | null;
  loading: boolean;
  error: unknown;
  reviewRequestPending: boolean;
  requestingReviewCandidateId: string | null;
  executionRecords: RetentionExecutionRecord[];
  onRequestReview: (
    candidate: RetentionDueCandidate,
    executionMode?: 'review_only' | 'execute_supported',
  ) => Promise<void>;
}) {
  const candidates: RetentionDueCandidate[] = report?.candidates ?? [];
  const suppressedByBoundedEvidenceCount = report?.suppressed_by_bounded_evidence_count ?? 0;

  return (
    <Card title="Candidatos de retenção vencidos">
      <div className="stack">
        <p className="field__hint">
          Varredura GET somente leitura para revisão de evidência. Esta secção não apaga, não
          anonimiza e não conclui cumprimento legal.
        </p>
        {report ? (
          <p className="muted">
            Gerado em {formatDateTime(report.generated_at)} · {report.scope} / {report.category} ·{' '}
            {report.candidate_count} candidato(s) ativo(s) · {suppressedByBoundedEvidenceCount}{' '}
            suprimido(s) por evidência delimitada
          </p>
        ) : null}
        {report && report.suppressed_candidate_count > 0 ? (
          <p className="muted">
            Candidatos suprimidos por evidência delimitada não são listados na tabela e não recebem
            botões de ação; reveja a evidência na fila/histórico de execução.
            {report.suppression_summary ? <> Resumo: {report.suppression_summary.note}</> : null}
          </p>
        ) : null}
        {loading ? (
          <SkeletonTable cols={7} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : candidates.length === 0 ? (
          <EmptyState title="Sem candidatos vencidos">
            <p>Não há candidatos vencidos da varredura somente leitura.</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>Livro e registo</th>
                <th>Política</th>
                <th>Vencimento e estado</th>
                <th>Bloqueios e aprovações</th>
                <th>Achados</th>
                <th>Flags sem execução</th>
                <th>Pedido de revisão</th>
              </tr>
            }
          >
            {candidates.map((candidate) => {
              const queuedReview = retentionQueuedReviewForCandidate(candidate, executionRecords);
              const priorExecution = candidate.prior_execution;
              const canRecordNoActionEvidence = retentionCandidateCanRecordNoActionEvidence(
                candidate,
                queuedReview,
              );
              const canRecordArchiveEvidence = retentionCandidateCanRecordArchiveEvidence(
                candidate,
                queuedReview,
              );
              return (
                <tr key={candidate.candidate_id}>
                  <td>
                    <div className="stack--tight">
                      <span className="mono">{candidate.record_id}</span>
                      <span>Livro: {candidate.book_id}</span>
                      <span className="muted">Entidade: {candidate.entity_id}</span>
                      <span className="muted">
                        {candidate.scope} / {candidate.category}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <span>{candidate.policy_name}</span>
                      <span className="muted">{candidate.policy_id}</span>
                      <span className="muted">
                        {candidate.schedule_id} · {candidate.retention_period}
                      </span>
                      <span>{candidate.disposal_action}</span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <span>Fecho: {candidate.closing_date}</span>
                      <span>Vencimento: {candidate.due_date ?? 'Sem data calculada'}</span>
                      <Badge tone={candidate.overdue ? 'warn' : 'neutral'}>
                        overdue: {String(candidate.overdue)}
                      </Badge>
                      <span>
                        {candidate.status} · {candidate.outcome}
                      </span>
                      <span className="muted">{candidate.next_step}</span>
                      <span className="muted">
                        Estado de evidência: {candidate.candidate_evidence_state}
                      </span>
                      <span className="muted">
                        Próximo passo de evidência: {candidate.evidence_next_step}
                      </span>
                      {priorExecution ? (
                        <>
                          <Badge tone="ok">Evidência delimitada registada</Badge>
                          <span>
                            {priorExecution.execution_status} · {priorExecution.outcome}
                          </span>
                          <span className="muted">
                            Evidência anterior: {priorExecution.evidence_state}
                          </span>
                          <span className="muted">
                            Execução {priorExecution.execution_id} · pedido em{' '}
                            {formatDateTime(priorExecution.requested_at)}
                          </span>
                          {priorExecution.executed_at ? (
                            <span className="muted">
                              Executado em {formatDateTime(priorExecution.executed_at)}
                            </span>
                          ) : null}
                          <span className="muted">{priorExecution.next_step}</span>
                          <span className="muted">
                            Próximo passo de evidência anterior: {priorExecution.evidence_next_step}
                          </span>
                        </>
                      ) : null}
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <strong>Legal hold</strong>
                      {candidate.legal_hold_blockers.length > 0 ? (
                        candidate.legal_hold_blockers.map((blocker, index) => (
                          <span key={`${candidate.candidate_id}-hold-${index}`}>
                            {renderUnknownEvidence(blocker)}
                          </span>
                        ))
                      ) : (
                        <span className="muted">Sem bloqueios de legal hold</span>
                      )}
                      <strong>Aprovações requeridas</strong>
                      {candidate.required_approvals.length > 0 ? (
                        candidate.required_approvals.map((approval, index) => (
                          <span key={`${candidate.candidate_id}-approval-${index}`}>
                            {renderUnknownEvidence(approval)}
                          </span>
                        ))
                      ) : (
                        <span className="muted">Sem aprovações requeridas</span>
                      )}
                      {candidate.blockers.map((blocker, index) => (
                        <span key={`${candidate.candidate_id}-blocker-${index}`}>
                          {renderUnknownEvidence(blocker)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      {candidate.findings.length > 0 ? (
                        candidate.findings.map((finding, index) => (
                          <span key={`${candidate.candidate_id}-finding-${index}`}>
                            {retentionFindingText(finding)}
                          </span>
                        ))
                      ) : (
                        <span className="muted">Sem achados de período não suportado</span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <span>destructive_action: {String(candidate.destructive_action)}</span>
                      <span>would_execute: {String(candidate.would_execute)}</span>
                      <span>
                        destructive_disposal_completed:{' '}
                        {String(candidate.destructive_disposal_completed)}
                      </span>
                      <span>
                        full_erasure_completed: {String(candidate.full_erasure_completed)}
                      </span>
                      {priorExecution ? (
                        <>
                          <span>
                            prior.destructive_disposal_completed:{' '}
                            {String(priorExecution.destructive_disposal_completed)}
                          </span>
                          <span>
                            prior.full_erasure_completed:{' '}
                            {String(priorExecution.full_erasure_completed)}
                          </span>
                          <span>
                            prior.targets_acted_count: {priorExecution.targets_acted_count}
                          </span>
                        </>
                      ) : null}
                      <span className="muted">
                        {canRecordNoActionEvidence
                          ? 'Apenas registo delimitado de evidência sem ação.'
                          : canRecordArchiveEvidence
                            ? 'Apenas registo delimitado de evidência de arquivo.'
                            : 'Apenas revisão de evidência.'}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      {priorExecution ? (
                        <Badge tone="ok">Evidência delimitada existente</Badge>
                      ) : queuedReview ? (
                        <Badge tone="warn">Revisão já na fila</Badge>
                      ) : canRecordNoActionEvidence ? (
                        <Button
                          type="button"
                          variant="secondary"
                          icon={<Icon.Check />}
                          disabled={reviewRequestPending}
                          onClick={() => void onRequestReview(candidate, 'execute_supported')}
                        >
                          {requestingReviewCandidateId === candidate.candidate_id
                            ? 'A registar evidência sem ação'
                            : 'Registar evidência sem ação'}
                        </Button>
                      ) : canRecordArchiveEvidence ? (
                        <Button
                          type="button"
                          variant="secondary"
                          icon={<Icon.Check />}
                          disabled={reviewRequestPending}
                          onClick={() => void onRequestReview(candidate, 'execute_supported')}
                        >
                          {requestingReviewCandidateId === candidate.candidate_id
                            ? 'A registar evidência de arquivo'
                            : 'Registar evidência de arquivo'}
                        </Button>
                      ) : (
                        <Button
                          type="button"
                          variant="secondary"
                          icon={<Icon.Check />}
                          disabled={reviewRequestPending}
                          onClick={() => void onRequestReview(candidate, 'review_only')}
                        >
                          {requestingReviewCandidateId === candidate.candidate_id
                            ? 'A registar revisão'
                            : 'Pedir revisão de evidência'}
                        </Button>
                      )}
                      {priorExecution ? (
                        <>
                          <span className="muted">
                            {priorExecution.execution_status} · {priorExecution.execution_id}
                          </span>
                          <span className="muted">
                            Não é criado pedido duplicado; a varredura é somente leitura.
                          </span>
                        </>
                      ) : queuedReview ? (
                        <>
                          <span className="muted">
                            {queuedReview.execution_status} · {queuedReview.id}
                          </span>
                          <span className="muted">
                            Pedido em {formatDateTime(queuedReview.requested_at)}
                          </span>
                          <span className="muted">
                            Estado de evidência na fila: {queuedReview.evidence_state}
                          </span>
                          <span className="muted">
                            Próximo passo na fila: {queuedReview.evidence_next_step}
                          </span>
                        </>
                      ) : canRecordNoActionEvidence ? (
                        <span className="muted">
                          Regista apenas evidência delimitada de no-action; não aprova nem executa
                          descarte.
                        </span>
                      ) : canRecordArchiveEvidence ? (
                        <span className="muted">
                          Regista apenas evidência delimitada de arquivo; não aprova nem executa
                          descarte.
                        </span>
                      ) : (
                        <span className="muted">
                          Regista um pedido review_only; não aprova nem executa descarte.
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </div>
    </Card>
  );
}

function RetentionExecutionReviewQueue({
  records,
  loading,
  error,
  statusFilter,
  onStatusFilterChange,
}: {
  records: RetentionExecutionRecord[];
  loading: boolean;
  error: unknown;
  statusFilter: RetentionExecutionStatus | 'all';
  onStatusFilterChange: (status: RetentionExecutionStatus | 'all') => void;
}) {
  const t = useT();
  const toast = useToast();
  const closeReview = useClosePrivacyRetentionExecutionReview();
  const [search, setSearch] = useState('');
  const [closingId, setClosingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.execution_status !== statusFilter) return false;
      return q.length === 0 || retentionExecutionSearchText(record).includes(q);
    });
  }, [records, search, statusFilter]);
  const statusOptions = RETENTION_EXECUTION_STATUSES.map((status) => ({
    value: status,
    label: retentionExecutionStatusLabel(status),
  }));

  async function closeOperationalReview(record: RetentionExecutionRecord) {
    setClosingId(record.id);
    try {
      await closeReview.mutateAsync({ id: record.id, body: retentionReviewClosureBody(record) });
      toast.success('Revisão operacional registada.');
    } catch (e) {
      toast.error(e);
    } finally {
      setClosingId(null);
    }
  }

  return (
    <Card title="Fila de revisão de execução">
      <div className="stack">
        <p className="field__hint">
          Registos persistidos de execução de retenção para revisão operacional.
        </p>
        <div className="filter">
          <Field
            label={t('settings.privacy.filter.search')}
            htmlFor="privacy-retention-execution-search"
          >
            <Input
              id="privacy-retention-execution-search"
              value={search}
              placeholder="Política, alvo, responsável, bloqueio ou próximo passo"
              onChange={(e) => setSearch(e.target.value)}
            />
          </Field>
          <Field label="Estado da execução" htmlFor="privacy-retention-execution-status">
            <Select
              id="privacy-retention-execution-status"
              value={statusFilter}
              onChange={(e) =>
                onStatusFilterChange(e.target.value as RetentionExecutionStatus | 'all')
              }
              options={[{ value: 'all', label: 'Todos os estados' }, ...statusOptions]}
            />
          </Field>
        </div>
        {loading ? (
          <SkeletonTable cols={6} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : records.length === 0 ? (
          <EmptyState title="Sem registos de execução">
            <p>A fila de revisão ainda não tem pedidos persistidos.</p>
          </EmptyState>
        ) : filtered.length === 0 ? (
          <EmptyState title={t('settings.privacy.emptyResults.title')}>
            <p>{t('settings.privacy.emptyResults.body')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>Pedido</th>
                <th>Estado</th>
                <th>Política</th>
                <th>Bloqueios e aprovações</th>
                <th>Próximo passo</th>
                <th>Revisão operacional</th>
              </tr>
            }
          >
            {filtered.map((record) => (
              <tr key={record.id}>
                <td>
                  <div className="stack--tight">
                    <span className="mono">{record.candidate.record_id ?? record.id}</span>
                    <span>
                      {record.candidate.scope} / {record.candidate.category}
                    </span>
                    <span className="muted">
                      {formatDateTime(record.requested_at)} · {record.actor}
                    </span>
                  </div>
                </td>
                <td>
                  <div className="stack--tight">
                    <Badge tone={retentionExecutionStatusTone(record.execution_status)}>
                      {retentionExecutionStatusLabel(record.execution_status)}
                    </Badge>
                    <span className="muted">{record.outcome}</span>
                    <span className="muted">{record.operator_review_decision}</span>
                  </div>
                </td>
                <td>
                  <div className="stack--tight">
                    <span>{record.requested_policy.name ?? 'Política não encontrada'}</span>
                    <span className="muted">{record.requested_policy.id ?? 'Sem política'}</span>
                    <span className="muted">
                      {record.requested_policy.schedule_id ?? 'Sem calendário'}
                      {record.requested_policy.retention_period
                        ? ` · ${record.requested_policy.retention_period}`
                        : ''}
                    </span>
                    {record.requested_policy.disposal_action ? (
                      <span>
                        {retentionDisposalLabel(t, record.requested_policy.disposal_action)}
                      </span>
                    ) : null}
                  </div>
                </td>
                <td>
                  <div className="stack--tight">
                    {record.workflow.blockers.length > 0 ? (
                      record.workflow.blockers.map((blocker) => (
                        <span key={`${record.id}-${blocker.code}-${blocker.policy_id ?? ''}`}>
                          <strong>{blocker.code}</strong>: {blocker.message}
                        </span>
                      ))
                    ) : (
                      <span className="muted">Sem bloqueios</span>
                    )}
                    {record.legal_hold_blockers.map((blocker) => (
                      <span key={`${record.id}-hold-${blocker.policy_id}`}>
                        <strong>{blocker.name}</strong>: {blocker.reason}
                      </span>
                    ))}
                    {record.workflow.required_approvals.map((approval) => (
                      <span key={`${record.id}-${approval.code}-${approval.required_from}`}>
                        <strong>{approval.code}</strong>: {approval.required_from}
                      </span>
                    ))}
                    {record.approval ? (
                      <span>
                        <strong>{record.approval.approval_reference}</strong> ·{' '}
                        {record.approval.approved_by}
                      </span>
                    ) : null}
                  </div>
                </td>
                <td>
                  <div className="stack--tight">
                    <span>{record.workflow.next_step}</span>
                    <span className="muted">Estado de evidência: {record.evidence_state}</span>
                    <span className="muted">
                      Próximo passo de evidência: {record.evidence_next_step}
                    </span>
                    {record.operator_notes ? (
                      <span className="muted">{record.operator_notes}</span>
                    ) : null}
                    <span className="muted">
                      targets_acted: {record.execution_result.targets_acted.length} ·
                      destructive_disposal_completed:{' '}
                      {String(record.execution_result.destructive_disposal_completed)} ·
                      full_erasure_completed:{' '}
                      {String(record.execution_result.full_erasure_completed)}
                    </span>
                  </div>
                </td>
                <td className="users-actions">
                  {record.decision_state === 'review_closed' ? (
                    <div className="stack--tight">
                      <span>
                        Revisão operacional registada
                        {record.review_closed_by ? ` por ${record.review_closed_by}` : ''}
                        {record.review_closed_at
                          ? ` em ${formatDateTime(record.review_closed_at)}`
                          : ''}
                        .
                      </span>
                      {record.review_closure_note ? (
                        <span className="muted">{record.review_closure_note}</span>
                      ) : null}
                      {(record.review_closure_evidence ?? []).map((evidence) => (
                        <span
                          key={`${record.id}-closure-${evidence.label}-${evidence.value}`}
                          className="muted"
                        >
                          {evidence.label}: {evidence.value}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <Button
                      type="button"
                      variant="ghost"
                      icon={<Icon.Check />}
                      disabled={closeReview.isPending}
                      onClick={() => void closeOperationalReview(record)}
                    >
                      {closingId === record.id
                        ? 'A registar revisão'
                        : 'Registar revisão operacional'}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </Card>
  );
}

function RetentionPolicyPanel({
  records,
  loading,
  error,
  saving,
  runningDryRun,
  dryRunReport,
  dueCandidatesReport,
  dueCandidatesLoading,
  dueCandidatesError,
  reviewRequestPending,
  requestingReviewCandidateId,
  executionRecords,
  executionLoading,
  executionError,
  executionStatusFilter,
  onCreate,
  onPatch,
  onDryRun,
  onRequestReview,
  onExecutionStatusFilterChange,
}: {
  records: RetentionPolicyView[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  runningDryRun: boolean;
  dryRunReport: RetentionDryRunReport | null;
  dueCandidatesReport: RetentionDueCandidatesReport | null;
  dueCandidatesLoading: boolean;
  dueCandidatesError: unknown;
  reviewRequestPending: boolean;
  requestingReviewCandidateId: string | null;
  executionRecords: RetentionExecutionRecord[];
  executionLoading: boolean;
  executionError: unknown;
  executionStatusFilter: RetentionExecutionStatus | 'all';
  onCreate: (body: CreateRetentionPolicyBody) => Promise<RetentionPolicyView>;
  onPatch: (id: string, body: PatchRetentionPolicyBody) => Promise<RetentionPolicyView>;
  onDryRun: (form: RetentionDryRunFormState) => Promise<void>;
  onRequestReview: (
    candidate: RetentionDueCandidate,
    executionMode?: 'review_only' | 'execute_supported',
  ) => Promise<void>;
  onExecutionStatusFilterChange: (status: RetentionExecutionStatus | 'all') => void;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const retentionStatusOptions = RETENTION_POLICY_STATUSES.map((status) => ({
    value: status,
    label: retentionStatusLabel(t, status),
  }));
  const [form, setForm] = useState<RetentionPolicyFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(search.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      return q.length === 0 || retentionSearchText(record).includes(q);
    });
  }, [records, search, statusFilter]);

  async function submitForm() {
    if (!form) return;
    try {
      if (editingId) {
        await onPatch(editingId, retentionCreateBody(form));
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await onCreate(retentionCreateBody(form));
        toast.success(t('settings.privacy.toast.created'));
      }
      setForm(null);
      setEditingId(null);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div className="stack">
      {form ? (
        <Card title={editingId ? t('settings.privacy.form.edit') : t('settings.privacy.form.new')}>
          <RetentionPolicyForm
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={() => {
              setForm(null);
              setEditingId(null);
            }}
            onSubmit={submitForm}
          />
        </Card>
      ) : null}
      <Card
        title={t('settings.privacy.retention.title')}
        actions={
          <Button
            type="button"
            variant="primary"
            icon={<Icon.Plus />}
            onClick={() => {
              setEditingId(null);
              setForm(EMPTY_RETENTION_FORM);
            }}
          >
            {t('settings.privacy.action.new')}
          </Button>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.retention.lede')}</p>
          <div className="filter">
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-retention-search">
              <Input
                id="privacy-retention-search"
                value={search}
                placeholder={t('settings.privacy.retention.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field label={t('settings.privacy.field.status')} htmlFor="privacy-retention-status">
              <Select
                id="privacy-retention-status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={[
                  { value: 'all', label: t('settings.privacy.retention.status.all') },
                  ...retentionStatusOptions,
                ]}
              />
            </Field>
          </div>
          {loading ? (
            <SkeletonTable cols={8} />
          ) : error ? (
            <ErrorNote error={error} />
          ) : records.length === 0 ? (
            <EmptyState title={t('settings.privacy.empty.title')}>
              <p>{t('settings.privacy.empty.body')}</p>
            </EmptyState>
          ) : filtered.length === 0 ? (
            <EmptyState title={t('settings.privacy.emptyResults.title')}>
              <p>{t('settings.privacy.emptyResults.body')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.retention.column.policy')}</th>
                  <th>{t('settings.privacy.retention.column.scope')}</th>
                  <th>{t('settings.privacy.retention.column.schedule')}</th>
                  <th>{t('settings.privacy.retention.column.disposalAction')}</th>
                  <th>{t('settings.privacy.field.status')}</th>
                  <th>{t('settings.privacy.retention.column.execution')}</th>
                  <th>{t('settings.privacy.table.action')}</th>
                </tr>
              }
            >
              {filtered.map((record) => (
                <tr key={record.id}>
                  <td>
                    {record.name}
                    <br />
                    <span className="muted">{record.legal_basis}</span>
                  </td>
                  <td>
                    {record.scope}
                    <br />
                    <span className="muted">{record.category}</span>
                  </td>
                  <td>
                    {record.schedule_id}
                    <br />
                    <span className="muted">{record.retention_period}</span>
                  </td>
                  <td>{retentionDisposalLabel(t, record.disposal_action)}</td>
                  <td>
                    <Badge tone={retentionStatusTone(record.status)}>
                      {retentionStatusLabel(t, record.status)}
                    </Badge>
                    <br />
                    <span className="muted">
                      {record.active
                        ? t('settings.privacy.retention.active.true')
                        : t('settings.privacy.retention.active.false')}
                    </span>
                  </td>
                  <td>{t('settings.privacy.retention.execution.false')}</td>
                  <td className="users-actions">
                    <Button
                      type="button"
                      variant="ghost"
                      icon={<Icon.Pencil />}
                      disabled={saving}
                      onClick={() => {
                        setEditingId(record.id);
                        setForm(retentionFormFromRecord(record));
                      }}
                    >
                      {t('settings.privacy.action.edit')}
                    </Button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      </Card>
      <RetentionLegalHoldDisposalStatusPanel
        report={dueCandidatesReport}
        records={executionRecords}
      />
      <RetentionDueCandidatesPanel
        report={dueCandidatesReport}
        loading={dueCandidatesLoading}
        error={dueCandidatesError}
        reviewRequestPending={reviewRequestPending}
        requestingReviewCandidateId={requestingReviewCandidateId}
        executionRecords={executionRecords}
        onRequestReview={onRequestReview}
      />
      <RetentionDryRunPanel running={runningDryRun} report={dryRunReport} onDryRun={onDryRun} />
      <RetentionExecutionReviewQueue
        records={executionRecords}
        loading={executionLoading}
        error={executionError}
        statusFilter={executionStatusFilter}
        onStatusFilterChange={onExecutionStatusFilterChange}
      />
    </div>
  );
}

export function PrivacyComplianceSection() {
  const t = useT();
  const can = useCan();
  const canManage = can('user.manage') || can('settings.manage');
  const [retentionExecutionStatusFilter, setRetentionExecutionStatusFilter] = useState<
    RetentionExecutionStatus | 'all'
  >('all');
  const [retentionReviewCandidateId, setRetentionReviewCandidateId] = useState<string | null>(null);
  const processors = usePrivacyProcessors(canManage);
  const dpias = usePrivacyDpias(canManage);
  const breachPlaybooks = usePrivacyBreachPlaybooks(canManage);
  const transferControls = usePrivacyTransferControls(canManage);
  const retentionPolicies = usePrivacyRetentionPolicies(canManage);
  const retentionDueCandidates = usePrivacyRetentionDueCandidates(canManage);
  const retentionExecutions = usePrivacyRetentionExecutions(
    retentionExecutionStatusFilter,
    canManage,
  );
  const createProcessor = useCreatePrivacyProcessor();
  const patchProcessor = usePatchPrivacyProcessor();
  const createDpia = useCreatePrivacyDpia();
  const patchDpia = usePatchPrivacyDpia();
  const createBreachPlaybook = useCreatePrivacyBreachPlaybook();
  const patchBreachPlaybook = usePatchPrivacyBreachPlaybook();
  const createTransferControl = useCreatePrivacyTransferControl();
  const patchTransferControl = usePatchPrivacyTransferControl();
  const createRetentionPolicy = useCreatePrivacyRetentionPolicy();
  const patchRetentionPolicy = usePatchPrivacyRetentionPolicy();
  const dryRunRetentionPolicy = useDryRunPrivacyRetentionPolicy();
  const toast = useToast();

  async function dryRunRetention(form: RetentionDryRunFormState) {
    try {
      await dryRunRetentionPolicy.mutateAsync({
        scope: form.scope.trim(),
        category: form.category.trim(),
        record_id: optionalText(form.recordId),
      });
    } catch (e) {
      toast.error(e);
    }
  }

  async function requestRetentionReview(
    candidate: RetentionDueCandidate,
    executionMode: 'review_only' | 'execute_supported' = 'review_only',
  ) {
    const body: RetentionDryRunBody = {
      scope: candidate.scope,
      category: candidate.category,
      record_id: candidate.record_id,
      execution_request: {
        requested_policy_id: candidate.policy_id,
        execution_mode: executionMode,
      },
    };

    setRetentionReviewCandidateId(candidate.candidate_id);
    try {
      const report = await dryRunRetentionPolicy.mutateAsync(body);
      const isArchiveEvidenceRequest =
        executionMode === 'execute_supported' && candidate.disposal_action === 'archive';
      toast.success(
        report.execution_record
          ? executionMode === 'execute_supported'
            ? isArchiveEvidenceRequest
              ? 'Evidência delimitada de arquivo registada.'
              : 'Evidência delimitada sem ação registada.'
            : 'Pedido de revisão de evidência registado.'
          : executionMode === 'execute_supported'
            ? isArchiveEvidenceRequest
              ? 'Pedido de evidência de arquivo enviado; sem registo devolvido.'
              : 'Pedido de evidência sem ação enviado; sem registo devolvido.'
            : 'Pedido de revisão enviado; sem registo de execução devolvido.',
      );
    } catch (e) {
      toast.error(e);
    } finally {
      setRetentionReviewCandidateId(null);
    }
  }

  if (!canManage) {
    return (
      <Card title={t('settings.privacy.title')}>
        <PermissionDeniedNote />
      </Card>
    );
  }

  return (
    <div className="stack">
      <InlineWarning tone="info" title={t('settings.privacy.notice.title')}>
        {t('settings.privacy.notice.body')}
      </InlineWarning>

      <RegisterPanel
        kind="processor"
        title="Processadores GDPR"
        lede="Registo dos processadores, subprocessadores e categorias de dados tratados por terceiros."
        records={processors.data ?? []}
        loading={processors.isLoading}
        error={processors.error}
        saving={createProcessor.isPending || patchProcessor.isPending}
        onCreate={(body) => createProcessor.mutateAsync(body as CreateProcessorRecordBody)}
        onPatch={(id, body) =>
          patchProcessor.mutateAsync({ id, body: body as PatchProcessorRecordBody })
        }
      />

      <RegisterPanel
        kind="dpia"
        title="DPIAs"
        lede="Avaliações de impacto com finalidade, base legal, categorias de dados e risco atual."
        records={dpias.data ?? []}
        loading={dpias.isLoading}
        error={dpias.error}
        saving={createDpia.isPending || patchDpia.isPending}
        onCreate={(body) => createDpia.mutateAsync(body as CreateDpiaRecordBody)}
        onPatch={(id, body) => patchDpia.mutateAsync({ id, body: body as PatchDpiaRecordBody })}
      />

      <BreachPlaybookPanel
        records={breachPlaybooks.data ?? []}
        loading={breachPlaybooks.isLoading}
        error={breachPlaybooks.error}
        saving={createBreachPlaybook.isPending || patchBreachPlaybook.isPending}
        onCreate={(body) => createBreachPlaybook.mutateAsync(body)}
        onPatch={(id, body) => patchBreachPlaybook.mutateAsync({ id, body })}
      />

      <TransferControlPanel
        records={transferControls.data ?? []}
        loading={transferControls.isLoading}
        error={transferControls.error}
        saving={createTransferControl.isPending || patchTransferControl.isPending}
        onCreate={(body) => createTransferControl.mutateAsync(body)}
        onPatch={(id, body) => patchTransferControl.mutateAsync({ id, body })}
      />

      <RetentionPolicyPanel
        records={retentionPolicies.data ?? []}
        loading={retentionPolicies.isLoading}
        error={retentionPolicies.error}
        saving={createRetentionPolicy.isPending || patchRetentionPolicy.isPending}
        runningDryRun={dryRunRetentionPolicy.isPending}
        dryRunReport={dryRunRetentionPolicy.data ?? null}
        dueCandidatesReport={retentionDueCandidates.data ?? null}
        dueCandidatesLoading={retentionDueCandidates.isLoading}
        dueCandidatesError={retentionDueCandidates.error}
        reviewRequestPending={dryRunRetentionPolicy.isPending}
        requestingReviewCandidateId={retentionReviewCandidateId}
        executionRecords={retentionExecutions.data ?? []}
        executionLoading={retentionExecutions.isLoading}
        executionError={retentionExecutions.error}
        executionStatusFilter={retentionExecutionStatusFilter}
        onCreate={(body) => createRetentionPolicy.mutateAsync(body)}
        onPatch={(id, body) => patchRetentionPolicy.mutateAsync({ id, body })}
        onDryRun={dryRunRetention}
        onRequestReview={requestRetentionReview}
        onExecutionStatusFilterChange={setRetentionExecutionStatusFilter}
      />
    </div>
  );
}
