import { useDeferredValue, useMemo, useState, type FormEvent, type ReactNode } from 'react';
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
  usePrivacyDpiaTemplate,
  usePrivacyDpias,
  usePrivacyRetentionCandidateResolutions,
  usePrivacyRetentionDueCandidates,
  usePrivacyProcessors,
  usePrivacyRetentionExecutions,
  usePrivacyRetentionPolicies,
  usePrivacyTransferControls,
  useRecordPrivacyRetentionCandidateResolution,
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
  type DpiaTemplateNoClaims,
  type DpiaTemplateView,
  type PatchBreachPlaybookBody,
  type PatchDpiaRecordBody,
  type PatchProcessorRecordBody,
  type PatchRetentionPolicyBody,
  type PatchTransferControlBody,
  PRIVACY_ADVISORY_REVIEW_STATUSES,
  type PrivacyAdvisoryReviewStatus,
  type PrivacyAdvisoryReviewSummary,
  type PrivacyRecordStatus,
  type PrivacyRiskLevel,
  type ProcessorRecordView,
  type RetentionCandidateDisposition,
  type RetentionCandidateResolutionBody,
  type RetentionCandidateResolutionRecord,
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
  type RetentionOperatorReviewDecision,
  type RetentionPolicyStatus,
  type RetentionPolicyView,
  type RetentionReviewClosureDecision,
  type TransferControlView,
} from '../../api/types';
import { formatTimestamp } from '../../format';
import { t as translateNow, useT, type MessageKey, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  Select,
  SkeletonTable,
  SubNav,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { PermissionDeniedNote, useCan } from '../session/permissions';
import {
  dpiaChecklistLabelKey,
  dpiaOperatorActionKey,
  dpiaSectionDescKey,
  dpiaSectionPromptKey,
  dpiaSectionTitleKey,
} from '../../i18n/dpiaTemplateLabels';
import { RegisterEditModal } from './RegisterEditModal';

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

const STATUS_LABEL_KEYS: Record<PrivacyRecordStatus, MessageKey> = {
  draft: 'settings.privacy.status.draft',
  active: 'settings.privacy.status.active',
  under_review: 'settings.privacy.status.underReview',
  retired: 'settings.privacy.status.retired',
};

const RISK_LABEL_KEYS: Record<PrivacyRiskLevel, MessageKey> = {
  low: 'settings.privacy.risk.low',
  medium: 'settings.privacy.risk.medium',
  high: 'settings.privacy.risk.high',
  critical: 'settings.privacy.risk.critical',
};

const ADVISORY_REVIEW_LABEL_KEYS: Record<PrivacyAdvisoryReviewStatus, MessageKey> = {
  no_receipt: 'settings.privacy.advisory.noReceipt',
  current: 'settings.privacy.advisory.current',
  due_soon: 'settings.privacy.advisory.dueSoon',
  overdue: 'settings.privacy.advisory.overdue',
  under_review: 'settings.privacy.advisory.underReview',
};

function statusLabel(t: TFunction, status: PrivacyRecordStatus): string {
  return t(STATUS_LABEL_KEYS[status]);
}

function riskLabel(t: TFunction, risk: PrivacyRiskLevel): string {
  return t(RISK_LABEL_KEYS[risk]);
}

function advisoryReviewLabel(t: TFunction, status: PrivacyAdvisoryReviewStatus): string {
  return t(ADVISORY_REVIEW_LABEL_KEYS[status]);
}

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

const RETENTION_EXECUTION_STATUS_LABEL_KEYS: Record<RetentionExecutionStatus, MessageKey> = {
  awaiting_review: 'settings.privacy.execution.status.awaitingReview',
  blocked: 'settings.privacy.execution.status.blocked',
  executed: 'settings.privacy.execution.status.executed',
};

/**
 * The operator's review decision on a queued execution — a state THIS system records, which is
 * why it can be given a label. It was previously rendered as its raw wire identifier
 * (`review_required`) in the queue's status cell.
 */
const RETENTION_OPERATOR_REVIEW_DECISION_LABEL_KEYS: Record<
  RetentionOperatorReviewDecision,
  MessageKey
> = {
  review_required: 'settings.privacy.execution.decision.reviewRequired',
  blocked: 'settings.privacy.execution.decision.blocked',
  execution_recorded: 'settings.privacy.execution.decision.executionRecorded',
};

const RETENTION_OPERATOR_REVIEW_DECISIONS = [
  'review_required',
  'blocked',
  'execution_recorded',
] as const satisfies readonly RetentionOperatorReviewDecision[];

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

function statusFilterOptions(t: TFunction) {
  return [
    { value: 'all', label: t('settings.privacy.status.all') },
    ...PRIVACY_RECORD_STATUSES.map((status) => ({ value: status, label: statusLabel(t, status) })),
  ];
}

function riskFilterOptions(t: TFunction) {
  return [
    { value: 'all', label: t('settings.privacy.risk.all') },
    ...PRIVACY_RISK_LEVELS.map((risk) => ({ value: risk, label: riskLabel(t, risk) })),
  ];
}

/**
 * Filter chrome shared by every register on this tab (t102).
 *
 * This is the shape every list page in the app already uses — Entidades, Livros, Arquivo,
 * Modelos, Utilizadores — reproduced here because Privacidade was the one register area that
 * had bare `<div className="filter">` with no primary bar, no clear affordance and no result
 * count. See `.entities-filterbar` / `.books-filterbar` in theme.css for the siblings; the
 * `filter-advanced` classes are the already-generic half of that vocabulary.
 *
 * Filters are LOCAL STATE, deliberately, and are NOT synchronised to the query string. No list
 * surface in this app puts filters in the URL, and Privacidade is not the place to start
 * diverging: `t97`'s rule moves *navigation identity* out of the query, which says nothing about
 * filters moving in. If linkable filtered views are ever wanted they are one app-wide change.
 */
function PrivacyFilterBar({
  name,
  hasFilters,
  onClear,
  children,
  advanced,
}: {
  /** The register's own title, for the search landmark's accessible name. */
  name: string;
  hasFilters: boolean;
  onClear: () => void;
  children: ReactNode;
  advanced?: ReactNode;
}) {
  const t = useT();
  return (
    <div
      className="stack--tight privacy-filters"
      role="search"
      aria-label={t('settings.privacy.filters.aria', { name })}
    >
      <div className="privacy-filterbar filter">
        <div className="privacy-filterbar__primary">
          {children}
          <IconButton
            className="privacy-filterbar__clear"
            icon={<Icon.Close />}
            label={t('settings.privacy.filters.clear')}
            disabled={!hasFilters}
            onClick={onClear}
          />
        </div>
      </div>
      {advanced ? (
        <details className="privacy-advanced-filters filter-advanced">
          <summary>{t('settings.privacy.filters.advanced')}</summary>
          <div className="privacy-advanced-filters__body filter filter-advanced__body">
            {advanced}
          </div>
        </details>
      ) : null}
    </div>
  );
}

/**
 * "N of M" beside a register's title. Carries a spelled-out `aria-label` because the badge
 * itself reads as two bare numerals; the same pairing Entidades and Livros use.
 */
function FilterCountBadge({ shown, total }: { shown: number; total: number }) {
  const t = useT();
  if (total === 0) return null;
  return (
    <span aria-label={t('settings.privacy.filters.countAria', { shown, total })}>
      <Badge>{t('settings.privacy.filters.count', { shown, total })}</Badge>
    </span>
  );
}

/** Advisory-review state — carried by DPIAs, playbooks and transfer controls alike. */
function advisoryReviewFilterOptions(t: TFunction) {
  return [
    { value: 'all', label: t('settings.privacy.filter.review.all') },
    ...PRIVACY_ADVISORY_REVIEW_STATUSES.map((status) => ({
      value: status,
      label: advisoryReviewLabel(t, status),
    })),
  ];
}

function presenceFilterOptions(
  t: TFunction,
  allKey: MessageKey,
  withKey: MessageKey,
  withoutKey: MessageKey,
) {
  return [
    { value: 'all', label: t(allKey) },
    { value: 'with', label: t(withKey) },
    { value: 'without', label: t(withoutKey) },
  ];
}

/** `with` / `without` against a boolean the row already carries. */
function matchesPresence(filter: string, present: boolean): boolean {
  if (filter === 'all') return true;
  return filter === 'with' ? present : !present;
}

function statusSelectOptionsFor(t: TFunction) {
  return PRIVACY_RECORD_STATUSES.map((status) => ({
    value: status,
    label: statusLabel(t, status),
  }));
}

function riskSelectOptionsFor(t: TFunction) {
  return PRIVACY_RISK_LEVELS.map((risk) => ({ value: risk, label: riskLabel(t, risk) }));
}

function breachEvidenceOptionsFor(t: TFunction): { value: BreachEvidenceKind; label: string }[] {
  return [
    { value: 'review', label: t('settings.privacy.evidence.kind.review') },
    { value: 'drill', label: t('settings.privacy.evidence.kind.drill') },
  ];
}

function retentionStatusLabel(t: TFunction, status: RetentionPolicyStatus): string {
  return t(RETENTION_STATUS_LABEL_KEYS[status]);
}

function retentionDisposalLabel(t: TFunction, action: RetentionDisposalAction): string {
  return t(RETENTION_DISPOSAL_LABEL_KEYS[action]);
}

function retentionExecutionStatusLabel(t: TFunction, status: RetentionExecutionStatus): string {
  return t(RETENTION_EXECUTION_STATUS_LABEL_KEYS[status]);
}

function retentionOperatorReviewDecisionLabel(
  t: TFunction,
  decision: RetentionOperatorReviewDecision,
): string {
  return t(RETENTION_OPERATOR_REVIEW_DECISION_LABEL_KEYS[decision]);
}

function executionDecisionFilterOptions(t: TFunction) {
  return [
    { value: 'all', label: t('settings.privacy.filter.decision.all') },
    ...RETENTION_OPERATOR_REVIEW_DECISIONS.map((decision) => ({
      value: decision,
      label: retentionOperatorReviewDecisionLabel(t, decision),
    })),
  ];
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

function retentionCandidateResolutionDisposition(
  candidate: RetentionDueCandidate,
): RetentionCandidateDisposition {
  if (
    candidate.status === 'blocked' ||
    candidate.destructive_action ||
    candidate.legal_hold_blockers.length > 0 ||
    candidate.blockers.length > 0 ||
    candidate.findings.length > 0
  ) {
    return 'blocked_follow_up';
  }
  return 'evidence_acknowledged';
}

function retentionCandidateResolutionBody(
  candidate: RetentionDueCandidate,
): RetentionCandidateResolutionBody {
  const disposition = retentionCandidateResolutionDisposition(candidate);
  return {
    candidate_fingerprint: candidate.candidate_fingerprint,
    disposition,
    note:
      disposition === 'blocked_follow_up'
        ? 'Seguimento bloqueado registado para evidencia local; sem alteracao dos registos fonte.'
        : 'Disposicao de evidencia local registada; sem alteracao dos registos fonte.',
    evidence: [
      {
        label: 'candidate_id',
        value: candidate.candidate_id,
      },
      {
        label: 'record_id',
        value: candidate.record_id,
      },
    ],
    destructive_disposal_completed: false,
    disposal_completed: false,
    full_erasure_completed: false,
    erasure_completed: false,
    legal_hold_mutated: false,
    legal_hold_resolved: false,
    retention_policy_mutated: false,
    retention_policy_changed: false,
    legal_completion_claimed: false,
    legal_disposal_completed: false,
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

function advisoryReviewDetail(t: TFunction, review: PrivacyAdvisoryReviewSummary): string {
  if (review.status === 'no_receipt') return t('settings.privacy.advisory.detail.noReceipt');
  if (review.status === 'under_review') return t('settings.privacy.advisory.detail.underReview');
  const due = review.next_review_due_at
    ? t('settings.privacy.advisory.detail.nextReview', { date: review.next_review_due_at })
    : '';
  const last = review.last_reviewed_at ?? review.last_drill_at;
  const lastText = last
    ? t('settings.privacy.advisory.detail.lastEvidence', { date: formatDateTime(last) })
    : '';
  return [due, lastText, t('settings.privacy.advisory.detail.noClaims')].filter(Boolean).join(' ');
}

function AdvisoryReviewBadge({ review }: { review: PrivacyAdvisoryReviewSummary }) {
  const t = useT();
  return (
    <div className="stack--tight">
      <Badge tone={advisoryReviewTone(review.status)}>
        {advisoryReviewLabel(t, review.status)}
      </Badge>
      <span className="muted">{advisoryReviewDetail(t, review)}</span>
    </div>
  );
}

function DpiaTemplateGuidancePanel({
  template,
  loading,
  error,
}: {
  template: DpiaTemplateView | null;
  loading: boolean;
  error: unknown;
}) {
  const t = useT();
  const noClaims = template
    ? (Object.entries(template.no_claims) as [keyof DpiaTemplateNoClaims, false][])
    : [];

  return (
    <Card
      title={
        <span className="row-wrap">
          {t('settings.privacy.guidance.title')}
          <FieldHelp text={t('settings.privacy.help.guidance')} />
        </span>
      }
    >
      <div className="stack">
        <p className="field__hint">{t('settings.privacy.guidance.lede')}</p>
        {loading ? (
          <SkeletonTable cols={3} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : !template ? (
          <EmptyState title={t('settings.privacy.guidance.empty.title')}>
            <p>{t('settings.privacy.guidance.empty.body')}</p>
          </EmptyState>
        ) : (
          <>
            <dl className="deflist">
              <div>
                <dt>{t('settings.privacy.guidance.dl.id')}</dt>
                <dd>{template.template_id}</dd>
              </div>
              <div>
                <dt>{t('settings.privacy.guidance.dl.scope')}</dt>
                <dd>{template.scope}</dd>
              </div>
              <div>
                <dt>{t('settings.privacy.guidance.dl.execution')}</dt>
                <dd className="mono">
                  local_offline_guidance_only: {String(template.local_offline_guidance_only)}
                </dd>
              </div>
            </dl>

            <Table
              head={
                <tr>
                  <th>{t('settings.privacy.guidance.column.section')}</th>
                  <th>{t('settings.privacy.guidance.column.prompts')}</th>
                  <th>{t('settings.privacy.guidance.column.checklist')}</th>
                </tr>
              }
            >
              {template.sections.map((section) => {
                // The template's wire copy is English; the client resolves each stable id to a
                // translated catalog key. An unknown id (a backend section added later) yields
                // `undefined`, so we fall back to the raw English rather than render blank —
                // `dpiaTemplateLabels.test.ts` fails loudly if that fallback ever fires in prod.
                const titleKey = dpiaSectionTitleKey(section.id);
                const descKey = dpiaSectionDescKey(section.id);
                return (
                  <tr key={section.id}>
                    <td>
                      {titleKey ? t(titleKey) : section.title}
                      <br />
                      <span className="muted">{descKey ? t(descKey) : section.description}</span>
                    </td>
                    <td>
                      <ul>
                        {section.prompts.map((prompt, index) => {
                          const promptKey = dpiaSectionPromptKey(section.id, index);
                          return (
                            <li key={`${section.id}-${index}`}>
                              {promptKey ? t(promptKey) : prompt}
                            </li>
                          );
                        })}
                      </ul>
                    </td>
                    <td>
                      <ul>
                        {section.checklist.map((item) => {
                          // Only the label is translated. `field_type` is a wire identifier shown
                          // in `mono` and stays verbatim (like the no_claims flags below).
                          const labelKey = dpiaChecklistLabelKey(item.id);
                          return (
                            <li key={item.id}>
                              {labelKey ? t(labelKey) : item.label} ·{' '}
                              <span className="mono">{item.field_type}</span> ·{' '}
                              {t('settings.privacy.guidance.required', {
                                value: String(item.required),
                              })}
                            </li>
                          );
                        })}
                      </ul>
                    </td>
                  </tr>
                );
              })}
            </Table>

            {/*
              The "Flags sem alegação" disclosure (t102). This was a `tag-row` of loose inline
              spans — `key: false` pairs wrapping mid-line under a proper Table — which is the
              rendering the user reported as not neatly displayed. It is a two-column grid, so
              it is a table.

              The flag IDENTIFIER is deliberately NOT translated. Each one names a legal claim
              this product does not make (`cnpd_filing_completed`, `legal_review_accepted`), and
              authoring 28 Portuguese renderings of legal claims is exactly the copy this area
              must not invent — the same boundary TRANSLATIONS.md draws for the names of legal
              instruments, which render verbatim in every locale. The column headers and the
              state carry the translation; the identifier stays the backend's own wire name.
            */}
            <details className="privacy-disclosure">
              <summary>{t('settings.privacy.guidance.noClaims')}</summary>
              {/*
                No `caption`: the `<summary>` immediately above already names this table, and a
                visually hidden caption repeating it would announce the same phrase twice. The
                sibling guidance table in this panel is captionless for the same reason.
              */}
              <Table
                head={
                  <tr>
                    <th>{t('settings.privacy.guidance.column.claim')}</th>
                    <th>{t('settings.privacy.guidance.column.claimState')}</th>
                  </tr>
                }
              >
                {noClaims.map(([key]) => (
                  <tr key={key}>
                    <td className="mono">{key}</td>
                    <td>
                      <Badge tone="neutral">{t('settings.privacy.guidance.notClaimed')}</Badge>
                    </td>
                  </tr>
                ))}
              </Table>
            </details>

            <div className="stack--tight">
              <strong>{t('settings.privacy.guidance.operatorActions')}</strong>
              <ul>
                {template.operator_actions.map((action, index) => {
                  const actionKey = dpiaOperatorActionKey(index);
                  return (
                    <li key={`operator-action-${index}`}>{actionKey ? t(actionKey) : action}</li>
                  );
                })}
              </ul>
            </div>
          </>
        )}
      </div>
    </Card>
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

/**
 * Compliance receipts, DPIA stamps and retention executions are evidence, so they render at
 * evidentiary precision — seconds plus the zone abbreviation. Kept as a thin local alias
 * because a dozen call sites interpolate it into `t(...)` params as a plain string; the
 * formatting itself lives in the shared date family. It previously hard-coded `'pt-PT'`,
 * showing Portuguese dates to readers of the other thirteen shipped locales.
 */
function formatDateTime(value: string): string {
  return formatTimestamp(value);
}

function latestReceipt<T extends { recorded_at: string }>(receipts: T[]): T | undefined {
  return [...receipts].sort((a, b) => b.recorded_at.localeCompare(a.recorded_at))[0];
}

function renderUnknownEvidence(t: TFunction, value: unknown): string {
  if (value === null || value === undefined) return t('settings.privacy.evidence.noDetail');
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) return value.map((item) => renderUnknownEvidence(t, item)).join(', ');
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== null && item !== undefined && item !== '')
      .map(([key, item]) => `${key}: ${renderUnknownEvidence(t, item)}`);
    return entries.length > 0 ? entries.join(' · ') : t('settings.privacy.evidence.noDetail');
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
  const t = useT();
  const summary = retentionLegalHoldDisposalStatusSummary(report, records);
  return (
    <Card
      title={
        <span className="row-wrap">
          {t('settings.privacy.legalHold.title')}
          <FieldHelp text={t('settings.privacy.help.legalHold')} />
        </span>
      }
    >
      <div className="stack">
        <InlineWarning tone="info" title={t('settings.privacy.legalHold.evidence.title')}>
          {t('settings.privacy.legalHold.evidence.body')}
        </InlineWarning>
        <dl className="deflist">
          <div>
            <dt>{t('settings.privacy.legalHold.dl.candidates')}</dt>
            <dd>{summary.dueCandidateLegalHoldBlockers}</dd>
          </div>
          <div>
            <dt>{t('settings.privacy.legalHold.dl.executions')}</dt>
            <dd>{summary.executionLegalHoldBlocks}</dd>
          </div>
          <div>
            <dt>{t('settings.privacy.legalHold.dl.openReviews')}</dt>
            <dd>{summary.openBlockedReviews}</dd>
          </div>
          <div>
            <dt>{t('settings.privacy.legalHold.dl.flags')}</dt>
            <dd className="mono">
              destructive_disposal_completed: false · disposal_approved: false ·
              legal_compliance_claimed: false
            </dd>
          </div>
        </dl>
        <p className="field__hint">{t('settings.privacy.legalHold.source')}</p>
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
  const t = useT();
  const idPrefix = `privacy-${kind}-${editing ? 'edit' : 'new'}`;
  const primaryLabel =
    kind === 'processor'
      ? t('settings.privacy.register.field.processorName')
      : t('settings.privacy.register.field.dpiaTitle');
  const parsedCategories = splitList(form.dataCategories);
  const canSubmit =
    form.primary.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    parsedCategories.length > 0 &&
    !saving;

  return (
    <form
      className="form settings-rows"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field
        label={primaryLabel}
        htmlFor={`${idPrefix}-primary`}
        help={
          kind === 'processor'
            ? t('settings.privacy.help.processor')
            : t('settings.privacy.help.dpia')
        }
      >
        <Input
          id={`${idPrefix}-primary`}
          value={form.primary}
          onChange={(e) => setForm({ ...form, primary: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.purpose')}
        htmlFor={`${idPrefix}-purpose`}
        help={t('settings.privacy.help.purpose')}
      >
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.legalBasis')}
        htmlFor={`${idPrefix}-legal-basis`}
        help={t('settings.privacy.help.legalBasis')}
      >
        <Input
          id={`${idPrefix}-legal-basis`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.categories')}
        htmlFor={`${idPrefix}-data-categories`}
        hint={t('settings.privacy.register.hint.categories')}
      >
        <TextArea
          id={`${idPrefix}-data-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.subprocessors')}
        htmlFor={`${idPrefix}-subprocessors`}
        hint={t('settings.privacy.register.hint.subprocessors')}
      >
        <TextArea
          id={`${idPrefix}-subprocessors`}
          value={form.subprocessors}
          onChange={(e) => setForm({ ...form, subprocessors: e.target.value })}
          rows={3}
        />
      </Field>

      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.field.risk')}
          htmlFor={`${idPrefix}-risk`}
          help={t('settings.privacy.help.risk')}
        >
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptionsFor(t)}
          />
        </Field>
        <Field
          label={t('settings.privacy.field.status')}
          htmlFor={`${idPrefix}-status`}
          help={t('settings.privacy.help.status')}
        >
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptionsFor(t)}
          />
        </Field>
      </div>

      {kind === 'dpia' ? (
        <>
          <InlineWarning tone="info" title={t('settings.privacy.evidence.operator.title')}>
            {t('settings.privacy.evidence.operator.dpiaBody')}
          </InlineWarning>
          <div className="api-key-rate-grid">
            <Field
              label={t('settings.privacy.evidence.field.type')}
              htmlFor={`${idPrefix}-evidence-type`}
            >
              <Select
                id={`${idPrefix}-evidence-type`}
                value={form.evidenceType}
                onChange={(e) =>
                  setForm({ ...form, evidenceType: e.target.value as DpiaEvidenceKind })
                }
                options={breachEvidenceOptionsFor(t)}
              />
            </Field>
            <Field
              label={t('settings.privacy.evidence.field.notes')}
              htmlFor={`${idPrefix}-evidence-notes`}
            >
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

function RegisterPanel({
  kind,
  title,
  lede,
  help,
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
  help: string;
  records: RegisterRecord[];
  loading: boolean;
  error: unknown;
  saving: boolean;
  onCreate: (body: PrivacyCreateBody) => Promise<RegisterRecord>;
  onPatch: (id: string, body: PrivacyPatchBody) => Promise<RegisterRecord>;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  // `useDeferredValue` is the debounce every list page in this app uses — it keeps the input
  // responsive while the filter pass runs against the stale value, with no timer to clean up.
  const deferredSearch = useDeferredValue(search);
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [subprocessorFilter, setSubprocessorFilter] = useState('all');
  const [evidenceFilter, setEvidenceFilter] = useState('all');
  const [reviewFilter, setReviewFilter] = useState('all');
  const [form, setForm] = useState<RegisterFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Only DPIAs carry evidence receipts and an advisory-review summary; the processor register
  // has neither, so it does not get the two filters that would always read "all".
  const hasDpiaAxes = kind === 'dpia';

  const filtered = useMemo(() => {
    const q = normalizeSearch(deferredSearch.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      if (!matchesPresence(subprocessorFilter, record.subprocessors.length > 0)) return false;
      if (hasDpiaAxes) {
        const dpia = record as DpiaRecordView;
        if (!matchesPresence(evidenceFilter, dpia.evidence_receipts.length > 0)) return false;
        if (reviewFilter !== 'all' && dpia.advisory_review.status !== reviewFilter) return false;
      }
      return q.length === 0 || recordSearchText(kind, record).includes(q);
    });
  }, [
    deferredSearch,
    evidenceFilter,
    hasDpiaAxes,
    kind,
    records,
    reviewFilter,
    riskFilter,
    statusFilter,
    subprocessorFilter,
  ]);

  const hasFilters =
    search.trim() !== '' ||
    statusFilter !== 'all' ||
    riskFilter !== 'all' ||
    subprocessorFilter !== 'all' ||
    evidenceFilter !== 'all' ||
    reviewFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setStatusFilter('all');
    setRiskFilter('all');
    setSubprocessorFilter('all');
    setEvidenceFilter('all');
    setReviewFilter('all');
  }

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
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await onCreate(createBody(kind, form));
        toast.success(t('settings.privacy.toast.created'));
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
      toast.success(t('settings.privacy.toast.updated'));
    } catch (e) {
      toast.error(e);
    }
  }

  function closeForm() {
    setForm(null);
    setEditingId(null);
  }

  return (
    <div className="stack">
      <RegisterEditModal
        open={form !== null}
        onClose={closeForm}
        busy={saving}
        title={editingId ? t('settings.privacy.form.edit') : t('settings.privacy.form.new')}
      >
        {form ? (
          <RegisterForm
            kind={kind}
            form={form}
            setForm={setForm}
            editing={editingId !== null}
            saving={saving}
            onCancel={closeForm}
            onSubmit={submitForm}
          />
        ) : null}
      </RegisterEditModal>

      <Card
        title={
          <span className="row-wrap">
            {title}
            <FieldHelp text={help} />
          </span>
        }
        actions={
          <>
            <FilterCountBadge shown={filtered.length} total={records.length} />
            <Button type="button" variant="primary" icon={<Icon.Plus />} onClick={startCreate}>
              {t('settings.privacy.action.new')}
            </Button>
          </>
        }
      >
        <div className="stack">
          <p className="field__hint">{lede}</p>

          <PrivacyFilterBar
            name={title}
            hasFilters={hasFilters}
            onClear={clearFilters}
            advanced={
              <>
                <Field
                  label={t('settings.privacy.filter.subprocessors')}
                  htmlFor={`privacy-${kind}-subprocessor-filter`}
                >
                  <Select
                    id={`privacy-${kind}-subprocessor-filter`}
                    value={subprocessorFilter}
                    onChange={(e) => setSubprocessorFilter(e.target.value)}
                    options={presenceFilterOptions(
                      t,
                      'settings.privacy.filter.subprocessors.all',
                      'settings.privacy.filter.subprocessors.with',
                      'settings.privacy.filter.subprocessors.without',
                    )}
                  />
                </Field>
                {hasDpiaAxes ? (
                  <>
                    <Field
                      label={t('settings.privacy.filter.evidence')}
                      htmlFor={`privacy-${kind}-evidence-filter`}
                    >
                      <Select
                        id={`privacy-${kind}-evidence-filter`}
                        value={evidenceFilter}
                        onChange={(e) => setEvidenceFilter(e.target.value)}
                        options={presenceFilterOptions(
                          t,
                          'settings.privacy.filter.evidence.all',
                          'settings.privacy.filter.evidence.with',
                          'settings.privacy.filter.evidence.without',
                        )}
                      />
                    </Field>
                    <Field
                      label={t('settings.privacy.filter.review')}
                      htmlFor={`privacy-${kind}-review-filter`}
                    >
                      <Select
                        id={`privacy-${kind}-review-filter`}
                        value={reviewFilter}
                        onChange={(e) => setReviewFilter(e.target.value)}
                        options={advisoryReviewFilterOptions(t)}
                      />
                    </Field>
                  </>
                ) : null}
              </>
            }
          >
            <Field label={t('settings.privacy.filter.search')} htmlFor={`privacy-${kind}-search`}>
              <Input
                id={`privacy-${kind}-search`}
                type="search"
                value={search}
                placeholder={t('settings.privacy.register.searchPlaceholder')}
                onChange={(e) => setSearch(e.target.value)}
              />
            </Field>
            <Field
              label={t('settings.privacy.field.status')}
              htmlFor={`privacy-${kind}-status-filter`}
            >
              <Select
                id={`privacy-${kind}-status-filter`}
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                options={statusFilterOptions(t)}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor={`privacy-${kind}-risk-filter`}>
              <Select
                id={`privacy-${kind}-risk-filter`}
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskFilterOptions(t)}
              />
            </Field>
          </PrivacyFilterBar>

          {loading ? (
            <SkeletonTable cols={9} />
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
                  <th>
                    {kind === 'processor'
                      ? t('settings.privacy.register.column.processor')
                      : t('settings.privacy.register.column.dpia')}
                  </th>
                  <th>{t('settings.privacy.register.column.purpose')}</th>
                  <th>{t('settings.privacy.register.column.categories')}</th>
                  <th>{t('settings.privacy.register.column.subprocessors')}</th>
                  {kind === 'dpia' ? <th>{t('settings.privacy.column.evidence')}</th> : null}
                  <th>{t('settings.privacy.field.risk')}</th>
                  <th>{t('settings.privacy.field.status')}</th>
                  <th>{t('settings.privacy.register.column.updated')}</th>
                  <th>{t('settings.privacy.table.action')}</th>
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
                            {t('settings.privacy.evidence.receiptBy', {
                              kind:
                                dpiaReceipt.evidence_type === 'drill'
                                  ? t('settings.privacy.evidence.kind.drill')
                                  : t('settings.privacy.evidence.kind.review'),
                              actor: dpiaReceipt.recorded_by,
                            })}
                            <br />
                            <span className="muted">
                              {formatDateTime(dpiaReceipt.recorded_at)} ·{' '}
                              {t('settings.privacy.evidence.dpiaReceiptNote')}
                            </span>
                          </>
                        ) : (
                          <span className="muted">{t('settings.privacy.evidence.none')}</span>
                        )}
                      </td>
                    ) : null}
                    <td>
                      <span className="row-wrap">
                        <Badge tone={riskTone(record.risk_level)}>
                          {riskLabel(t, record.risk_level)}
                        </Badge>
                        <Select
                          aria-label={t('settings.privacy.register.aria.risk', { name: label })}
                          value={record.risk_level}
                          disabled={saving}
                          onChange={(e) =>
                            patchOne(record.id, {
                              risk_level: e.target.value as PrivacyRiskLevel,
                            })
                          }
                          options={riskSelectOptionsFor(t)}
                        />
                      </span>
                    </td>
                    <td>
                      <span className={dpiaRecord ? 'stack--tight' : 'row-wrap'}>
                        <Badge tone={statusTone(record.status)}>
                          {statusLabel(t, record.status)}
                        </Badge>
                        {dpiaRecord ? (
                          <AdvisoryReviewBadge review={dpiaRecord.advisory_review} />
                        ) : null}
                        <Select
                          aria-label={t('settings.privacy.register.aria.status', { name: label })}
                          value={record.status}
                          disabled={saving}
                          onChange={(e) =>
                            patchOne(record.id, {
                              status: e.target.value as PrivacyRecordStatus,
                            })
                          }
                          options={statusSelectOptionsFor(t)}
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
      className="form settings-rows"
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
            options={riskSelectOptionsFor(t)}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptionsFor(t)}
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
      <InlineWarning tone="info" title={t('settings.privacy.evidence.operator.title')}>
        {t('settings.privacy.evidence.operator.breachBody')}
      </InlineWarning>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.evidence.field.type')}
          htmlFor={`${idPrefix}-evidence-type`}
        >
          <Select
            id={`${idPrefix}-evidence-type`}
            value={form.evidenceType}
            onChange={(e) =>
              setForm({ ...form, evidenceType: e.target.value as BreachEvidenceKind })
            }
            options={breachEvidenceOptionsFor(t)}
          />
        </Field>
        <Field
          label={t('settings.privacy.evidence.field.notes')}
          htmlFor={`${idPrefix}-evidence-notes`}
        >
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
  const deferredSearch = useDeferredValue(search);
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [reviewFilter, setReviewFilter] = useState('all');
  const [evidenceFilter, setEvidenceFilter] = useState('all');
  const [form, setForm] = useState<BreachPlaybookFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(deferredSearch.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      if (reviewFilter !== 'all' && record.advisory_review.status !== reviewFilter) return false;
      if (!matchesPresence(evidenceFilter, record.evidence_receipts.length > 0)) return false;
      return q.length === 0 || breachSearchText(record).includes(q);
    });
  }, [deferredSearch, evidenceFilter, records, reviewFilter, riskFilter, statusFilter]);

  const hasFilters =
    search.trim() !== '' ||
    statusFilter !== 'all' ||
    riskFilter !== 'all' ||
    reviewFilter !== 'all' ||
    evidenceFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setStatusFilter('all');
    setRiskFilter('all');
    setReviewFilter('all');
    setEvidenceFilter('all');
  }

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
        title={
          <span className="row-wrap">
            {t('settings.privacy.breach.title')}
            <FieldHelp text={t('settings.privacy.help.breach')} />
          </span>
        }
        actions={
          <>
            <FilterCountBadge shown={filtered.length} total={records.length} />
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
          </>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.breach.lede')}</p>
          <PrivacyFilterBar
            name={t('settings.privacy.breach.title')}
            hasFilters={hasFilters}
            onClear={clearFilters}
            advanced={
              <>
                <Field
                  label={t('settings.privacy.filter.review')}
                  htmlFor="privacy-breach-review-filter"
                >
                  <Select
                    id="privacy-breach-review-filter"
                    value={reviewFilter}
                    onChange={(e) => setReviewFilter(e.target.value)}
                    options={advisoryReviewFilterOptions(t)}
                  />
                </Field>
                <Field
                  label={t('settings.privacy.filter.evidence')}
                  htmlFor="privacy-breach-evidence-filter"
                >
                  <Select
                    id="privacy-breach-evidence-filter"
                    value={evidenceFilter}
                    onChange={(e) => setEvidenceFilter(e.target.value)}
                    options={presenceFilterOptions(
                      t,
                      'settings.privacy.filter.evidence.all',
                      'settings.privacy.filter.evidence.with',
                      'settings.privacy.filter.evidence.without',
                    )}
                  />
                </Field>
              </>
            }
          >
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-breach-search">
              <Input
                id="privacy-breach-search"
                type="search"
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
                options={statusFilterOptions(t)}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor="privacy-breach-risk">
              <Select
                id="privacy-breach-risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskFilterOptions(t)}
              />
            </Field>
          </PrivacyFilterBar>
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
                  <th>{t('settings.privacy.column.evidence')}</th>
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
                          {t('settings.privacy.evidence.receiptBy', {
                            kind:
                              receipt.evidence_type === 'drill'
                                ? t('settings.privacy.evidence.kind.drill')
                                : t('settings.privacy.evidence.kind.review'),
                            actor: receipt.recorded_by,
                          })}
                          <br />
                          <span className="muted">
                            {formatDateTime(receipt.recorded_at)} ·{' '}
                            {t('settings.privacy.evidence.breachReceiptNote')}
                          </span>
                        </>
                      ) : (
                        <span className="muted">{t('settings.privacy.evidence.none')}</span>
                      )}
                    </td>
                    <td>
                      <Badge tone={riskTone(record.risk_level)}>
                        {riskLabel(t, record.risk_level)}
                      </Badge>
                    </td>
                    <td>
                      <div className="stack--tight">
                        <Badge tone={statusTone(record.status)}>
                          {statusLabel(t, record.status)}
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
      className="form settings-rows"
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
            options={riskSelectOptionsFor(t)}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptionsFor(t)}
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
      <InlineWarning tone="info" title={t('settings.privacy.evidence.operator.title')}>
        {t('settings.privacy.evidence.operator.transferBody')}
      </InlineWarning>
      <Field
        label={t('settings.privacy.evidence.field.notes')}
        htmlFor={`${idPrefix}-evidence-notes`}
      >
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
  const deferredSearch = useDeferredValue(search);
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [destinationFilter, setDestinationFilter] = useState('all');
  const [reviewFilter, setReviewFilter] = useState('all');
  const [form, setForm] = useState<TransferControlFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);

  // Destination options come from the rows actually loaded, the way Entidades derives its
  // family/kind options — so the list only ever offers destinations that exist.
  const destinationOptions = useMemo(() => {
    const seen = [...new Set(records.map((record) => record.destination_country.trim()))]
      .filter((value) => value !== '')
      .sort((a, b) => a.localeCompare(b));
    return [
      { value: 'all', label: t('settings.privacy.filter.destination.all') },
      ...seen.map((value) => ({ value, label: value })),
    ];
  }, [records, t]);

  const filtered = useMemo(() => {
    const q = normalizeSearch(deferredSearch.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (riskFilter !== 'all' && record.risk_level !== riskFilter) return false;
      if (destinationFilter !== 'all' && record.destination_country.trim() !== destinationFilter) {
        return false;
      }
      if (reviewFilter !== 'all' && record.advisory_review.status !== reviewFilter) return false;
      return q.length === 0 || transferSearchText(record).includes(q);
    });
  }, [deferredSearch, destinationFilter, records, reviewFilter, riskFilter, statusFilter]);

  const hasFilters =
    search.trim() !== '' ||
    statusFilter !== 'all' ||
    riskFilter !== 'all' ||
    destinationFilter !== 'all' ||
    reviewFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setStatusFilter('all');
    setRiskFilter('all');
    setDestinationFilter('all');
    setReviewFilter('all');
  }

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
        title={
          <span className="row-wrap">
            {t('settings.privacy.transfer.title')}
            <FieldHelp text={t('settings.privacy.help.transfer')} />
          </span>
        }
        actions={
          <>
            <FilterCountBadge shown={filtered.length} total={records.length} />
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
          </>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.transfer.lede')}</p>
          <PrivacyFilterBar
            name={t('settings.privacy.transfer.title')}
            hasFilters={hasFilters}
            onClear={clearFilters}
            advanced={
              <>
                <Field
                  label={t('settings.privacy.filter.destination')}
                  htmlFor="privacy-transfer-destination-filter"
                >
                  <Select
                    id="privacy-transfer-destination-filter"
                    value={destinationFilter}
                    onChange={(e) => setDestinationFilter(e.target.value)}
                    options={destinationOptions}
                  />
                </Field>
                <Field
                  label={t('settings.privacy.filter.review')}
                  htmlFor="privacy-transfer-review-filter"
                >
                  <Select
                    id="privacy-transfer-review-filter"
                    value={reviewFilter}
                    onChange={(e) => setReviewFilter(e.target.value)}
                    options={advisoryReviewFilterOptions(t)}
                  />
                </Field>
              </>
            }
          >
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-transfer-search">
              <Input
                id="privacy-transfer-search"
                type="search"
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
                options={statusFilterOptions(t)}
              />
            </Field>
            <Field label={t('settings.privacy.field.risk')} htmlFor="privacy-transfer-risk">
              <Select
                id="privacy-transfer-risk"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value)}
                options={riskFilterOptions(t)}
              />
            </Field>
          </PrivacyFilterBar>
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
                  <th>{t('settings.privacy.column.evidence')}</th>
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
                          {t('settings.privacy.evidence.receiptBy', {
                            kind: t('settings.privacy.evidence.kind.review'),
                            actor: receipt.recorded_by,
                          })}
                          <br />
                          <span className="muted">
                            {formatDateTime(receipt.recorded_at)} ·{' '}
                            {t('settings.privacy.evidence.transferReceiptNote')}
                          </span>
                        </>
                      ) : (
                        <span className="muted">{t('settings.privacy.evidence.none')}</span>
                      )}
                    </td>
                    <td>
                      <Badge tone={riskTone(record.risk_level)}>
                        {riskLabel(t, record.risk_level)}
                      </Badge>
                    </td>
                    <td>
                      <div className="stack--tight">
                        <Badge tone={statusTone(record.status)}>
                          {statusLabel(t, record.status)}
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
      className="form settings-rows"
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
    <Card
      title={
        <span className="row-wrap">
          {t('settings.privacy.retention.dryRun.title')}
          <FieldHelp text={t('settings.privacy.help.dryRun')} />
        </span>
      }
    >
      <form
        className="form settings-rows"
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
  resolutionRecords,
  resolutionRequestPending,
  resolvingCandidateId,
  reviewRequestPending,
  requestingReviewCandidateId,
  executionRecords,
  onRecordResolution,
  onRequestReview,
}: {
  report: RetentionDueCandidatesReport | null;
  loading: boolean;
  error: unknown;
  resolutionRecords: RetentionCandidateResolutionRecord[];
  resolutionRequestPending: boolean;
  resolvingCandidateId: string | null;
  reviewRequestPending: boolean;
  requestingReviewCandidateId: string | null;
  executionRecords: RetentionExecutionRecord[];
  onRecordResolution: (candidate: RetentionDueCandidate) => Promise<void>;
  onRequestReview: (
    candidate: RetentionDueCandidate,
    executionMode?: 'review_only' | 'execute_supported',
  ) => Promise<void>;
}) {
  const t = useT();
  const candidates: RetentionDueCandidate[] = report?.candidates ?? [];
  const suppressedByBoundedEvidenceCount = report?.suppressed_by_bounded_evidence_count ?? 0;

  return (
    <Card
      title={
        <span className="row-wrap">
          {t('settings.privacy.dueCandidates.title')}
          <FieldHelp text={t('settings.privacy.help.dueCandidates')} />
        </span>
      }
    >
      <div className="stack">
        <p className="field__hint">{t('settings.privacy.dueCandidates.lede')}</p>
        {report ? (
          <p className="muted">
            {t('settings.privacy.dueCandidates.summary', {
              generated: formatDateTime(report.generated_at),
              scope: report.scope,
              category: report.category,
              active: report.candidate_count,
              suppressed: suppressedByBoundedEvidenceCount,
              withResolution: report.candidates_with_resolution_count,
              resolutions: resolutionRecords.length,
            })}
          </p>
        ) : null}
        {report && report.suppressed_candidate_count > 0 ? (
          <p className="muted">
            {t('settings.privacy.dueCandidates.suppressedNote')}
            {report.suppression_summary ? (
              <>
                {' '}
                {t('settings.privacy.dueCandidates.suppressedSummary', {
                  note: report.suppression_summary.note,
                })}
              </>
            ) : null}
          </p>
        ) : null}
        {loading ? (
          <SkeletonTable cols={7} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : candidates.length === 0 ? (
          <EmptyState title={t('settings.privacy.dueCandidates.empty.title')}>
            <p>{t('settings.privacy.dueCandidates.empty.body')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('settings.privacy.dueCandidates.column.record')}</th>
                <th>{t('settings.privacy.dueCandidates.column.policy')}</th>
                <th>{t('settings.privacy.dueCandidates.column.due')}</th>
                <th>{t('settings.privacy.dueCandidates.column.blockers')}</th>
                <th>{t('settings.privacy.dueCandidates.column.findings')}</th>
                <th>{t('settings.privacy.dueCandidates.column.flags')}</th>
                <th>{t('settings.privacy.dueCandidates.column.review')}</th>
              </tr>
            }
          >
            {candidates.map((candidate) => {
              const queuedReview = retentionQueuedReviewForCandidate(candidate, executionRecords);
              const priorExecution = candidate.prior_execution;
              const latestResolution = candidate.latest_resolution;
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
                      <span>
                        {t('settings.privacy.dueCandidates.book')}: {candidate.book_id}
                      </span>
                      <span className="muted">
                        {t('settings.privacy.dueCandidates.entity')}: {candidate.entity_id}
                      </span>
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
                      <span>
                        {t('settings.privacy.dueCandidates.closing')}: {candidate.closing_date}
                      </span>
                      <span>
                        {t('settings.privacy.dueCandidates.due')}:{' '}
                        {candidate.due_date ?? t('settings.privacy.dueCandidates.noDueDate')}
                      </span>
                      <Badge tone={candidate.overdue ? 'warn' : 'neutral'}>
                        {' '}
                        {translateNow('uiLiteral.privacyComplianceSection.overdue')}{' '}
                        {String(candidate.overdue)}
                      </Badge>
                      <span>
                        {candidate.status} · {candidate.outcome}
                      </span>
                      <span className="muted">{candidate.next_step}</span>
                      <span className="muted">
                        {t('settings.privacy.dueCandidates.evidenceState')}:{' '}
                        {candidate.candidate_evidence_state}
                      </span>
                      <span className="muted">
                        {t('settings.privacy.dueCandidates.evidenceNextStep')}:{' '}
                        {candidate.evidence_next_step}
                      </span>
                      {priorExecution ? (
                        <>
                          <Badge tone="ok">
                            {t('settings.privacy.dueCandidates.boundedRecorded')}
                          </Badge>
                          <span>
                            {priorExecution.execution_status} · {priorExecution.outcome}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.priorEvidence')}:{' '}
                            {priorExecution.evidence_state}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.executionRequested', {
                              id: priorExecution.execution_id,
                              date: formatDateTime(priorExecution.requested_at),
                            })}
                          </span>
                          {priorExecution.executed_at ? (
                            <span className="muted">
                              {t('settings.privacy.dueCandidates.executedAt', {
                                date: formatDateTime(priorExecution.executed_at),
                              })}
                            </span>
                          ) : null}
                          <span className="muted">{priorExecution.next_step}</span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.priorEvidenceNextStep')}:{' '}
                            {priorExecution.evidence_next_step}
                          </span>
                        </>
                      ) : null}
                      {latestResolution ? (
                        <>
                          <Badge tone="accent">
                            {t('settings.privacy.dueCandidates.localDispositionRecorded')}
                          </Badge>
                          <span>
                            {latestResolution.disposition} · {latestResolution.id}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.recordedByOn', {
                              actor: latestResolution.recorded_by,
                              date: formatDateTime(latestResolution.recorded_at),
                            })}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.evidenceCountFlags', {
                              count: latestResolution.evidence_count,
                            })}
                          </span>
                          <span className="muted">{latestResolution.next_step}</span>
                        </>
                      ) : null}
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      <strong>{t('settings.privacy.dueCandidates.legalHold')}</strong>
                      {candidate.legal_hold_blockers.length > 0 ? (
                        candidate.legal_hold_blockers.map((blocker, index) => (
                          <span key={`${candidate.candidate_id}-hold-${index}`}>
                            {renderUnknownEvidence(t, blocker)}
                          </span>
                        ))
                      ) : (
                        <span className="muted">
                          {t('settings.privacy.dueCandidates.noLegalHold')}
                        </span>
                      )}
                      <strong>{t('settings.privacy.dueCandidates.requiredApprovals')}</strong>
                      {candidate.required_approvals.length > 0 ? (
                        candidate.required_approvals.map((approval, index) => (
                          <span key={`${candidate.candidate_id}-approval-${index}`}>
                            {renderUnknownEvidence(t, approval)}
                          </span>
                        ))
                      ) : (
                        <span className="muted">
                          {t('settings.privacy.dueCandidates.noApprovals')}
                        </span>
                      )}
                      {candidate.blockers.map((blocker, index) => (
                        <span key={`${candidate.candidate_id}-blocker-${index}`}>
                          {renderUnknownEvidence(t, blocker)}
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
                        <span className="muted">
                          {t('settings.privacy.dueCandidates.noFindings')}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight mono">
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
                          ? t('settings.privacy.dueCandidates.onlyNoActionEvidence')
                          : canRecordArchiveEvidence
                            ? t('settings.privacy.dueCandidates.onlyArchiveEvidence')
                            : t('settings.privacy.dueCandidates.onlyReviewEvidence')}
                      </span>
                    </div>
                  </td>
                  <td>
                    <div className="stack--tight">
                      {latestResolution ? (
                        <>
                          <Badge tone="accent">
                            {t('settings.privacy.dueCandidates.localDispositionExists')}
                          </Badge>
                        </>
                      ) : (
                        <Button
                          type="button"
                          variant="secondary"
                          icon={<Icon.Check />}
                          disabled={resolutionRequestPending}
                          onClick={() => void onRecordResolution(candidate)}
                        >
                          {resolvingCandidateId === candidate.candidate_id
                            ? t('settings.privacy.dueCandidates.recordingDisposition')
                            : t('settings.privacy.dueCandidates.recordDisposition')}
                        </Button>
                      )}
                      {priorExecution ? (
                        <Badge tone="ok">
                          {t('settings.privacy.dueCandidates.boundedEvidenceExists')}
                        </Badge>
                      ) : queuedReview ? (
                        <Badge tone="warn">
                          {t('settings.privacy.dueCandidates.reviewQueued')}
                        </Badge>
                      ) : canRecordNoActionEvidence ? (
                        <Button
                          type="button"
                          variant="secondary"
                          icon={<Icon.Check />}
                          disabled={reviewRequestPending}
                          onClick={() => void onRequestReview(candidate, 'execute_supported')}
                        >
                          {requestingReviewCandidateId === candidate.candidate_id
                            ? t('settings.privacy.dueCandidates.recordingNoAction')
                            : t('settings.privacy.dueCandidates.recordNoAction')}
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
                            ? t('settings.privacy.dueCandidates.recordingArchive')
                            : t('settings.privacy.dueCandidates.recordArchive')}
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
                            ? t('settings.privacy.dueCandidates.recordingReview')
                            : t('settings.privacy.dueCandidates.requestReview')}
                        </Button>
                      )}
                      {priorExecution ? (
                        <>
                          <span className="muted">
                            {priorExecution.execution_status} · {priorExecution.execution_id}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.noDuplicate')}
                          </span>
                        </>
                      ) : queuedReview ? (
                        <>
                          <span className="muted">
                            {queuedReview.execution_status} · {queuedReview.id}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.requestedAt', {
                              date: formatDateTime(queuedReview.requested_at),
                            })}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.queueEvidenceState')}:{' '}
                            {queuedReview.evidence_state}
                          </span>
                          <span className="muted">
                            {t('settings.privacy.dueCandidates.queueNextStep')}:{' '}
                            {queuedReview.evidence_next_step}
                          </span>
                        </>
                      ) : canRecordNoActionEvidence ? (
                        <span className="muted">
                          {t('settings.privacy.dueCandidates.noActionHint')}
                        </span>
                      ) : canRecordArchiveEvidence ? (
                        <span className="muted">
                          {t('settings.privacy.dueCandidates.archiveHint')}
                        </span>
                      ) : (
                        <span className="muted">
                          {t('settings.privacy.dueCandidates.reviewHint')}
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
  const deferredSearch = useDeferredValue(search);
  const [decisionFilter, setDecisionFilter] = useState('all');
  const [legalHoldFilter, setLegalHoldFilter] = useState('all');
  const [closingId, setClosingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(deferredSearch.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.execution_status !== statusFilter) return false;
      if (decisionFilter !== 'all' && record.operator_review_decision !== decisionFilter) {
        return false;
      }
      if (!matchesPresence(legalHoldFilter, record.legal_hold_blockers.length > 0)) return false;
      return q.length === 0 || retentionExecutionSearchText(record).includes(q);
    });
  }, [decisionFilter, deferredSearch, legalHoldFilter, records, statusFilter]);

  // The execution-status filter is the one server-side filter on this tab (it is a query
  // parameter of the list request, lifted to the section). Clearing has to reset it through
  // the same callback that owns it rather than resetting local state alone.
  const hasFilters =
    search.trim() !== '' ||
    statusFilter !== 'all' ||
    decisionFilter !== 'all' ||
    legalHoldFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setDecisionFilter('all');
    setLegalHoldFilter('all');
    onStatusFilterChange('all');
  }
  const statusOptions = RETENTION_EXECUTION_STATUSES.map((status) => ({
    value: status,
    label: retentionExecutionStatusLabel(t, status),
  }));

  async function closeOperationalReview(record: RetentionExecutionRecord) {
    setClosingId(record.id);
    try {
      await closeReview.mutateAsync({ id: record.id, body: retentionReviewClosureBody(record) });
      toast.success(t('settings.privacy.execution.toast.reviewed'));
    } catch (e) {
      toast.error(e);
    } finally {
      setClosingId(null);
    }
  }

  return (
    <Card
      title={
        <span className="row-wrap">
          {t('settings.privacy.execution.title')}
          <FieldHelp text={t('settings.privacy.help.execution')} />
        </span>
      }
      actions={<FilterCountBadge shown={filtered.length} total={records.length} />}
    >
      <div className="stack">
        <p className="field__hint">{t('settings.privacy.execution.lede')}</p>
        <PrivacyFilterBar
          name={t('settings.privacy.execution.title')}
          hasFilters={hasFilters}
          onClear={clearFilters}
          advanced={
            <>
              <Field
                label={t('settings.privacy.filter.decision')}
                htmlFor="privacy-retention-execution-decision"
              >
                <Select
                  id="privacy-retention-execution-decision"
                  value={decisionFilter}
                  onChange={(e) => setDecisionFilter(e.target.value)}
                  options={executionDecisionFilterOptions(t)}
                />
              </Field>
              <Field
                label={t('settings.privacy.filter.legalHold')}
                htmlFor="privacy-retention-execution-legal-hold"
              >
                <Select
                  id="privacy-retention-execution-legal-hold"
                  value={legalHoldFilter}
                  onChange={(e) => setLegalHoldFilter(e.target.value)}
                  options={presenceFilterOptions(
                    t,
                    'settings.privacy.filter.legalHold.all',
                    'settings.privacy.filter.legalHold.with',
                    'settings.privacy.filter.legalHold.without',
                  )}
                />
              </Field>
            </>
          }
        >
          <Field
            label={t('settings.privacy.filter.search')}
            htmlFor="privacy-retention-execution-search"
          >
            <Input
              id="privacy-retention-execution-search"
              type="search"
              value={search}
              placeholder={t('settings.privacy.execution.searchPlaceholder')}
              onChange={(e) => setSearch(e.target.value)}
            />
          </Field>
          <Field
            label={t('settings.privacy.execution.statusFilter')}
            htmlFor="privacy-retention-execution-status"
          >
            <Select
              id="privacy-retention-execution-status"
              value={statusFilter}
              onChange={(e) =>
                onStatusFilterChange(e.target.value as RetentionExecutionStatus | 'all')
              }
              options={[
                { value: 'all', label: t('settings.privacy.status.all') },
                ...statusOptions,
              ]}
            />
          </Field>
        </PrivacyFilterBar>
        {loading ? (
          <SkeletonTable cols={6} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : records.length === 0 ? (
          <EmptyState title={t('settings.privacy.execution.empty.title')}>
            <p>{t('settings.privacy.execution.empty.body')}</p>
          </EmptyState>
        ) : filtered.length === 0 ? (
          <EmptyState title={t('settings.privacy.emptyResults.title')}>
            <p>{t('settings.privacy.emptyResults.body')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('settings.privacy.execution.column.request')}</th>
                <th>{t('settings.privacy.field.status')}</th>
                <th>{t('settings.privacy.retention.column.policy')}</th>
                <th>{t('settings.privacy.execution.column.blockers')}</th>
                <th>{t('settings.privacy.execution.column.nextStep')}</th>
                <th>{t('settings.privacy.execution.column.review')}</th>
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
                      {retentionExecutionStatusLabel(t, record.execution_status)}
                    </Badge>
                    <span className="muted">{record.outcome}</span>
                    <span className="muted">
                      {retentionOperatorReviewDecisionLabel(t, record.operator_review_decision)}
                    </span>
                  </div>
                </td>
                <td>
                  <div className="stack--tight">
                    <span>
                      {record.requested_policy.name ??
                        t('settings.privacy.execution.policyNotFound')}
                    </span>
                    <span className="muted">
                      {record.requested_policy.id ?? t('settings.privacy.execution.noPolicy')}
                    </span>
                    <span className="muted">
                      {record.requested_policy.schedule_id ??
                        t('settings.privacy.execution.noSchedule')}
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
                      <span className="muted">{t('settings.privacy.execution.noBlockers')}</span>
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
                    <span className="muted">
                      {t('settings.privacy.dueCandidates.evidenceState')}: {record.evidence_state}
                    </span>
                    <span className="muted">
                      {t('settings.privacy.dueCandidates.evidenceNextStep')}:{' '}
                      {record.evidence_next_step}
                    </span>
                    {record.operator_notes ? (
                      <span className="muted">{record.operator_notes}</span>
                    ) : null}
                    <span className="muted mono">
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
                        {t('settings.privacy.execution.reviewRecorded')}
                        {record.review_closed_by
                          ? ` ${t('settings.privacy.execution.byActor', {
                              actor: record.review_closed_by,
                            })}`
                          : ''}
                        {record.review_closed_at
                          ? ` ${t('settings.privacy.execution.onDate', {
                              date: formatDateTime(record.review_closed_at),
                            })}`
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
                        ? t('settings.privacy.execution.recordingReview')
                        : t('settings.privacy.execution.recordReview')}
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
  candidateResolutionRecords,
  candidateResolutionPending,
  resolvingCandidateId,
  reviewRequestPending,
  requestingReviewCandidateId,
  executionRecords,
  executionLoading,
  executionError,
  executionStatusFilter,
  onCreate,
  onPatch,
  onDryRun,
  onRecordResolution,
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
  candidateResolutionRecords: RetentionCandidateResolutionRecord[];
  candidateResolutionPending: boolean;
  resolvingCandidateId: string | null;
  reviewRequestPending: boolean;
  requestingReviewCandidateId: string | null;
  executionRecords: RetentionExecutionRecord[];
  executionLoading: boolean;
  executionError: unknown;
  executionStatusFilter: RetentionExecutionStatus | 'all';
  onCreate: (body: CreateRetentionPolicyBody) => Promise<RetentionPolicyView>;
  onPatch: (id: string, body: PatchRetentionPolicyBody) => Promise<RetentionPolicyView>;
  onDryRun: (form: RetentionDryRunFormState) => Promise<void>;
  onRecordResolution: (candidate: RetentionDueCandidate) => Promise<void>;
  onRequestReview: (
    candidate: RetentionDueCandidate,
    executionMode?: 'review_only' | 'execute_supported',
  ) => Promise<void>;
  onExecutionStatusFilterChange: (status: RetentionExecutionStatus | 'all') => void;
}) {
  const t = useT();
  const toast = useToast();
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [statusFilter, setStatusFilter] = useState('all');
  const [disposalFilter, setDisposalFilter] = useState('all');
  const [activeFilter, setActiveFilter] = useState('all');
  const retentionStatusOptions = RETENTION_POLICY_STATUSES.map((status) => ({
    value: status,
    label: retentionStatusLabel(t, status),
  }));
  const [form, setForm] = useState<RetentionPolicyFormState | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const filtered = useMemo(() => {
    const q = normalizeSearch(deferredSearch.trim());
    return records.filter((record) => {
      if (statusFilter !== 'all' && record.status !== statusFilter) return false;
      if (disposalFilter !== 'all' && record.disposal_action !== disposalFilter) return false;
      if (!matchesPresence(activeFilter, record.active)) return false;
      return q.length === 0 || retentionSearchText(record).includes(q);
    });
  }, [activeFilter, deferredSearch, disposalFilter, records, statusFilter]);

  const hasFilters =
    search.trim() !== '' ||
    statusFilter !== 'all' ||
    disposalFilter !== 'all' ||
    activeFilter !== 'all';

  function clearFilters() {
    setSearch('');
    setStatusFilter('all');
    setDisposalFilter('all');
    setActiveFilter('all');
  }

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
        title={
          <span className="row-wrap">
            {t('settings.privacy.retention.title')}
            <FieldHelp text={t('settings.privacy.help.retention')} />
          </span>
        }
        actions={
          <>
            <FilterCountBadge shown={filtered.length} total={records.length} />
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
          </>
        }
      >
        <div className="stack">
          <p className="field__hint">{t('settings.privacy.retention.lede')}</p>
          <PrivacyFilterBar
            name={t('settings.privacy.retention.title')}
            hasFilters={hasFilters}
            onClear={clearFilters}
            advanced={
              <Field
                label={t('settings.privacy.filter.active')}
                htmlFor="privacy-retention-active-filter"
              >
                <Select
                  id="privacy-retention-active-filter"
                  value={activeFilter}
                  onChange={(e) => setActiveFilter(e.target.value)}
                  options={presenceFilterOptions(
                    t,
                    'settings.privacy.filter.active.all',
                    'settings.privacy.retention.active.true',
                    'settings.privacy.retention.active.false',
                  )}
                />
              </Field>
            }
          >
            <Field label={t('settings.privacy.filter.search')} htmlFor="privacy-retention-search">
              <Input
                id="privacy-retention-search"
                type="search"
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
            <Field
              label={t('settings.privacy.filter.disposal')}
              htmlFor="privacy-retention-disposal-filter"
            >
              <Select
                id="privacy-retention-disposal-filter"
                value={disposalFilter}
                onChange={(e) => setDisposalFilter(e.target.value)}
                options={[
                  { value: 'all', label: t('settings.privacy.filter.disposal.all') },
                  ...RETENTION_DISPOSAL_ACTIONS.map((action) => ({
                    value: action,
                    label: retentionDisposalLabel(t, action),
                  })),
                ]}
              />
            </Field>
          </PrivacyFilterBar>
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
        resolutionRecords={candidateResolutionRecords}
        resolutionRequestPending={candidateResolutionPending}
        resolvingCandidateId={resolvingCandidateId}
        reviewRequestPending={reviewRequestPending}
        requestingReviewCandidateId={requestingReviewCandidateId}
        executionRecords={executionRecords}
        onRecordResolution={onRecordResolution}
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

type PrivacySubTab = 'registers' | 'retention' | 'guidance';

const PRIVACY_SUBTABS: { id: PrivacySubTab; labelKey: MessageKey; icon: ReactNode }[] = [
  { id: 'registers', labelKey: 'settings.privacy.subtab.registers.label', icon: <Icon.FileText /> },
  { id: 'retention', labelKey: 'settings.privacy.subtab.retention.label', icon: <Icon.Archive /> },
  { id: 'guidance', labelKey: 'settings.privacy.subtab.guidance.label', icon: <Icon.Info /> },
];

export function PrivacyComplianceSection() {
  const t = useT();
  const can = useCan();
  // The privacy record registers (processors, DPIAs, breach playbooks, transfer controls) and
  // the DPIA guidance template gate on `privacy.manage`; the retention family (policies, due
  // candidates, resolutions, executions) gates on its own `retention.manage` (t27 granular
  // split). A holder of either verb reaches the section; each sub-tab is gated by its own verb.
  const canManagePrivacy = can('privacy.manage');
  const canManageRetention = can('retention.manage');
  const canManage = canManagePrivacy || canManageRetention;
  const [subTab, setSubTab] = useState<PrivacySubTab>('registers');
  const [retentionExecutionStatusFilter, setRetentionExecutionStatusFilter] = useState<
    RetentionExecutionStatus | 'all'
  >('all');
  const [retentionReviewCandidateId, setRetentionReviewCandidateId] = useState<string | null>(null);
  const [retentionResolutionCandidateId, setRetentionResolutionCandidateId] = useState<
    string | null
  >(null);
  const processors = usePrivacyProcessors(canManagePrivacy);
  const dpiaTemplate = usePrivacyDpiaTemplate(canManagePrivacy);
  const dpias = usePrivacyDpias(canManagePrivacy);
  const breachPlaybooks = usePrivacyBreachPlaybooks(canManagePrivacy);
  const transferControls = usePrivacyTransferControls(canManagePrivacy);
  const retentionPolicies = usePrivacyRetentionPolicies(canManageRetention);
  const retentionDueCandidates = usePrivacyRetentionDueCandidates(canManageRetention);
  const retentionCandidateResolutions = usePrivacyRetentionCandidateResolutions(canManageRetention);
  const retentionExecutions = usePrivacyRetentionExecutions(
    retentionExecutionStatusFilter,
    canManageRetention,
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
  const recordRetentionCandidateResolution = useRecordPrivacyRetentionCandidateResolution();
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
              ? t('settings.privacy.toast.archiveEvidenceRecorded')
              : t('settings.privacy.toast.noActionEvidenceRecorded')
            : t('settings.privacy.toast.reviewRequestRecorded')
          : executionMode === 'execute_supported'
            ? isArchiveEvidenceRequest
              ? t('settings.privacy.toast.archiveEvidenceSent')
              : t('settings.privacy.toast.noActionEvidenceSent')
            : t('settings.privacy.toast.reviewRequestSent'),
      );
    } catch (e) {
      toast.error(e);
    } finally {
      setRetentionReviewCandidateId(null);
    }
  }

  async function recordRetentionResolution(candidate: RetentionDueCandidate) {
    setRetentionResolutionCandidateId(candidate.candidate_id);
    try {
      await recordRetentionCandidateResolution.mutateAsync({
        candidateId: candidate.candidate_id,
        body: retentionCandidateResolutionBody(candidate),
      });
      toast.success(t('settings.privacy.toast.dispositionRecorded'));
    } catch (e) {
      toast.error(e);
    } finally {
      setRetentionResolutionCandidateId(null);
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

      <SubNav
        items={PRIVACY_SUBTABS.map((s) => ({ id: s.id, label: t(s.labelKey), icon: s.icon }))}
        active={subTab}
        onSelect={setSubTab}
        ariaLabel={t('settings.privacy.subnav.aria')}
      />

      <div className="route-transition stack" key={subTab}>
        {subTab === 'registers' ? (
          <div className="stack">
            <p className="field__hint">{t('settings.privacy.subtab.registers.desc')}</p>

            {!canManagePrivacy ? (
              <PermissionDeniedNote />
            ) : (
              <>
                <RegisterPanel
                  kind="processor"
                  title={t('settings.privacy.register.processor.title')}
                  lede={t('settings.privacy.register.processor.lede')}
                  help={t('settings.privacy.help.processor')}
                  records={processors.data ?? []}
                  loading={processors.isLoading}
                  error={processors.error}
                  saving={createProcessor.isPending || patchProcessor.isPending}
                  onCreate={(body) =>
                    createProcessor.mutateAsync(body as CreateProcessorRecordBody)
                  }
                  onPatch={(id, body) =>
                    patchProcessor.mutateAsync({ id, body: body as PatchProcessorRecordBody })
                  }
                />

                <RegisterPanel
                  kind="dpia"
                  title={t('settings.privacy.register.dpia.title')}
                  lede={t('settings.privacy.register.dpia.lede')}
                  help={t('settings.privacy.help.dpia')}
                  records={dpias.data ?? []}
                  loading={dpias.isLoading}
                  error={dpias.error}
                  saving={createDpia.isPending || patchDpia.isPending}
                  onCreate={(body) => createDpia.mutateAsync(body as CreateDpiaRecordBody)}
                  onPatch={(id, body) =>
                    patchDpia.mutateAsync({ id, body: body as PatchDpiaRecordBody })
                  }
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
              </>
            )}
          </div>
        ) : null}

        {subTab === 'retention' ? (
          <div className="stack">
            <p className="field__hint">{t('settings.privacy.subtab.retention.desc')}</p>

            {!canManageRetention ? (
              <PermissionDeniedNote />
            ) : (
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
                candidateResolutionRecords={retentionCandidateResolutions.data ?? []}
                candidateResolutionPending={recordRetentionCandidateResolution.isPending}
                resolvingCandidateId={retentionResolutionCandidateId}
                reviewRequestPending={dryRunRetentionPolicy.isPending}
                requestingReviewCandidateId={retentionReviewCandidateId}
                executionRecords={retentionExecutions.data ?? []}
                executionLoading={retentionExecutions.isLoading}
                executionError={retentionExecutions.error}
                executionStatusFilter={retentionExecutionStatusFilter}
                onCreate={(body) => createRetentionPolicy.mutateAsync(body)}
                onPatch={(id, body) => patchRetentionPolicy.mutateAsync({ id, body })}
                onDryRun={dryRunRetention}
                onRecordResolution={recordRetentionResolution}
                onRequestReview={requestRetentionReview}
                onExecutionStatusFilterChange={setRetentionExecutionStatusFilter}
              />
            )}
          </div>
        ) : null}

        {subTab === 'guidance' ? (
          <div className="stack">
            <p className="field__hint">{t('settings.privacy.subtab.guidance.desc')}</p>

            {!canManagePrivacy ? (
              <PermissionDeniedNote />
            ) : (
              <DpiaTemplateGuidancePanel
                template={dpiaTemplate.data ?? null}
                loading={dpiaTemplate.isLoading}
                error={dpiaTemplate.error}
              />
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
