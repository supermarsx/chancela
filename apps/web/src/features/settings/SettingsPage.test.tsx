import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { SettingsPage } from './SettingsPage';
import {
  DEFAULT_SETTINGS,
  RETENTION_DISPOSAL_ACTIONS,
  type DpiaTemplateView,
  type PrivacyAdvisoryReviewStatus,
  type PrivacyAdvisoryReviewSummary,
  type RetentionCandidateResolutionRecord,
  type RetentionDisposalAction,
  type RetentionDueCandidatesReport,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import { colorStore } from '../../theme/colorStore';
import { grainStore } from '../../theme/grainStore';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  method: string;
  body: string | null;
}

const PERMISSION_CATALOG = {
  permissions: [
    { permission: 'ledger.read', meta: false },
    { permission: 'entity.read', meta: false },
    { permission: 'role.manage', meta: true },
  ],
};

const API_KEY_ONE = {
  id: 'key-1',
  name: 'ERP bridge',
  prefix: 'chk_ab12cd34ef56',
  grant: {
    kind: 'permissions',
    permissions: ['ledger.read'],
    scope: { kind: 'global' },
  },
  created_by: 'user-1',
  created_at: '2026-07-09T10:00:00Z',
  revoked: false,
  active: true,
  rate_limit: { rpm: 60, burst: 20 },
};

type ApiKeyMetadata = typeof API_KEY_ONE;

const API_KEY_REVOKED: ApiKeyMetadata = {
  ...API_KEY_ONE,
  id: 'key-revoked',
  name: 'Retired bridge',
  prefix: 'chk_revoked',
  revoked: true,
  active: false,
};

const REGISTRY_AUTO_UPDATE_PLAN = {
  generated_at: '2026-07-09T10:00:00Z',
  dry_run_only: true,
  config: DEFAULT_SETTINGS.registry_auto_update,
  due: [
    {
      entity_id: 'ent-1',
      entity_name: 'Acme, S.A.',
      entity_profile: 'SociedadeAnonima',
      retrieved_at: '2026-05-01T10:00:00Z',
      age_hours: 1656,
      stale_threshold_hours: 720,
      code_masked: '1234********9012',
      status: 'due',
      reason: 'stale',
      next_allowed_at: null,
    },
  ],
  skipped: {
    disabled: 1,
    fresh: 2,
    backoff: 0,
    running: 0,
    orphaned: 0,
    capped: 0,
  },
  notes: [],
};

const PROCESSOR_ONE = {
  id: 'processor-1',
  name: 'Cloud Processor',
  purpose: 'Alojamento da aplicação',
  legal_basis: 'Contrato',
  data_categories: ['Identificação', 'Contactos'],
  subprocessors: ['EU Backup SARL'],
  risk_level: 'medium',
  status: 'draft',
  created_at: '2026-07-09T10:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T10:00:00Z',
  updated_by: 'amelia.marques',
};

const DPIA_ONE = {
  id: 'dpia-1',
  title: 'Marketing profiling',
  purpose: 'Segmentação de comunicações',
  legal_basis: 'Interesse legítimo',
  data_categories: ['Comportamento'],
  subprocessors: ['Analytics Processor SA'],
  risk_level: 'high',
  status: 'under_review',
  evidence_receipts: [
    {
      id: 'dpia-receipt-1',
      evidence_type: 'review',
      recorded_at: '2026-07-09T11:20:00Z',
      recorded_by: 'amelia.marques',
      notes: 'Local DPIA review only.',
      authority_filing_completed: false,
      legal_review_accepted: false,
      legal_certification_completed: false,
      external_delivery_completed: false,
      dpia_completed: false,
      compliance_certification_completed: false,
    },
  ],
  advisory_review: dpiaAdvisoryReviewSummary({
    status: 'under_review',
    last_reviewed_at: '2026-07-09T11:20:00Z',
    next_review_due_at: undefined,
    days_until_due: undefined,
  }),
  created_at: '2026-07-09T11:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T11:00:00Z',
  updated_by: 'amelia.marques',
};

const DPIA_TEMPLATE: DpiaTemplateView = {
  schema: 'chancela-privacy-dpia-template/v1',
  template_id: 'privacy-dpia-guidance/v1',
  title: 'Local DPIA guidance template',
  version: 1,
  language: 'en',
  scope: 'local_offline_guidance_only',
  local_offline_guidance_only: true,
  sections: [
    {
      id: 'processing_description',
      title: 'Processing description',
      description: 'Use placeholders only; do not paste live register records.',
      prompts: ['What processing activity is being assessed?'],
      checklist: [
        {
          id: 'activity_label',
          label: 'Processing activity label',
          field_type: 'text',
          required: true,
        },
      ],
    },
    {
      id: 'necessity_proportionality',
      title: 'Necessity and proportionality prompts',
      description: 'Guide human review without deciding legal sufficiency.',
      prompts: ['What lower-impact alternatives should be considered?'],
      checklist: [
        {
          id: 'necessity_rationale',
          label: 'Necessity rationale prompt',
          field_type: 'textarea',
          required: true,
        },
      ],
    },
    {
      id: 'risk_prompts',
      title: 'Risk prompts',
      description: 'Qualitative prompts only; no scoring authority.',
      prompts: ['What unresolved questions require escalation?'],
      checklist: [
        {
          id: 'risk_review_note',
          label: 'Human risk review note',
          field_type: 'review_note',
          required: false,
        },
      ],
    },
    {
      id: 'safeguards',
      title: 'Safeguards',
      description: 'List safeguards for later human review.',
      prompts: ['Which safeguards should be evidenced?'],
      checklist: [
        {
          id: 'evidence_references',
          label: 'Local evidence references',
          field_type: 'evidence_reference',
          required: false,
        },
      ],
    },
    {
      id: 'consultation_escalation',
      title: 'Consultation and escalation prompts',
      description: 'Escalation prompts without authority approval claims.',
      prompts: ['What blocker prevents treating this as reviewed?'],
      checklist: [
        {
          id: 'next_operator_action',
          label: 'Next operator action',
          field_type: 'review_note',
          required: true,
        },
      ],
    },
    {
      id: 'evidence_boundaries',
      title: 'Evidence and no-claim boundaries',
      description: 'Keep local/offline boundaries and false flags visible.',
      prompts: ['Which no-claim flags remain false?'],
      checklist: [
        {
          id: 'false_no_claim_flags',
          label: 'False no-claim flags acknowledged',
          field_type: 'checklist',
          required: true,
        },
      ],
    },
  ],
  operator_actions: [
    'Review the prompts before any separate DPIA register update.',
    'Keep authority, legal, external, scoring, completion, certification, and mutation claims false.',
  ],
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

function advisoryReviewSummary(
  overrides: Record<string, unknown> = {},
): PrivacyAdvisoryReviewSummary {
  const summary: PrivacyAdvisoryReviewSummary = {
    status: 'current' as PrivacyAdvisoryReviewStatus,
    last_reviewed_at: '2026-07-09T12:00:00Z',
    next_review_due_at: '2027-07-09',
    days_until_due: 361,
    review_interval_days: 365,
    receipt_count: 1,
    review_receipt_count: 1,
    drill_receipt_count: 0,
    local_advisory_only: true as const,
    authority_notification_claimed: false as const,
    subject_notification_claimed: false as const,
    transfer_approval_claimed: false as const,
    transfer_execution_claimed: false as const,
    external_delivery_configured: false as const,
    legal_completion_claimed: false as const,
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) {
      delete (summary as unknown as Record<string, unknown>)[key];
    } else {
      (summary as unknown as Record<string, unknown>)[key] = value;
    }
  }
  return summary;
}

function dpiaAdvisoryReviewSummary(overrides: Record<string, unknown> = {}) {
  return {
    ...advisoryReviewSummary(overrides),
    authority_filing_claimed: false,
    legal_acceptance_claimed: false,
    legal_certification_claimed: false,
    external_delivery_claimed: false,
    completion_claimed: false,
    compliance_certification_claimed: false,
  };
}

const BREACH_PLAYBOOK_ONE = {
  id: 'breach-1',
  title: 'Suspected account compromise',
  scope: 'account-access',
  detection_channels: ['SIEM alert'],
  containment_steps: ['Disable sessions'],
  notification_roles: ['DPO'],
  authority_notification_window: '72 hours when required',
  subject_notification_guidance: 'Notify high-risk subjects.',
  risk_level: 'high',
  status: 'active',
  review_notes: 'Annual review.',
  evidence_receipts: [
    {
      id: 'breach-receipt-1',
      evidence_type: 'drill',
      recorded_at: '2026-07-09T12:10:00Z',
      recorded_by: 'amelia.marques',
      notes: 'Tabletop drill only.',
      authority_notified: false,
      subjects_notified: false,
    },
  ],
  advisory_review: advisoryReviewSummary({
    last_reviewed_at: undefined,
    last_drill_at: '2026-07-09T12:10:00Z',
    drill_receipt_count: 1,
  }),
  created_at: '2026-07-09T12:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T12:00:00Z',
  updated_by: 'amelia.marques',
};

const TRANSFER_CONTROL_ONE = {
  id: 'transfer-1',
  name: 'EU to UK support access',
  purpose: 'Support ticket investigation',
  legal_basis: 'Contract',
  data_categories: ['Support messages'],
  recipient: 'UK Support Ltd',
  destination_country: 'United Kingdom',
  transfer_mechanism: 'UK adequacy regulation',
  safeguards: ['Ticket-scoped access'],
  risk_level: 'medium',
  status: 'draft',
  review_notes: 'Quarterly review.',
  evidence_receipts: [
    {
      id: 'transfer-receipt-1',
      recorded_at: '2026-07-09T12:40:00Z',
      recorded_by: 'amelia.marques',
      notes: 'Control review only.',
      transfer_approved: false,
      data_transfer_executed: false,
    },
  ],
  advisory_review: advisoryReviewSummary({
    last_reviewed_at: '2026-07-09T12:40:00Z',
  }),
  created_at: '2026-07-09T12:30:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T12:30:00Z',
  updated_by: 'amelia.marques',
};

const RETENTION_POLICY_ONE = {
  id: 'retention-1',
  name: 'Mensagens de suporte',
  scope: 'support',
  category: 'messages',
  schedule_id: 'support-messages-v1',
  retention_period: 'P2Y',
  legal_basis: 'Obrigação contratual',
  disposal_action: 'delete',
  status: 'active',
  active: true,
  notes: 'Revisão antes de qualquer descarte.',
  created_at: '2026-07-09T12:50:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T12:50:00Z',
  updated_by: 'amelia.marques',
};

const RETENTION_DUE_CANDIDATES_REPORT: RetentionDueCandidatesReport = {
  generated_at: '2026-07-09T14:00:00Z',
  scope: 'book_archive',
  category: 'documents',
  candidate_count: 2,
  suppressed_candidate_count: 0,
  suppressed_by_bounded_evidence_count: 0,
  candidate_resolution_record_count: 0,
  candidates_with_resolution_count: 0,
  candidates: [
    {
      candidate_id: 'retention-candidate-1',
      candidate_fingerprint: '1'.repeat(64),
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-1',
      book_id: 'book-archive-1',
      entity_id: 'entity-1',
      closing_date: '2024-06-01',
      due_date: '2026-06-01',
      overdue: true,
      policy_id: 'retention-1',
      policy_name: 'Mensagens de suporte',
      schedule_id: 'support-messages-v1',
      retention_period: 'P2Y',
      disposal_action: 'review',
      destructive_action: false,
      legal_hold_blockers: [],
      required_approvals: [
        {
          code: 'retention_manual_review',
          required_from: 'privacy_or_settings_manager',
          reason: 'review evidence only before any separate operational process',
        },
      ],
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
    },
    {
      candidate_id: 'retention-candidate-unsupported',
      candidate_fingerprint: '2'.repeat(64),
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-blocked',
      book_id: 'book-archive-blocked',
      entity_id: 'entity-2',
      closing_date: '2023-02-10',
      due_date: null,
      overdue: false,
      policy_id: 'retention-unsupported',
      policy_name: 'Unsupported archival period',
      schedule_id: 'archive-unsupported-v1',
      retention_period: 'PXBROKEN',
      disposal_action: 'review',
      destructive_action: false,
      legal_hold_blockers: [
        {
          policy_id: 'retention-unsupported',
          name: 'Board preservation hold',
          reason: 'legal hold active on archived book',
        },
      ],
      required_approvals: [
        {
          code: 'unsupported_period_review',
          required_from: 'privacy_or_settings_manager',
          reason: 'unsupported period must be corrected before operational review',
        },
      ],
      blockers: [
        {
          code: 'unsupported_retention_period',
          message: 'Retention period PXBROKEN is not supported.',
        },
      ],
      findings: [
        {
          code: 'unsupported_retention_period',
          message: 'Retention period PXBROKEN is not supported.',
          severity: 'warning',
        },
      ],
      outcome: 'blocked_unsupported_period',
      status: 'blocked',
      candidate_evidence_state: 'blocked',
      evidence_next_step: 'Correct the retention schedule; this scan records evidence only.',
      would_execute: false,
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      candidate_resolution_record_count: 0,
      next_step: 'Correct the retention schedule; this scan records evidence only.',
    },
  ],
};

const RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE =
  'Due candidates with prior safe bounded archive/no-action evidence are omitted from the active candidate list; execution history remains queryable for review.';

type RetentionExecutionMetadata = {
  id: string;
  execution_status: 'awaiting_review' | 'blocked' | 'executed';
  [key: string]: unknown;
};

const RETENTION_EXECUTION_BLOCKED: RetentionExecutionMetadata = {
  id: 'retention-exec-blocked',
  requested_at: '2026-07-09T13:30:00Z',
  actor: 'amelia.marques',
  execution_intent: 'execute_supported',
  execution_status: 'blocked',
  operator_review_decision: 'blocked',
  decision_state: 'open',
  review_closure_evidence: [],
  destructive_disposal_completed: false,
  full_erasure_completed: false,
  legal_hold_mutated: false,
  retention_policy_mutated: false,
  requested_policy: {
    id: 'retention-1',
    found: true,
    name: 'Mensagens de suporte',
    scope: 'support',
    category: 'messages',
    schedule_id: 'support-messages-v1',
    retention_period: 'P2Y',
    disposal_action: 'delete',
    status: 'active',
    active: true,
    stale: false,
    matches_candidate: true,
    destructive_action: true,
  },
  candidate: { scope: 'support', category: 'messages', record_id: 'ticket-123' },
  matched_records_summary: {
    scope: 'support',
    category: 'messages',
    record_id: 'ticket-123',
    record_count: 1,
    policy_match_count: 1,
    destructive_policy_count: 1,
    policy_ids: ['retention-1'],
  },
  legal_hold_blockers: [],
  operator_notes: 'Operator reviewed ticket retention.',
  audit_evidence: [{ label: 'case', value: 'ticket export hash verified' }],
  outcome: 'blocked_destructive_action',
  block_reason: 'delete/anonymize execution is not enabled in this guarded slice',
  evidence_state: 'blocked',
  evidence_next_step:
    'Record separate governance approval before any external destructive process; this API will not execute it.',
  workflow: {
    status: 'blocked',
    blockers: [
      {
        code: 'destructive_action_disabled',
        message: 'delete/anonymize execution is not enabled in this guarded slice',
        policy_id: 'retention-1',
      },
    ],
    required_approvals: [
      {
        code: 'retention_manual_review',
        required_from: 'privacy_or_settings_manager',
        reason: 'approve the retained evidence before any separate operational action',
      },
      {
        code: 'destructive_disposal_governance',
        required_from: 'external_governance_process',
        reason: 'destructive disposal is outside this API and requires separate approval',
      },
    ],
    next_step:
      'Record separate governance approval before any external destructive process; this API will not execute it.',
  },
  execution_result: {
    bounded_executor: true,
    targets_considered: [
      {
        target_type: 'retention_candidate_record',
        target_id: 'ticket-123',
        action: 'bounded_delete_evidence',
        reason_code: 'target_considered',
        detail: 'candidate evaluated against retention-1; bounded evidence only',
      },
    ],
    targets_acted: [],
    targets_skipped: [
      {
        target_type: 'retention_candidate_record',
        target_id: 'ticket-123',
        action: 'bounded_delete_evidence',
        reason_code: 'destructive_action_disabled',
        detail: 'delete/anonymize execution is not enabled in this guarded slice',
      },
    ],
    reason_codes: ['destructive_action_disabled', 'destructive_disposal_approval_required'],
    next_step:
      'Record separate governance approval before any external destructive process; this API will not execute it.',
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    blocker_metadata: [
      {
        code: 'destructive_action_disabled',
        detail: 'delete/anonymize execution is not enabled in this guarded slice',
        policy_id: 'retention-1',
      },
    ],
  },
  would_execute: false,
};

const RETENTION_EXECUTION_AWAITING: RetentionExecutionMetadata = {
  ...RETENTION_EXECUTION_BLOCKED,
  id: 'retention-exec-awaiting',
  requested_at: '2026-07-09T13:40:00Z',
  execution_intent: 'review_only',
  execution_status: 'awaiting_review',
  operator_review_decision: 'review_required',
  requested_policy: {
    ...((RETENTION_EXECUTION_BLOCKED.requested_policy as Record<string, unknown>) ?? {}),
    disposal_action: 'review',
    destructive_action: false,
  },
  candidate: { scope: 'support', category: 'messages', record_id: 'ticket-456' },
  matched_records_summary: {
    scope: 'support',
    category: 'messages',
    record_id: 'ticket-456',
    record_count: 1,
    policy_match_count: 1,
    destructive_policy_count: 0,
    policy_ids: ['retention-1'],
  },
  operator_notes: 'Manual review evidence captured.',
  outcome: 'manual_review_required',
  block_reason: 'retention execution request is recorded for manual review only',
  evidence_state: 'review_queued',
  evidence_next_step:
    'Review the retained evidence for manual approval; no disposal has been executed.',
  workflow: {
    status: 'awaiting_manual_review',
    blockers: [],
    required_approvals: [
      {
        code: 'retention_manual_review',
        required_from: 'privacy_or_settings_manager',
        reason: 'approve the retained evidence before any separate operational action',
      },
    ],
    next_step: 'Review the retained evidence for manual approval; no disposal has been executed.',
  },
  execution_result: {
    bounded_executor: true,
    targets_considered: [
      {
        target_type: 'retention_candidate_record',
        target_id: 'ticket-456',
        action: 'bounded_review_evidence',
        reason_code: 'target_considered',
        detail: 'candidate evaluated against retention-1; bounded evidence only',
      },
    ],
    targets_acted: [],
    targets_skipped: [
      {
        target_type: 'retention_candidate_record',
        target_id: 'ticket-456',
        action: 'bounded_review_evidence',
        reason_code: 'retention_manual_review',
        detail: 'manual review only',
      },
    ],
    reason_codes: ['retention_manual_review', 'review_only_intent'],
    next_step: 'Review the retained evidence for manual approval; no disposal has been executed.',
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    blocker_metadata: [],
  },
  would_execute: false,
};

const RETENTION_EXECUTION_EXECUTED: RetentionExecutionMetadata = {
  ...RETENTION_EXECUTION_BLOCKED,
  id: 'retention-exec-executed',
  requested_at: '2026-07-09T13:50:00Z',
  execution_status: 'executed',
  operator_review_decision: 'execution_recorded',
  requested_policy: {
    ...((RETENTION_EXECUTION_BLOCKED.requested_policy as Record<string, unknown>) ?? {}),
    disposal_action: 'archive',
    destructive_action: false,
  },
  candidate: { scope: 'support', category: 'messages', record_id: 'ticket-789' },
  matched_records_summary: {
    scope: 'support',
    category: 'messages',
    record_id: 'ticket-789',
    record_count: 1,
    policy_match_count: 1,
    destructive_policy_count: 0,
    policy_ids: ['retention-1'],
  },
  approval: {
    approval_reference: 'privacy-board-42',
    policy_id: 'retention-1',
    disposal_action: 'archive',
    approved_by: 'privacy-board',
    approved_at: '2026-07-09T13:45:00Z',
  },
  outcome: 'bounded_archive_recorded',
  block_reason: 'bounded archive evidence recorded for the retention target',
  evidence_state: 'bounded_archive_recorded',
  evidence_next_step:
    'Bounded archive evidence was recorded for this target; no source document deletion or GDPR erasure was performed.',
  workflow: {
    status: 'awaiting_manual_review',
    blockers: [],
    required_approvals: [
      {
        code: 'retention_manual_review',
        required_from: 'privacy_or_settings_manager',
        reason: 'approve the retained evidence before any separate operational action',
      },
    ],
    next_step:
      'Bounded archive evidence was recorded for this target; no source document deletion or GDPR erasure was performed.',
  },
  execution_result: {
    bounded_executor: true,
    executed_at: '2026-07-09T13:50:00Z',
    executed_by: 'amelia.marques',
    targets_considered: [
      {
        target_type: 'retention_candidate_record',
        target_id: 'ticket-789',
        action: 'bounded_archive_evidence',
        reason_code: 'target_considered',
        detail: 'candidate evaluated against retention-1; bounded evidence only',
      },
    ],
    targets_acted: [
      {
        target_type: 'retention_candidate_record',
        target_id: 'ticket-789',
        action: 'bounded_archive_evidence',
        reason_code: 'bounded_archive_recorded',
        detail: 'bounded archive evidence recorded',
      },
    ],
    targets_skipped: [],
    reason_codes: ['bounded_archive_recorded'],
    next_step:
      'Bounded archive evidence was recorded for this target; no source document deletion or GDPR erasure was performed.',
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    blocker_metadata: [],
  },
  would_execute: true,
};

type ProcessorRecordMetadata = typeof PROCESSOR_ONE;
type DpiaRecordMetadata = typeof DPIA_ONE;
type BreachPlaybookMetadata = typeof BREACH_PLAYBOOK_ONE;
type TransferControlMetadata = typeof TRANSFER_CONTROL_ONE;
type RetentionPolicyMetadata = typeof RETENTION_POLICY_ONE;
type RetentionDueCandidatesSuppressionSummaryMetadata = {
  suppressed_by_bounded_evidence_count: number;
  note: string;
};
type RetentionDueCandidatesReportMetadata = RetentionDueCandidatesReport & {
  suppression_summary?: RetentionDueCandidatesSuppressionSummaryMetadata;
};
type RetentionCandidateResolutionMetadata = RetentionCandidateResolutionRecord;

function apiKeyIdFromUrl(url: string): string | undefined {
  return url.match(/\/v1\/api-keys\/([^/]+)/)?.[1];
}

function privacyRecordIdFromUrl(
  url: string,
  root: 'processors' | 'dpias' | 'breach-playbooks' | 'transfer-controls' | 'retention-policies',
): string | undefined {
  return url.match(new RegExp(`/v1/privacy/${root}/([^/]+)`))?.[1];
}

function retentionExecutionReviewClosureIdFromUrl(url: string): string | undefined {
  return url.match(/\/v1\/privacy\/retention-executions\/([^/]+)\/review-closure/)?.[1];
}

function retentionCandidateResolutionIdFromUrl(url: string): string | undefined {
  const match = url.match(/\/v1\/privacy\/retention-due-candidates\/([^/]+)\/resolution/);
  return match ? decodeURIComponent(match[1]) : undefined;
}

type TestSettings = typeof DEFAULT_SETTINGS;

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function retentionDisposalActionForResolution(action: string): RetentionDisposalAction {
  if (RETENTION_DISPOSAL_ACTIONS.includes(action as RetentionDisposalAction)) {
    return action as RetentionDisposalAction;
  }
  throw new Error(`unsupported retention disposal action for resolution snapshot: ${action}`);
}

function retentionSuppressionSummary(
  suppressedByBoundedEvidenceCount: number,
): RetentionDueCandidatesSuppressionSummaryMetadata {
  return {
    suppressed_by_bounded_evidence_count: suppressedByBoundedEvidenceCount,
    note: RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE,
  };
}

function materializeSettings(value: unknown): TestSettings {
  const partial = cloneJson(value) as Partial<TestSettings>;
  const platform = partial.platform ?? DEFAULT_SETTINGS.platform;
  const logging = platform.logging ?? DEFAULT_SETTINGS.platform.logging;
  const workflow = partial.workflow ?? DEFAULT_SETTINGS.workflow;
  const workflowReminders = workflow.reminders ?? DEFAULT_SETTINGS.workflow.reminders;
  const dataManagement = partial.data_management ?? DEFAULT_SETTINGS.data_management;
  return {
    ...DEFAULT_SETTINGS,
    ...partial,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      ...(partial.signing ?? {}),
      cmd: { ...DEFAULT_SETTINGS.signing.cmd, ...(partial.signing?.cmd ?? {}) },
      tsl_sources: partial.signing?.tsl_sources ?? DEFAULT_SETTINGS.signing.tsl_sources,
      tsa_providers: partial.signing?.tsa_providers ?? DEFAULT_SETTINGS.signing.tsa_providers,
      providers: partial.signing?.providers ?? DEFAULT_SETTINGS.signing.providers,
    },
    ai: { ...DEFAULT_SETTINGS.ai, ...(partial.ai ?? {}) },
    ui: {
      ...DEFAULT_SETTINGS.ui,
      ...(partial.ui ?? {}),
      registered_entity_columns:
        partial.ui?.registered_entity_columns ?? DEFAULT_SETTINGS.ui.registered_entity_columns,
    },
    registry_auto_update: {
      ...DEFAULT_SETTINGS.registry_auto_update,
      ...(partial.registry_auto_update ?? {}),
      cadence:
        partial.registry_auto_update?.cadence ?? DEFAULT_SETTINGS.registry_auto_update.cadence,
      entity_defaults: {
        ...DEFAULT_SETTINGS.registry_auto_update.entity_defaults,
        ...(partial.registry_auto_update?.entity_defaults ?? {}),
        enabled_profiles:
          partial.registry_auto_update?.entity_defaults?.enabled_profiles ??
          DEFAULT_SETTINGS.registry_auto_update.entity_defaults.enabled_profiles,
      },
    },
    workflow: {
      ...DEFAULT_SETTINGS.workflow,
      ...(partial.workflow ?? {}),
      reminders: {
        ...DEFAULT_SETTINGS.workflow.reminders,
        ...(partial.workflow?.reminders ?? {}),
        sources: {
          ...DEFAULT_SETTINGS.workflow.reminders.sources,
          ...(workflowReminders.sources ?? {}),
        },
      },
    },
    data_management: {
      ...DEFAULT_SETTINGS.data_management,
      ...dataManagement,
      retained_export_cleanup: {
        ...DEFAULT_SETTINGS.data_management.retained_export_cleanup,
        ...(dataManagement.retained_export_cleanup ?? {}),
      },
      backup_recovery: {
        ...DEFAULT_SETTINGS.data_management.backup_recovery,
        ...(dataManagement.backup_recovery ?? {}),
      },
    },
    platform: {
      ...DEFAULT_SETTINGS.platform,
      ...platform,
      logging: {
        ...DEFAULT_SETTINGS.platform.logging,
        ...logging,
        service_overrides:
          logging.service_overrides ?? DEFAULT_SETTINGS.platform.logging.service_overrides,
      },
      api_server: {
        ...DEFAULT_SETTINGS.platform.api_server,
        ...(platform.api_server ?? {}),
      },
      mcp_stdio_server: {
        ...DEFAULT_SETTINGS.platform.mcp_stdio_server,
        ...(platform.mcp_stdio_server ?? {}),
      },
      audit: platform.audit ?? DEFAULT_SETTINGS.platform.audit,
    },
  };
}

function platformActionCapabilities(serviceId: 'api' | 'mcp_stdio') {
  if (serviceId === 'api') {
    return [
      {
        action: 'start',
        supported: false,
        outcome: 'unsupported',
        limitation: 'The current API process cannot start another copy of itself.',
      },
      {
        action: 'stop',
        supported: false,
        outcome: 'unsupported',
        limitation: 'The current API process cannot stop itself through this request.',
      },
      {
        action: 'restart',
        supported: false,
        outcome: 'restart_required',
        limitation: 'Restart requires an external supervisor or process relaunch.',
      },
    ];
  }
  return ['start', 'stop', 'restart'].map((action) => ({
    action,
    supported: false,
    outcome: 'supervisor_required',
    limitation:
      'The stdio MCP server is launched externally; the API can only record desired state.',
  }));
}

function platformServiceStatus(settings: TestSettings, serviceId: 'api' | 'mcp_stdio') {
  if (serviceId === 'api') {
    return {
      id: 'api',
      kind: 'api',
      label: 'Chancela API server',
      configured: true,
      enabled: settings.platform.api_server.enabled,
      desired_state: settings.platform.api_server.desired_state,
      actual_runtime_status: 'running',
      controllable_actions: platformActionCapabilities('api'),
      logging_level:
        settings.platform.logging.global === 'off'
          ? 'off'
          : (settings.platform.logging.service_overrides.api ?? settings.platform.logging.api),
      last_action: settings.platform.api_server.last_action,
      limitations: [
        'The API can observe this process as running only because it is serving this request.',
        'Start, stop, and restart require an external supervisor or process relaunch.',
      ],
    };
  }
  return {
    id: 'mcp_stdio',
    kind: 'mcp',
    label: 'Chancela MCP stdio server',
    configured: false,
    enabled: settings.platform.mcp_stdio_server.enabled,
    desired_state: settings.platform.mcp_stdio_server.desired_state,
    actual_runtime_status: 'unknown',
    controllable_actions: platformActionCapabilities('mcp_stdio'),
    logging_level:
      settings.platform.logging.global === 'off'
        ? 'off'
        : (settings.platform.logging.service_overrides.mcp_stdio ?? settings.platform.logging.mcp),
    last_action: settings.platform.mcp_stdio_server.last_action,
    limitations: [
      'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
      'No MCP API key or other secret is exposed through this status surface.',
    ],
  };
}

function platformServicesResponse(settings: TestSettings) {
  return {
    services: [
      platformServiceStatus(settings, 'api'),
      platformServiceStatus(settings, 'mcp_stdio'),
    ],
  };
}

const PLATFORM_LOG_LIMITATIONS = [
  'This is an in-memory API-owned structured log ring; entries reset when the API process restarts.',
  'It is not historical stdout/stderr tailing and does not include MCP process logs unless a future supervisor forwards structured events into the API.',
];

const PLATFORM_LOG_FIXTURE = [
  {
    id: 'platform-log-1',
    seq: 1,
    timestamp: '2026-07-09T12:00:00Z',
    service_id: 'api',
    level: 'info',
    target: 'platform.services',
    message: 'Platform service status read',
    context: { service_count: 2 },
  },
  {
    id: 'platform-log-2',
    seq: 2,
    timestamp: '2026-07-09T12:01:00Z',
    service_id: 'mcp_stdio',
    level: 'warn',
    target: 'platform.service.control',
    message: 'MCP supervisor handoff recorded',
  },
] as const;

function platformOutcome(serviceId: 'api' | 'mcp_stdio', action: string) {
  if (serviceId === 'api' && action === 'restart') return 'restart_required';
  if (serviceId === 'api') return 'unsupported';
  return 'supervisor_required';
}

function platformMessage(serviceId: 'api' | 'mcp_stdio', action: string) {
  if (serviceId === 'api' && action === 'restart') {
    return 'API restart desired state was recorded; an external supervisor must restart the process.';
  }
  if (serviceId === 'api' && action === 'start') {
    return 'API start desired state was recorded, but this already-running process cannot start itself.';
  }
  if (serviceId === 'api') {
    return 'API stop desired state was recorded, but this process cannot terminate itself safely through the API.';
  }
  if (action === 'start') {
    return 'MCP start desired state was recorded; relaunch the external MCP client or supervisor.';
  }
  if (action === 'stop') {
    return 'MCP stop desired state was recorded; stop or relaunch the external MCP client or supervisor.';
  }
  return 'MCP restart desired state was recorded; relaunch the external MCP client or supervisor.';
}

/**
 * A fetch stub for the settings page's endpoints. Captures every call so a test
 * can assert what the PUT sent. The PUT echoes the posted document (schema stamped),
 * mirroring the real server.
 */
function settingsFetch(
  initialSettings: unknown = DEFAULT_SETTINGS,
  options: {
    platformLogs?: readonly unknown[];
    platformLogLimitations?: string[];
  } = {},
): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let storedSettings: unknown = cloneJson(initialSettings);
  let platformLogs = cloneJson(options.platformLogs ?? PLATFORM_LOG_FIXTURE) as Array<
    Record<string, unknown>
  >;
  const platformLogLimitations = options.platformLogLimitations ?? PLATFORM_LOG_LIMITATIONS;
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/platform/logs')) {
      const parsed = new URL(url, 'http://test.local');
      const serviceId = parsed.searchParams.get('service_id');
      const level = parsed.searchParams.get('level');
      const tail = Number(parsed.searchParams.get('tail') ?? '100');
      const logs = platformLogs
        .filter((entry) => !serviceId || entry.service_id === serviceId)
        .filter((entry) => !level || entry.level === level)
        .slice(-tail);
      const oldestSeq = platformLogs.length > 0 ? Number(platformLogs[0].seq) : null;
      const newestSeq =
        platformLogs.length > 0 ? Number(platformLogs[platformLogs.length - 1].seq) : null;
      return Promise.resolve(
        jsonResponse({
          logs,
          tail,
          order: 'chronological',
          retention: {
            retention_limit: 512,
            retained_count: platformLogs.length,
            oldest_seq: oldestSeq,
            newest_seq: newestSeq,
            dropped_before_seq: oldestSeq !== null && oldestSeq > 1 ? oldestSeq - 1 : null,
            durable: false,
            basis: 'memory',
            source: 'process_memory',
          },
          limitations: platformLogLimitations,
        }),
      );
    }

    if (url.includes('/v1/platform/services')) {
      if (method === 'POST') {
        const match = url.match(/\/v1\/platform\/services\/([^/]+)\/actions\/([^/?]+)/);
        const serviceId = decodeURIComponent(match?.[1] ?? '') as 'api' | 'mcp_stdio';
        const action = decodeURIComponent(match?.[2] ?? '') as 'start' | 'stop' | 'restart';
        const desired_state = (action === 'stop' ? 'stopped' : 'running') as 'running' | 'stopped';
        const outcome = platformOutcome(serviceId, action) as
          'unsupported' | 'restart_required' | 'supervisor_required';
        const message = platformMessage(serviceId, action);
        const current = materializeSettings(storedSettings);
        const last_action = {
          action,
          requested_at: '2026-07-09T12:00:00Z',
          requested_by: 'amelia.marques',
          outcome,
          message,
        };
        const controlKey = serviceId === 'api' ? 'api_server' : 'mcp_stdio_server';
        current.platform[controlKey] = {
          ...current.platform[controlKey],
          enabled: desired_state === 'running',
          desired_state,
          last_action,
        };
        current.platform.audit = [
          ...current.platform.audit,
          {
            service_id: serviceId,
            action,
            requested_at: last_action.requested_at,
            requested_by: last_action.requested_by,
            outcome,
            desired_state,
            message,
          },
        ].slice(-100);
        storedSettings = { ...(cloneJson(storedSettings) as object), platform: current.platform };
        const service = platformServiceStatus(current, serviceId);
        platformLogs = [
          ...platformLogs,
          {
            id: `platform-log-${platformLogs.length + 1}`,
            seq: platformLogs.length + 1,
            timestamp: '2026-07-09T12:02:00Z',
            service_id: serviceId,
            level: 'info',
            target: 'platform.service.control',
            message: 'Platform service control desired state recorded',
            context: { action, outcome, applied_to_settings: true },
          },
        ];
        return Promise.resolve(
          jsonResponse({
            service,
            action,
            result: {
              kind: outcome,
              supported: false,
              applied_to_settings: true,
              desired_state,
              actual_runtime_status: service.actual_runtime_status,
              message,
              limitations: service.limitations,
            },
          }),
        );
      }
      return Promise.resolve(
        jsonResponse(platformServicesResponse(materializeSettings(storedSettings))),
      );
    }
    if (url.includes('/v1/settings')) {
      if (method === 'PUT') {
        const parsed = JSON.parse(init?.body as string) as Record<string, unknown>;
        storedSettings = { ...parsed, schema_version: 1 };
        return Promise.resolve(jsonResponse(storedSettings));
      }
      return Promise.resolve(jsonResponse(storedSettings));
    }
    if (url.includes('/v1/registry/lookup')) {
      return Promise.resolve(jsonResponse(REGISTRY_AUTO_UPDATE_PLAN));
    }
    if (/\/v1\/entities\/[^/]+\/registry/.test(url) && method === 'POST') {
      return Promise.resolve(
        jsonResponse({
          accepted: true,
          entity_id: 'ent-1',
          status: 'manual_required',
          generated_at: '2026-07-09T10:01:00Z',
          dry_run_only: true,
          reason: 'manual dry run',
          last_attempt_at: '2026-07-09T10:01:00Z',
          next_allowed_at: null,
          failure_count: 0,
          audit_event_seq: 42,
        }),
      );
    }
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
    }
    if (url.includes('/health')) {
      return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function settingsWithoutAi(): Omit<typeof DEFAULT_SETTINGS, 'ai'> {
  const copy: Partial<typeof DEFAULT_SETTINGS> = { ...DEFAULT_SETTINGS };
  delete copy.ai;
  return copy as Omit<typeof DEFAULT_SETTINGS, 'ai'>;
}

function settingsWithoutProviderMetadata(): unknown {
  return {
    ...DEFAULT_SETTINGS,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      providers: undefined,
    },
  };
}

function settingsWithoutTrustSourceMetadata(): unknown {
  return {
    ...DEFAULT_SETTINGS,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      tsl_sources: undefined,
      tsa_providers: undefined,
    },
  };
}

function settingsWithMultipleTrustSources(): TestSettings {
  return materializeSettings({
    ...DEFAULT_SETTINGS,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      tsl_sources: [
        ...DEFAULT_SETTINGS.signing.tsl_sources,
        {
          id: 'operator-cache',
          name: 'Operator cached TSL',
          enabled: false,
          url: null,
          path: 'F:\\Projects\\chancela\\fixtures\\operator-tsl.xml',
          country: 'PT',
          scheme: 'operator-cache',
          digest: null,
          timeout_seconds: 30,
          max_bytes: 26214400,
          refresh: { enabled: false, cadence: { kind: 'manual' } },
        },
      ],
      tsa_providers: [
        ...DEFAULT_SETTINGS.signing.tsa_providers,
        {
          id: 'backup-tsa',
          name: 'Backup Timestamp TSA',
          enabled: true,
          url: 'http://tsa.backup.example.test/tsa',
          path: null,
          default: false,
          policy: '1.2.3.4.5',
          digest: 'sha256',
          timeout_seconds: 45,
          max_bytes: 1048576,
        },
      ],
    },
  });
}

function apiKeysFetch(initialKeys: ApiKeyMetadata[] = [API_KEY_ONE]): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let keys = initialKeys.map((key) => ({
    ...key,
    grant: {
      ...key.grant,
      permissions: [...key.grant.permissions],
      scope: { ...key.grant.scope },
    },
    rate_limit: key.rate_limit ? { ...key.rate_limit } : undefined,
  }));
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/api-keys/') && method === 'POST' && url.endsWith('/rotate')) {
      const id = apiKeyIdFromUrl(url);
      const existing = keys.find((k) => k.id === id);
      if (!existing) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const rotated = {
        ...existing,
        secret: 'chk_rotated_plaintext_secret',
        prefix: 'chk_rotated',
        revoked: false,
        active: true,
      };
      keys = keys.map((k) =>
        k.id === id
          ? {
              ...k,
              prefix: rotated.prefix,
              revoked: rotated.revoked,
              active: rotated.active,
            }
          : k,
      );
      return Promise.resolve(jsonResponse(rotated));
    }
    if (url.includes('/v1/api-keys/') && method === 'DELETE') {
      const id = apiKeyIdFromUrl(url);
      const updated = { ...keys.find((k) => k.id === id)!, revoked: true, active: false };
      keys = keys.map((k) => (k.id === id ? updated : k));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/api-keys')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Record<string, unknown>;
        const name = body.name as string;
        const grant = body.grant as typeof API_KEY_ONE.grant;
        const rate_limit = body.rate_limit as typeof API_KEY_ONE.rate_limit;
        const created = {
          id: 'key-2',
          secret: 'chk_new_plaintext_secret',
          prefix: 'chk_new',
          created_by: 'user-1',
          created_at: '2026-07-09T11:00:00Z',
          revoked: false,
          active: true,
          name,
          grant,
          rate_limit,
        };
        keys = [
          ...keys,
          {
            id: created.id,
            name: created.name,
            prefix: created.prefix,
            grant: created.grant,
            created_by: created.created_by,
            created_at: created.created_at,
            revoked: created.revoked,
            active: created.active,
            rate_limit: created.rate_limit,
          },
        ];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(keys));
    }
    if (url.includes('/v1/permissions')) return Promise.resolve(jsonResponse(PERMISSION_CATALOG));
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse([]));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([]));
    if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
    }
    if (url.includes('/health')) {
      return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function privacyFetch(
  initialProcessors: ProcessorRecordMetadata[] = [PROCESSOR_ONE],
  initialDpias: DpiaRecordMetadata[] = [DPIA_ONE],
  initialBreachPlaybooks: BreachPlaybookMetadata[] = [BREACH_PLAYBOOK_ONE],
  initialTransferControls: TransferControlMetadata[] = [TRANSFER_CONTROL_ONE],
  initialRetentionPolicies: RetentionPolicyMetadata[] = [RETENTION_POLICY_ONE],
  initialRetentionDueCandidatesReport: RetentionDueCandidatesReportMetadata = RETENTION_DUE_CANDIDATES_REPORT,
  initialRetentionExecutions: RetentionExecutionMetadata[] = [
    RETENTION_EXECUTION_BLOCKED,
    RETENTION_EXECUTION_AWAITING,
    RETENTION_EXECUTION_EXECUTED,
  ],
  initialRetentionCandidateResolutions: RetentionCandidateResolutionMetadata[] = [],
): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let processors = initialProcessors.map((record) => ({
    ...record,
    data_categories: [...record.data_categories],
    subprocessors: [...record.subprocessors],
  }));
  let dpias = initialDpias.map((record) => ({
    ...record,
    data_categories: [...record.data_categories],
    subprocessors: [...record.subprocessors],
    evidence_receipts: [...record.evidence_receipts],
    advisory_review: { ...record.advisory_review },
  }));
  let breachPlaybooks = initialBreachPlaybooks.map((record) => ({
    ...record,
    detection_channels: [...record.detection_channels],
    containment_steps: [...record.containment_steps],
    notification_roles: [...record.notification_roles],
    evidence_receipts: [...record.evidence_receipts],
    advisory_review: { ...record.advisory_review },
  }));
  let transferControls = initialTransferControls.map((record) => ({
    ...record,
    data_categories: [...record.data_categories],
    safeguards: [...record.safeguards],
    evidence_receipts: [...record.evidence_receipts],
    advisory_review: { ...record.advisory_review },
  }));
  let retentionPolicies = initialRetentionPolicies.map((record) => ({ ...record }));
  let retentionDueCandidatesReport = cloneJson(initialRetentionDueCandidatesReport);
  let retentionExecutions = initialRetentionExecutions.map((record) => cloneJson(record));
  let retentionCandidateResolutions = initialRetentionCandidateResolutions.map((record) =>
    cloneJson(record),
  );

  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/privacy/processors/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'processors');
      const patch = JSON.parse(init?.body as string) as Partial<ProcessorRecordMetadata>;
      const current = processors.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const updated = {
        ...current,
        ...patch,
        updated_at: '2026-07-09T12:00:00Z',
        updated_by: 'amelia.marques',
      };
      processors = processors.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/dpias/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'dpias');
      const patch = JSON.parse(init?.body as string) as Partial<DpiaRecordMetadata> & {
        evidence_receipt?: { evidence_type?: 'review' | 'drill'; notes?: string };
      };
      const current = dpias.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const { evidence_receipt: receiptInput, ...recordPatch } = patch;
      const updated = {
        ...current,
        ...recordPatch,
        evidence_receipts: receiptInput
          ? [
              ...current.evidence_receipts,
              {
                id: 'dpia-receipt-patch',
                evidence_type: receiptInput.evidence_type ?? 'review',
                recorded_at: '2026-07-09T13:10:00Z',
                recorded_by: 'amelia.marques',
                notes: receiptInput.notes ?? '',
                authority_filing_completed: false,
                legal_review_accepted: false,
                legal_certification_completed: false,
                external_delivery_completed: false,
                dpia_completed: false,
                compliance_certification_completed: false,
              },
            ]
          : current.evidence_receipts,
        advisory_review: receiptInput
          ? dpiaAdvisoryReviewSummary({
              last_reviewed_at:
                (receiptInput.evidence_type ?? 'review') === 'review'
                  ? '2026-07-09T13:10:00Z'
                  : current.advisory_review.last_reviewed_at,
              last_drill_at:
                (receiptInput.evidence_type ?? 'review') === 'drill'
                  ? '2026-07-09T13:10:00Z'
                  : current.advisory_review.last_drill_at,
              receipt_count: current.evidence_receipts.length + 1,
              review_receipt_count:
                current.advisory_review.review_receipt_count +
                ((receiptInput.evidence_type ?? 'review') === 'review' ? 1 : 0),
              drill_receipt_count:
                current.advisory_review.drill_receipt_count +
                ((receiptInput.evidence_type ?? 'review') === 'drill' ? 1 : 0),
            })
          : current.advisory_review,
        updated_at: '2026-07-09T13:10:00Z',
        updated_by: 'amelia.marques',
      };
      dpias = dpias.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/breach-playbooks/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'breach-playbooks');
      const patch = JSON.parse(init?.body as string) as Partial<BreachPlaybookMetadata> & {
        evidence_receipt?: { evidence_type?: 'review' | 'drill'; notes?: string };
      };
      const current = breachPlaybooks.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const { evidence_receipt: receiptInput, ...recordPatch } = patch;
      const updated = {
        ...current,
        ...recordPatch,
        evidence_receipts: receiptInput
          ? [
              ...current.evidence_receipts,
              {
                id: 'breach-receipt-patch',
                evidence_type: receiptInput.evidence_type ?? 'review',
                recorded_at: '2026-07-09T13:00:00Z',
                recorded_by: 'amelia.marques',
                notes: receiptInput.notes ?? '',
                authority_notified: false,
                subjects_notified: false,
              },
            ]
          : current.evidence_receipts,
        advisory_review: receiptInput
          ? advisoryReviewSummary({
              last_reviewed_at:
                (receiptInput.evidence_type ?? 'review') === 'review'
                  ? '2026-07-09T13:00:00Z'
                  : undefined,
              last_drill_at:
                (receiptInput.evidence_type ?? 'review') === 'drill'
                  ? '2026-07-09T13:00:00Z'
                  : current.advisory_review.last_drill_at,
              receipt_count: current.evidence_receipts.length + 1,
              review_receipt_count:
                current.advisory_review.review_receipt_count +
                ((receiptInput.evidence_type ?? 'review') === 'review' ? 1 : 0),
              drill_receipt_count:
                current.advisory_review.drill_receipt_count +
                ((receiptInput.evidence_type ?? 'review') === 'drill' ? 1 : 0),
            })
          : current.advisory_review,
        updated_at: '2026-07-09T13:00:00Z',
        updated_by: 'amelia.marques',
      };
      breachPlaybooks = breachPlaybooks.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/transfer-controls/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'transfer-controls');
      const patch = JSON.parse(init?.body as string) as Partial<TransferControlMetadata> & {
        evidence_receipt?: { notes?: string };
      };
      const current = transferControls.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const { evidence_receipt: receiptInput, ...recordPatch } = patch;
      const updated = {
        ...current,
        ...recordPatch,
        evidence_receipts: receiptInput
          ? [
              ...current.evidence_receipts,
              {
                id: 'transfer-receipt-patch',
                recorded_at: '2026-07-09T13:00:00Z',
                recorded_by: 'amelia.marques',
                notes: receiptInput.notes ?? '',
                transfer_approved: false,
                data_transfer_executed: false,
              },
            ]
          : current.evidence_receipts,
        advisory_review: receiptInput
          ? advisoryReviewSummary({
              last_reviewed_at: '2026-07-09T13:00:00Z',
              receipt_count: current.evidence_receipts.length + 1,
              review_receipt_count: current.evidence_receipts.length + 1,
            })
          : current.advisory_review,
        updated_at: '2026-07-09T13:00:00Z',
        updated_by: 'amelia.marques',
      };
      transferControls = transferControls.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/retention-policies/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'retention-policies');
      const patch = JSON.parse(init?.body as string) as Partial<RetentionPolicyMetadata>;
      const current = retentionPolicies.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const updated = {
        ...current,
        ...patch,
        updated_at: '2026-07-09T13:20:00Z',
        updated_by: 'amelia.marques',
      };
      retentionPolicies = retentionPolicies.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/retention-policies/dry-run') && method === 'POST') {
      const body = JSON.parse(init?.body as string) as {
        scope: string;
        category: string;
        record_id?: string;
        execution_request?: {
          requested_policy_id?: string;
          execution_mode?: 'review_only' | 'execute_supported';
          operator_notes?: string;
          evidence?: { label: string; value: string }[];
        };
      };
      const matches = retentionPolicies
        .filter(
          (policy) =>
            policy.scope === body.scope &&
            policy.category === body.category &&
            policy.status === 'active' &&
            policy.active,
        )
        .map((policy) => ({
          policy_id: policy.id,
          name: policy.name,
          scope: policy.scope,
          category: policy.category,
          schedule_id: policy.schedule_id,
          retention_period: policy.retention_period,
          disposal_action: policy.disposal_action,
          status: policy.status,
          active: policy.active,
          destructive_action: ['delete', 'anonymize'].includes(policy.disposal_action),
          would_execute: false,
          reason: 'Dry-run only; no disposal executed.',
        }));
      if (body.execution_request) {
        const requestedPolicy = retentionPolicies.find(
          (policy) => policy.id === body.execution_request?.requested_policy_id,
        );
        const supportedBoundedEvidenceAction =
          body.execution_request.execution_mode === 'execute_supported' &&
          (requestedPolicy?.disposal_action === 'no_action' ||
            requestedPolicy?.disposal_action === 'archive')
            ? requestedPolicy.disposal_action
            : null;
        const isSupportedBoundedEvidenceRequest = supportedBoundedEvidenceAction !== null;
        const supportedBoundedOutcome =
          supportedBoundedEvidenceAction === 'archive'
            ? 'bounded_archive_recorded'
            : 'bounded_no_action_recorded';
        const supportedBoundedBlockReason =
          supportedBoundedEvidenceAction === 'archive'
            ? 'bounded archive evidence recorded for the retention target'
            : 'bounded no-action evidence recorded for the retention target';
        const supportedBoundedNextStep =
          supportedBoundedEvidenceAction === 'archive'
            ? 'Bounded archive evidence was recorded for this target; no source records were changed.'
            : 'Bounded no-action evidence was recorded; no source records were changed.';
        const supportedBoundedTargetAction =
          supportedBoundedEvidenceAction === 'archive'
            ? 'bounded_archive_evidence'
            : 'bounded_no_action_evidence';
        const supportedBoundedDetail =
          supportedBoundedEvidenceAction === 'archive'
            ? 'candidate evaluated for bounded archive evidence only'
            : 'candidate evaluated for bounded no-action evidence only';
        const supportedBoundedRecordedDetail =
          supportedBoundedEvidenceAction === 'archive'
            ? 'bounded archive evidence recorded'
            : 'bounded no-action evidence recorded';
        const executionRecord = cloneJson(RETENTION_EXECUTION_AWAITING);
        executionRecord.id = `retention-exec-requested-${retentionExecutions.length + 1}`;
        executionRecord.requested_at = '2026-07-09T14:05:00Z';
        executionRecord.execution_intent = body.execution_request.execution_mode ?? 'review_only';
        executionRecord.execution_status = isSupportedBoundedEvidenceRequest
          ? 'executed'
          : 'awaiting_review';
        executionRecord.operator_review_decision = isSupportedBoundedEvidenceRequest
          ? 'execution_recorded'
          : 'review_required';
        executionRecord.candidate = {
          scope: body.scope,
          category: body.category,
          record_id: body.record_id,
        };
        executionRecord.requested_policy = {
          id: body.execution_request.requested_policy_id,
          found: Boolean(requestedPolicy),
          name: requestedPolicy?.name,
          scope: body.scope,
          category: body.category,
          schedule_id: requestedPolicy?.schedule_id,
          retention_period: requestedPolicy?.retention_period,
          disposal_action: supportedBoundedEvidenceAction ?? 'review',
          status: requestedPolicy?.status,
          active: requestedPolicy?.active,
          stale: false,
          matches_candidate: Boolean(requestedPolicy),
          destructive_action: false,
        };
        executionRecord.matched_records_summary = {
          scope: body.scope,
          category: body.category,
          record_id: body.record_id,
          record_count: body.record_id ? 1 : 0,
          policy_match_count: requestedPolicy ? 1 : 0,
          destructive_policy_count: 0,
          policy_ids: body.execution_request.requested_policy_id
            ? [body.execution_request.requested_policy_id]
            : [],
        };
        if (body.execution_request.operator_notes) {
          executionRecord.operator_notes = body.execution_request.operator_notes;
        } else {
          delete executionRecord.operator_notes;
        }
        executionRecord.audit_evidence = body.execution_request.evidence ?? [];
        executionRecord.outcome = isSupportedBoundedEvidenceRequest
          ? supportedBoundedOutcome
          : 'manual_review_required';
        executionRecord.block_reason = isSupportedBoundedEvidenceRequest
          ? supportedBoundedBlockReason
          : 'retention execution request is recorded for manual review only';
        executionRecord.evidence_state = isSupportedBoundedEvidenceRequest
          ? supportedBoundedOutcome
          : 'review_queued';
        executionRecord.evidence_next_step = isSupportedBoundedEvidenceRequest
          ? supportedBoundedNextStep
          : 'Review retained evidence only; no disposal has been executed.';
        executionRecord.workflow = {
          status: 'awaiting_manual_review',
          blockers: [],
          required_approvals: isSupportedBoundedEvidenceRequest
            ? []
            : [
                {
                  code: 'retention_manual_review',
                  required_from: 'privacy_or_settings_manager',
                  reason: 'review retained evidence only before any separate operational process',
                },
              ],
          next_step: isSupportedBoundedEvidenceRequest
            ? supportedBoundedNextStep
            : 'Review retained evidence only; no disposal has been executed.',
        };
        executionRecord.execution_result = {
          bounded_executor: true,
          targets_considered: [
            {
              target_type: 'retention_candidate_record',
              target_id: body.record_id ?? `${body.scope}:${body.category}`,
              action: isSupportedBoundedEvidenceRequest
                ? supportedBoundedTargetAction
                : 'bounded_review_evidence',
              reason_code: 'target_considered',
              detail: isSupportedBoundedEvidenceRequest
                ? supportedBoundedDetail
                : 'candidate queued for review-only evidence evaluation',
            },
          ],
          targets_acted: isSupportedBoundedEvidenceRequest
            ? [
                {
                  target_type: 'retention_candidate_record',
                  target_id: body.record_id ?? `${body.scope}:${body.category}`,
                  action: supportedBoundedTargetAction,
                  reason_code: supportedBoundedOutcome,
                  detail: supportedBoundedRecordedDetail,
                },
              ]
            : [],
          targets_skipped: isSupportedBoundedEvidenceRequest
            ? []
            : [
                {
                  target_type: 'retention_candidate_record',
                  target_id: body.record_id ?? `${body.scope}:${body.category}`,
                  action: 'bounded_review_evidence',
                  reason_code: 'review_only_intent',
                  detail: 'manual review request only',
                },
              ],
          reason_codes: isSupportedBoundedEvidenceRequest
            ? [supportedBoundedOutcome]
            : ['retention_manual_review', 'review_only_intent'],
          next_step: isSupportedBoundedEvidenceRequest
            ? supportedBoundedNextStep
            : 'Review retained evidence only; no disposal has been executed.',
          destructive_disposal_completed: false,
          full_erasure_completed: false,
          blocker_metadata: [],
        };
        executionRecord.would_execute = false;
        retentionExecutions = [executionRecord, ...retentionExecutions];
        if (isSupportedBoundedEvidenceRequest) {
          const activeCandidates = retentionDueCandidatesReport.candidates.filter(
            (candidate) =>
              !(
                candidate.record_id === body.record_id &&
                candidate.policy_id === body.execution_request?.requested_policy_id
              ),
          );
          const newlySuppressedCount =
            retentionDueCandidatesReport.candidates.length - activeCandidates.length;
          const suppressedByBoundedEvidenceCount =
            retentionDueCandidatesReport.suppressed_by_bounded_evidence_count +
            newlySuppressedCount;
          const suppressedCandidateCount =
            retentionDueCandidatesReport.suppressed_candidate_count + newlySuppressedCount;
          retentionDueCandidatesReport = {
            ...retentionDueCandidatesReport,
            candidate_count: activeCandidates.length,
            suppressed_candidate_count: suppressedCandidateCount,
            suppressed_by_bounded_evidence_count: suppressedByBoundedEvidenceCount,
            suppression_summary:
              suppressedCandidateCount > 0
                ? retentionSuppressionSummary(suppressedByBoundedEvidenceCount)
                : undefined,
            candidates: activeCandidates,
          };
        }
        return Promise.resolve(
          jsonResponse({
            mode: 'execution_request',
            execution_supported: false,
            destructive_execution_supported: false,
            candidate: {
              scope: body.scope,
              category: body.category,
              record_id: body.record_id,
            },
            matched_count: matches.length,
            matches,
            execution_record: executionRecord,
          }),
        );
      }
      return Promise.resolve(
        jsonResponse({
          mode: 'dry_run',
          execution_supported: false,
          destructive_execution_supported: false,
          candidate: {
            scope: body.scope,
            category: body.category,
            record_id: body.record_id,
          },
          matched_count: matches.length,
          matches,
        }),
      );
    }
    if (url.includes('/v1/privacy/retention-executions/') && url.includes('/review-closure')) {
      if (method !== 'POST') {
        return Promise.resolve(jsonResponse({ error: 'method not allowed' }, 405));
      }
      const id = retentionExecutionReviewClosureIdFromUrl(url);
      const current = retentionExecutions.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const body = JSON.parse(init?.body as string) as {
        review_closure_decision: string;
        review_closure_note?: string;
        review_closure_evidence?: { label: string; value: string }[];
        destructive_disposal_completed?: boolean;
        full_erasure_completed?: boolean;
        legal_hold_mutated?: boolean;
        retention_policy_mutated?: boolean;
      };
      const updated = {
        ...current,
        decision_state: 'review_closed',
        review_closure_decision: body.review_closure_decision,
        review_closure_note: body.review_closure_note,
        review_closure_evidence: body.review_closure_evidence ?? [],
        review_closed_by: 'amelia.marques',
        review_closed_at: '2026-07-09T14:30:00Z',
        destructive_disposal_completed: false,
        full_erasure_completed: false,
        legal_hold_mutated: false,
        retention_policy_mutated: false,
      };
      retentionExecutions = retentionExecutions.map((record) =>
        record.id === id ? updated : record,
      );
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/retention-executions')) {
      const parsed = new URL(url, 'http://test.local');
      const status = parsed.searchParams.get('status');
      const filtered =
        status && status !== 'all'
          ? retentionExecutions.filter((record) => record.execution_status === status)
          : retentionExecutions;
      return Promise.resolve(jsonResponse(filtered));
    }
    if (url.includes('/v1/privacy/retention-candidate-resolutions')) {
      return Promise.resolve(jsonResponse(retentionCandidateResolutions));
    }
    if (url.includes('/v1/privacy/retention-due-candidates/') && url.includes('/resolution')) {
      if (method !== 'POST') {
        return Promise.resolve(jsonResponse({ error: 'method not allowed' }, 405));
      }
      const candidateId = retentionCandidateResolutionIdFromUrl(url);
      const candidate = retentionDueCandidatesReport.candidates.find(
        (item) => item.candidate_id === candidateId,
      );
      if (!candidate) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const body = JSON.parse(init?.body as string) as {
        candidate_fingerprint: string;
        disposition: 'evidence_acknowledged' | 'follow_up_required' | 'blocked_follow_up';
        note?: string;
        evidence?: { label: string; value: string }[];
      };
      const recorded: RetentionCandidateResolutionMetadata = {
        id: `retention-candidate-resolution-${retentionCandidateResolutions.length + 1}`,
        candidate_id: candidate.candidate_id,
        candidate_fingerprint: body.candidate_fingerprint,
        recorded_at: '2026-07-09T14:35:00Z',
        recorded_by: 'amelia.marques',
        disposition: body.disposition,
        note: body.note,
        evidence: body.evidence ?? [],
        evidence_count: body.evidence?.length ?? 0,
        candidate: {
          candidate_id: candidate.candidate_id,
          candidate_fingerprint: body.candidate_fingerprint,
          scope: candidate.scope,
          category: candidate.category,
          record_id: candidate.record_id,
          book_id: candidate.book_id,
          entity_id: candidate.entity_id,
          closing_date: candidate.closing_date,
          due_date: candidate.due_date ?? undefined,
          overdue: candidate.overdue,
          policy_id: candidate.policy_id,
          policy_name: candidate.policy_name,
          schedule_id: candidate.schedule_id,
          retention_period: candidate.retention_period,
          disposal_action: retentionDisposalActionForResolution(candidate.disposal_action),
          destructive_action: candidate.destructive_action,
          outcome: candidate.outcome,
          status: candidate.status,
          candidate_evidence_state: candidate.candidate_evidence_state,
          legal_hold_blocker_count: candidate.legal_hold_blockers.length,
          required_approval_count: candidate.required_approvals.length,
          blocker_count: candidate.blockers.length,
          finding_count: candidate.findings.length,
        },
        evidence_only: true,
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
        next_step:
          body.disposition === 'blocked_follow_up'
            ? 'Blocked follow-up evidence recorded; blockers remain active for separate governance review.'
            : 'Evidence-only disposition recorded; the due candidate remains available for separate governance review.',
      };
      retentionCandidateResolutions = [...retentionCandidateResolutions, recorded];
      retentionDueCandidatesReport = {
        ...retentionDueCandidatesReport,
        candidate_resolution_record_count:
          retentionDueCandidatesReport.candidate_resolution_record_count + 1,
        candidates_with_resolution_count: retentionDueCandidatesReport.candidates.some(
          (item) => item.candidate_id === candidateId && item.latest_resolution,
        )
          ? retentionDueCandidatesReport.candidates_with_resolution_count
          : retentionDueCandidatesReport.candidates_with_resolution_count + 1,
        candidates: retentionDueCandidatesReport.candidates.map((item) =>
          item.candidate_id === candidateId
            ? {
                ...item,
                candidate_resolution_record_count: item.candidate_resolution_record_count + 1,
                latest_resolution: {
                  id: recorded.id,
                  candidate_fingerprint: recorded.candidate_fingerprint,
                  recorded_at: recorded.recorded_at,
                  recorded_by: recorded.recorded_by,
                  disposition: recorded.disposition,
                  evidence_count: recorded.evidence_count,
                  note: recorded.note,
                  evidence_only: true,
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
                  next_step: recorded.next_step,
                },
              }
            : item,
        ),
      };
      return Promise.resolve(jsonResponse(recorded, 201));
    }
    if (url.includes('/v1/privacy/retention-due-candidates')) {
      if (method !== 'GET') {
        return Promise.resolve(jsonResponse({ error: 'method not allowed' }, 405));
      }
      return Promise.resolve(jsonResponse(retentionDueCandidatesReport));
    }
    if (url.includes('/v1/privacy/dpia-template')) {
      if (method !== 'GET') {
        return Promise.resolve(jsonResponse({ error: 'method not allowed' }, 405));
      }
      return Promise.resolve(jsonResponse(DPIA_TEMPLATE));
    }
    if (url.includes('/v1/privacy/processors')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<ProcessorRecordMetadata, 'id'>;
        const created = {
          ...body,
          id: 'processor-2',
          created_at: '2026-07-09T12:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T12:00:00Z',
          updated_by: 'amelia.marques',
        };
        processors = [...processors, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(processors));
    }
    if (url.includes('/v1/privacy/dpias')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<DpiaRecordMetadata, 'id'> & {
          evidence_receipt?: { evidence_type?: 'review' | 'drill'; notes?: string };
        };
        const { evidence_receipt: receiptInput, ...recordBody } = body;
        const created = {
          ...recordBody,
          id: 'dpia-2',
          evidence_receipts: receiptInput
            ? [
                {
                  id: 'dpia-receipt-2',
                  evidence_type: receiptInput.evidence_type ?? 'review',
                  recorded_at: '2026-07-09T13:10:00Z',
                  recorded_by: 'amelia.marques',
                  notes: receiptInput.notes ?? '',
                  authority_filing_completed: false,
                  legal_review_accepted: false,
                  legal_certification_completed: false,
                  external_delivery_completed: false,
                  dpia_completed: false,
                  compliance_certification_completed: false,
                },
              ]
            : [],
          advisory_review: receiptInput
            ? dpiaAdvisoryReviewSummary({
                last_reviewed_at:
                  (receiptInput.evidence_type ?? 'review') === 'review'
                    ? '2026-07-09T13:10:00Z'
                    : undefined,
                last_drill_at:
                  (receiptInput.evidence_type ?? 'review') === 'drill'
                    ? '2026-07-09T13:10:00Z'
                    : undefined,
                receipt_count: 1,
                review_receipt_count: (receiptInput.evidence_type ?? 'review') === 'review' ? 1 : 0,
                drill_receipt_count: (receiptInput.evidence_type ?? 'review') === 'drill' ? 1 : 0,
              })
            : dpiaAdvisoryReviewSummary({
                status: 'no_receipt',
                last_reviewed_at: undefined,
                next_review_due_at: undefined,
                days_until_due: undefined,
                receipt_count: 0,
                review_receipt_count: 0,
                drill_receipt_count: 0,
              }),
          created_at: '2026-07-09T12:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T12:00:00Z',
          updated_by: 'amelia.marques',
        };
        dpias = [...dpias, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(dpias));
    }
    if (url.includes('/v1/privacy/breach-playbooks')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<BreachPlaybookMetadata, 'id'> & {
          evidence_receipt?: { evidence_type?: 'review' | 'drill'; notes?: string };
        };
        const { evidence_receipt: receiptInput, ...recordBody } = body;
        const created = {
          ...recordBody,
          id: 'breach-2',
          evidence_receipts: receiptInput
            ? [
                {
                  id: 'breach-receipt-2',
                  evidence_type: receiptInput.evidence_type ?? 'review',
                  recorded_at: '2026-07-09T13:00:00Z',
                  recorded_by: 'amelia.marques',
                  notes: receiptInput.notes ?? '',
                  authority_notified: false,
                  subjects_notified: false,
                },
              ]
            : [],
          advisory_review: receiptInput
            ? advisoryReviewSummary({
                last_reviewed_at:
                  (receiptInput.evidence_type ?? 'review') === 'review'
                    ? '2026-07-09T13:00:00Z'
                    : undefined,
                last_drill_at:
                  (receiptInput.evidence_type ?? 'review') === 'drill'
                    ? '2026-07-09T13:00:00Z'
                    : undefined,
                receipt_count: 1,
                review_receipt_count: (receiptInput.evidence_type ?? 'review') === 'review' ? 1 : 0,
                drill_receipt_count: (receiptInput.evidence_type ?? 'review') === 'drill' ? 1 : 0,
              })
            : advisoryReviewSummary({
                status: 'no_receipt',
                last_reviewed_at: undefined,
                next_review_due_at: undefined,
                days_until_due: undefined,
                receipt_count: 0,
                review_receipt_count: 0,
              }),
          created_at: '2026-07-09T13:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T13:00:00Z',
          updated_by: 'amelia.marques',
        };
        breachPlaybooks = [...breachPlaybooks, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(breachPlaybooks));
    }
    if (url.includes('/v1/privacy/transfer-controls')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<TransferControlMetadata, 'id'> & {
          evidence_receipt?: { notes?: string };
        };
        const { evidence_receipt: receiptInput, ...recordBody } = body;
        const created = {
          ...recordBody,
          id: 'transfer-2',
          evidence_receipts: receiptInput
            ? [
                {
                  id: 'transfer-receipt-2',
                  recorded_at: '2026-07-09T13:00:00Z',
                  recorded_by: 'amelia.marques',
                  notes: receiptInput.notes ?? '',
                  transfer_approved: false,
                  data_transfer_executed: false,
                },
              ]
            : [],
          advisory_review: receiptInput
            ? advisoryReviewSummary({
                last_reviewed_at: '2026-07-09T13:00:00Z',
                receipt_count: 1,
                review_receipt_count: 1,
              })
            : advisoryReviewSummary({
                status: 'no_receipt',
                last_reviewed_at: undefined,
                next_review_due_at: undefined,
                days_until_due: undefined,
                receipt_count: 0,
                review_receipt_count: 0,
              }),
          created_at: '2026-07-09T13:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T13:00:00Z',
          updated_by: 'amelia.marques',
        };
        transferControls = [...transferControls, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(transferControls));
    }
    if (url.includes('/v1/privacy/retention-policies')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<RetentionPolicyMetadata, 'id'>;
        const created = {
          ...body,
          id: 'retention-2',
          created_at: '2026-07-09T13:10:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T13:10:00Z',
          updated_by: 'amelia.marques',
        };
        retentionPolicies = [...retentionPolicies, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(retentionPolicies));
    }
    if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
    }
    if (url.includes('/health')) {
      return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;

  return { fn, calls };
}

function retentionNoActionPolicy(overrides: Partial<RetentionPolicyMetadata> = {}) {
  return {
    ...RETENTION_POLICY_ONE,
    id: 'retention-no-action',
    name: 'Conservação sem ação',
    disposal_action: 'no_action',
    notes: 'Registo delimitado de evidência sem ação.',
    ...overrides,
  };
}

function retentionArchivePolicy(overrides: Partial<RetentionPolicyMetadata> = {}) {
  return {
    ...RETENTION_POLICY_ONE,
    id: 'retention-archive',
    name: 'Arquivo delimitado',
    scope: 'book_archive',
    category: 'documents',
    disposal_action: 'archive',
    notes: 'Registo delimitado de evidência de arquivo.',
    ...overrides,
  };
}

function retentionExecutedEvidenceRecord(
  recordId: string,
  outcome: 'bounded_archive_recorded' | 'bounded_no_action_recorded',
  overrides: Partial<RetentionExecutionMetadata> = {},
): RetentionExecutionMetadata {
  const disposalAction = outcome === 'bounded_archive_recorded' ? 'archive' : 'no_action';
  const policyId = disposalAction === 'archive' ? 'retention-archive' : 'retention-no-action';
  const nextStep =
    outcome === 'bounded_archive_recorded'
      ? 'Bounded archive evidence already exists.'
      : 'Bounded no-action evidence already exists.';
  const record = cloneJson(RETENTION_EXECUTION_EXECUTED);
  record.id = `retention-exec-${recordId}`;
  record.execution_status = 'executed';
  record.operator_review_decision = 'execution_recorded';
  record.candidate = { scope: 'book_archive', category: 'documents', record_id: recordId };
  record.requested_policy = {
    id: policyId,
    found: true,
    name: disposalAction === 'archive' ? 'Arquivo delimitado' : 'Conservação sem ação',
    scope: 'book_archive',
    category: 'documents',
    schedule_id: 'support-messages-v1',
    retention_period: 'P2Y',
    disposal_action: disposalAction,
    status: 'active',
    active: true,
    stale: false,
    matches_candidate: true,
    destructive_action: false,
  };
  record.matched_records_summary = {
    scope: 'book_archive',
    category: 'documents',
    record_id: recordId,
    record_count: 1,
    policy_match_count: 1,
    destructive_policy_count: 0,
    policy_ids: [policyId],
  };
  record.outcome = outcome;
  record.block_reason = nextStep;
  record.evidence_state = outcome;
  record.evidence_next_step = nextStep;
  record.workflow = {
    status: 'awaiting_manual_review',
    blockers: [],
    required_approvals: [],
    next_step: nextStep,
  };
  record.execution_result = {
    bounded_executor: true,
    executed_at: '2026-07-09T14:00:00Z',
    executed_by: 'amelia.marques',
    targets_considered: [
      {
        target_type: 'retention_candidate_record',
        target_id: recordId,
        action:
          outcome === 'bounded_archive_recorded'
            ? 'bounded_archive_evidence'
            : 'bounded_no_action_evidence',
        reason_code: 'target_considered',
        detail: 'candidate evaluated for bounded evidence only',
      },
    ],
    targets_acted: [
      {
        target_type: 'retention_candidate_record',
        target_id: recordId,
        action:
          outcome === 'bounded_archive_recorded'
            ? 'bounded_archive_evidence'
            : 'bounded_no_action_evidence',
        reason_code: outcome,
        detail: nextStep,
      },
    ],
    targets_skipped: [],
    reason_codes: [outcome],
    next_step: nextStep,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    blocker_metadata: [],
  };
  record.would_execute = false;
  return { ...record, ...overrides };
}

function closedRetentionReviewRecord(
  overrides: Partial<RetentionExecutionMetadata> = {},
): RetentionExecutionMetadata {
  const record = cloneJson(RETENTION_EXECUTION_AWAITING);
  return {
    ...record,
    decision_state: 'review_closed',
    review_closure_decision: 'review_evidence_acknowledged',
    review_closure_note:
      'Revisão operacional registada para evidência retida; esta ação não altera registos fonte.',
    review_closure_evidence: [
      {
        label: 'fila_operacional',
        value: 'registo revisto na interface de configuracoes',
      },
    ],
    review_closed_by: 'privacy-manager',
    review_closed_at: '2026-07-09T14:20:00Z',
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    legal_hold_mutated: false,
    retention_policy_mutated: false,
    ...overrides,
  };
}

async function openPrivacySubTab(name: 'Registos' | 'Retenção' | 'Orientação') {
  fireEvent.click(await screen.findByRole('button', { name }));
}

function retentionNoActionCandidate(overrides: Record<string, unknown> = {}) {
  return {
    ...cloneJson(RETENTION_DUE_CANDIDATES_REPORT.candidates[0]),
    candidate_id: 'retention-candidate-no-action',
    record_id: 'archive-doc-no-action',
    book_id: 'book-no-action',
    entity_id: 'entity-no-action',
    policy_id: 'retention-no-action',
    policy_name: 'Conservação sem ação',
    disposal_action: 'no_action',
    destructive_action: false,
    legal_hold_blockers: [],
    required_approvals: [],
    blockers: [],
    findings: [],
    outcome: 'no_action_required',
    status: 'due_no_action',
    candidate_evidence_state: 'review_queued',
    evidence_next_step:
      'Registar apenas evidência delimitada sem ação; nenhum registo fonte é alterado.',
    would_execute: false,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    next_step: 'Registar apenas evidência delimitada sem ação; nenhum registo fonte é alterado.',
    ...overrides,
  };
}

function retentionArchiveCandidate(overrides: Record<string, unknown> = {}) {
  return {
    ...cloneJson(RETENTION_DUE_CANDIDATES_REPORT.candidates[0]),
    candidate_id: 'retention-candidate-archive',
    record_id: 'archive-doc-archive',
    book_id: 'book-archive',
    entity_id: 'entity-archive',
    policy_id: 'retention-archive',
    policy_name: 'Arquivo delimitado',
    disposal_action: 'archive',
    destructive_action: false,
    legal_hold_blockers: [],
    required_approvals: [],
    blockers: [],
    findings: [],
    outcome: 'manual_review_required',
    status: 'awaiting_manual_review',
    candidate_evidence_state: 'review_queued',
    evidence_next_step:
      'Registar apenas evidência delimitada de arquivo; nenhum registo fonte é alterado.',
    would_execute: false,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    next_step: 'Registar apenas evidência delimitada de arquivo; nenhum registo fonte é alterado.',
    ...overrides,
  };
}

function retentionDueReportWith(
  candidates: Record<string, unknown>[],
  overrides: Partial<RetentionDueCandidatesReportMetadata> = {},
): RetentionDueCandidatesReportMetadata {
  const report = {
    ...cloneJson(RETENTION_DUE_CANDIDATES_REPORT),
    candidate_count: candidates.length,
    suppressed_candidate_count: 0,
    suppressed_by_bounded_evidence_count: 0,
    candidates,
    ...overrides,
  } as unknown as RetentionDueCandidatesReportMetadata;
  if (report.suppressed_candidate_count > 0 && !report.suppression_summary) {
    report.suppression_summary = retentionSuppressionSummary(
      report.suppressed_by_bounded_evidence_count,
    );
  }
  return report;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.style.removeProperty('--leather-grain-opacity');
  colorStore.reset();
});

describe('SettingsPage', () => {
  it('offers a sub-tab per section and shows Aparência by default', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // A segmented sub-tab per section (Gestão included).
    for (const name of [
      'Aparência',
      'Documentos',
      'Assinaturas',
      'Gestão',
      'Operações',
      'Sobre',
    ]) {
      expect(await screen.findByRole('button', { name })).toBeTruthy();
    }
    // Aparência is the default section: its theme control is present…
    expect(await screen.findByLabelText('Tema')).toBeTruthy();
    // …while a Documentos-only field is not rendered until that sub-tab is active.
    expect(screen.queryByLabelText('URL de atualização do catálogo CAE')).toBeNull();
  });

  it('deep-links to a section via ?sec= and navigates between sub-tabs', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=documentos']);

    // The deep-linked section renders its field; the default section's does not.
    expect(await screen.findByLabelText('URL de atualização do catálogo CAE')).toBeTruthy();
    expect(screen.queryByLabelText('Tema')).toBeNull();

    // Switching to Sobre surfaces the /health version there.
    fireEvent.click(screen.getByRole('button', { name: 'Sobre' }));
    expect(await screen.findByText('9.9.9')).toBeTruthy();
  });

  it('hosts Identidade as its own card inside Documentos, and keeps its retired deep link working', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    // Identidade is no longer a sub-tab…
    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);
    expect(await screen.findByLabelText('Nome da organização')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Identidade' })).toBeNull();

    // …but the old link lands on Documentos, which shows both cards, each under its own
    // heading, and marks Documentos as the active sub-tab.
    expect(screen.getByRole('heading', { name: 'Identidade', level: 3 })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Documentos', level: 3 })).toBeTruthy();
    expect(screen.getByLabelText('URL de atualização do catálogo CAE')).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Documentos' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('surfaces an initial settings read failure instead of loading forever', async () => {
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/settings')) {
        return Promise.resolve(jsonResponse({ error: 'settings document unavailable' }, 503));
      }
      if (url.includes('/v1/ledger/verify')) {
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      }
      if (url.includes('/health')) {
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    expect(await screen.findByText('settings document unavailable')).toBeTruthy();
    expect(screen.queryByText('A carregar…')).toBeNull();
  });

  it('renders degraded about-state evidence without claiming a healthy ledger or server', async () => {
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      if (url.includes('/v1/ledger/verify')) {
        return Promise.resolve(jsonResponse({ valid: false, length: 4 }));
      }
      if (url.includes('/health')) {
        return Promise.resolve(jsonResponse({ error: 'health unavailable' }, 503));
      }
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=sobre']);

    const about = (await screen.findByRole('heading', { name: 'Sobre', level: 3 })).closest(
      '.panel',
    ) as HTMLElement;
    expect(within(about).getByText('Cadeia comprometida')).toBeTruthy();
    expect(within(about).getByText('—')).toBeTruthy();
    expect(within(about).queryByText('servidor desatualizado')).toBeNull();
  });

  it('persists document locale and numbering edits through the whole settings document', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=documentos']);

    fireEvent.change(await screen.findByLabelText('Idioma'), {
      target: { value: 'en-GB' },
    });
    fireEvent.change(screen.getByLabelText('Esquema de numeração predefinido'), {
      target: { value: 'LooseLeaf' },
    });

    await waitFor(() => expect(calls.some((call) => call.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });
    const body = JSON.parse(
      calls.filter((call) => call.method === 'PUT').at(-1)!.body as string,
    ) as typeof DEFAULT_SETTINGS;
    expect(body.documents.locale).toBe('en-GB');
    expect(body.documents.numbering_scheme_default).toBe('LooseLeaf');
  });

  it('previews texture and custom-colour controls and can restore theme defaults', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    const reroll = vi.spyOn(grainStore, 'reroll');
    colorStore.reset();
    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Regenerar grão' }));
    expect(reroll).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('switch', { name: 'Textura de couro (fundo)' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Textura de couro nos botões' }));

    fireEvent.change(screen.getByLabelText('Primária'), { target: { value: '#112233' } });
    expect(colorStore.get().primary).toBe('#112233');
    fireEvent.click(screen.getByRole('button', { name: 'Repor esta cor' }));
    expect(colorStore.get().primary).toBeUndefined();

    fireEvent.change(screen.getByLabelText('Secundária'), { target: { value: '#445566' } });
    fireEvent.change(screen.getByLabelText('Fundo'), { target: { value: '#778899' } });
    expect(colorStore.hasOverrides()).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Repor predefinições do tema' }));
    expect(colorStore.get()).toEqual({});
    expect(screen.getByText('A usar as cores predefinidas do tema')).toBeTruthy();
  });

  it('spaces the theme reset row on the appearance form rhythm, not a bespoke margin', async () => {
    // The appearance form's rhythm is `.form > * + *` — a DIRECT-child selector. The reset row
    // is nested inside `.color-customizer`, so it never matched and had no top spacing at all,
    // which is what made it read as cramped next to the identically-shaped "baralhar" row two
    // rows up. Pin the structural fix: the nested row steps by the SAME 1rem the section uses.
    const nodeFs = 'node:fs';
    const { readFileSync } = (await import(nodeFs)) as {
      readFileSync(path: string, encoding: 'utf8'): string;
    };
    const css = readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');

    const sectionStep = css.match(/^\.form > \* \+ \* \{[^}]*margin-top:\s*([^;]+);/m);
    expect(sectionStep).toBeTruthy();

    const resetRow = css.match(/^\.color-customizer > \.form__actions \{[^}]*\}/m)?.[0] ?? '';
    expect(resetRow).toContain('margin-top');
    // Same value as the section rhythm — matching it, not inventing a new step.
    expect(resetRow).toContain(`margin-top: ${sectionStep![1]};`);
    // Wraps rather than overflowing the card when the settings column narrows.
    expect(resetRow).toContain('flex-wrap: wrap');
  });

  it('defaults the AI/MCP tenant gate off when the settings document omits it', async () => {
    const { fn } = settingsFetch(settingsWithoutAi());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar IA/MCP',
    })) as HTMLInputElement;
    expect(toggle.checked).toBe(false);
  });

  it('round-trips an enabled AI/MCP tenant gate through the settings autosave', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar IA/MCP',
    })) as HTMLInputElement;
    fireEvent.click(toggle);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.ai).toEqual({ enabled: true });
  });

  it('hides the AI/MCP tenant gate from users without settings.manage', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=gestao'],
    );

    expect(await screen.findByRole('heading', { name: 'Gestão' })).toBeTruthy();
    expect(screen.queryByRole('switch', { name: 'Ativar IA/MCP' })).toBeNull();
  });

  it('renders and autosaves the workflow reminder policy fields', { timeout: 15_000 }, async () => {
    const olderSettings = cloneJson(DEFAULT_SETTINGS) as Partial<typeof DEFAULT_SETTINGS>;
    delete olderSettings.workflow;
    const { fn, calls } = settingsFetch(olderSettings);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const enabled = (await screen.findByRole('switch', {
      name: 'Gerar lembretes locais',
    })) as HTMLInputElement;
    expect(enabled.checked).toBe(true);
    expect((screen.getByLabelText('Limite no painel') as HTMLInputElement).value).toBe('5');
    expect((screen.getByLabelText('Prazo breve') as HTMLInputElement).value).toBe('45');
    expect((screen.getByLabelText('Janela de presenças') as HTMLInputElement).value).toBe('45');
    expect(
      (screen.getByRole('switch', { name: 'Calendário do perfil' }) as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (screen.getByRole('switch', { name: 'Seguimentos de atas' }) as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (screen.getByRole('switch', { name: 'Higiene de presenças' }) as HTMLInputElement).checked,
    ).toBe(true);
    expect(
      (screen.getByRole('switch', { name: 'Revisões de privacidade' }) as HTMLInputElement).checked,
    ).toBe(true);

    fireEvent.click(enabled);
    fireEvent.change(screen.getByLabelText('Limite no painel'), { target: { value: '7' } });
    fireEvent.change(screen.getByLabelText('Prazo breve'), { target: { value: '12' } });
    fireEvent.change(screen.getByLabelText('Janela de presenças'), {
      target: { value: '20' },
    });
    fireEvent.click(screen.getByRole('switch', { name: 'Calendário do perfil' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Seguimentos de atas' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Higiene de presenças' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Revisões de privacidade' }));

    await waitFor(
      () => {
        const put = calls.filter((c) => c.method === 'PUT').at(-1);
        expect(put).toBeTruthy();
        const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
        expect(sent.workflow.reminders).toEqual({
          enabled: false,
          dashboard_limit: 7,
          due_soon_days: 12,
          attendance_lookahead_days: 20,
          sources: {
            profile_calendar: false,
            act_follow_ups: false,
            attendance_hygiene: false,
            privacy_control_reviews: false,
          },
        });
      },
      { timeout: 3000 },
    );
  });

  it('renders and autosaves retained-export cleanup preview policy defaults', async () => {
    const olderSettings = cloneJson(DEFAULT_SETTINGS) as Partial<typeof DEFAULT_SETTINGS>;
    delete olderSettings.data_management;
    const { fn, calls } = settingsFetch(olderSettings);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    expect(
      await screen.findByRole('heading', {
        name: 'Política de limpeza de exportações retidas',
      }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Idade mínima das exportações') as HTMLInputElement).value).toBe(
      '30',
    );
    expect(
      (screen.getByLabelText('Exportações recentes a preservar') as HTMLInputElement).value,
    ).toBe('5');
    expect(screen.getByText(/apenas na pré-visualização de limpeza/)).toBeTruthy();
    expect(screen.getByText(/Não aprovam retenção legal/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Idade mínima das exportações'), {
      target: { value: '45' },
    });
    fireEvent.change(screen.getByLabelText('Exportações recentes a preservar'), {
      target: { value: '9' },
    });

    await waitFor(
      () => {
        const put = calls.filter((c) => c.method === 'PUT').at(-1);
        expect(put).toBeTruthy();
        const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
        expect(sent.data_management.retained_export_cleanup).toEqual({
          minimum_age_days: 45,
          keep_latest: 9,
        });
      },
      { timeout: 3000 },
    );
  });

  it('renders and autosaves local backup recovery freshness policy defaults', async () => {
    const olderSettings = cloneJson(DEFAULT_SETTINGS) as Partial<typeof DEFAULT_SETTINGS>;
    olderSettings.data_management = {
      retained_export_cleanup: DEFAULT_SETTINGS.data_management.retained_export_cleanup,
    } as typeof DEFAULT_SETTINGS.data_management;
    const { fn, calls } = settingsFetch(olderSettings);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    expect(
      await screen.findByRole('heading', {
        name: 'Política local de recuperação de backups',
      }),
    ).toBeTruthy();
    expect((screen.getByLabelText('Idade máxima do ensaio') as HTMLInputElement).value).toBe('90');
    expect((screen.getByLabelText('RPO alvo') as HTMLInputElement).value).toBe('1440');
    expect((screen.getByLabelText('RTO alvo') as HTMLInputElement).value).toBe('240');
    expect(screen.getByText(/não provam custódia off-site/i)).toBeTruthy();
    expect(screen.getByText(/não certificam RPO\/RTO/i)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Idade máxima do ensaio'), {
      target: { value: '120' },
    });
    fireEvent.change(screen.getByLabelText('RPO alvo'), {
      target: { value: '720' },
    });
    fireEvent.change(screen.getByLabelText('RTO alvo'), {
      target: { value: '180' },
    });

    await waitFor(
      () => {
        const put = calls.filter((c) => c.method === 'PUT').at(-1);
        expect(put).toBeTruthy();
        const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
        expect(sent.data_management.backup_recovery).toEqual({
          max_drill_age_days: 120,
          target_rpo_minutes: 720,
          target_rto_minutes: 180,
        });
      },
      { timeout: 3000 },
    );
  });

  it('shows platform API and MCP status with honest control limitations', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByRole('button', { name: 'Operações' })).toBeTruthy();
    expect(await screen.findByText('Chancela API server')).toBeTruthy();
    expect(await screen.findByText('Chancela MCP stdio server')).toBeTruthy();
    expect(screen.getAllByText('Reinício necessário').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Supervisor necessário').length).toBeGreaterThan(0);
    expect(screen.getByText(/cannot observe or spawn/)).toBeTruthy();
    expect(screen.getAllByRole('button', { name: /Registar reinício/ }).length).toBeGreaterThan(0);
  });

  it('renders only meaningful platform action buttons from backend capabilities', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    const apiRow = (await screen.findByText('Chancela API server')).closest('section');
    expect(apiRow).toBeTruthy();
    expect(within(apiRow!).queryByRole('button', { name: /Registar arranque/ })).toBeNull();
    expect(within(apiRow!).getByRole('button', { name: /Registar paragem/ })).toBeTruthy();
    expect(within(apiRow!).getByRole('button', { name: /Registar reinício/ })).toBeTruthy();
    expect(within(apiRow!).getAllByText('Não suportado').length).toBeGreaterThan(0);
    expect(
      within(apiRow!).getByText('The current API process cannot start another copy of itself.'),
    ).toBeTruthy();

    const mcpRow = (await screen.findByText('Chancela MCP stdio server')).closest('section');
    expect(mcpRow).toBeTruthy();
    expect(within(mcpRow!).getByRole('button', { name: /Registar arranque/ })).toBeTruthy();
    expect(within(mcpRow!).queryByRole('button', { name: /Registar paragem/ })).toBeNull();
    expect(within(mcpRow!).queryByRole('button', { name: /Registar reinício/ })).toBeNull();
    expect(within(mcpRow!).getAllByText('Supervisor necessário').length).toBeGreaterThan(0);
    expect(
      within(mcpRow!).getAllByText(
        'The stdio MCP server is launched externally; the API can only record desired state.',
      ),
    ).toHaveLength(3);
  });

  it('shows global-off effective platform logging even when service overrides remain stored', async () => {
    const { fn } = settingsFetch(
      materializeSettings({
        ...DEFAULT_SETTINGS,
        platform: {
          ...DEFAULT_SETTINGS.platform,
          logging: {
            ...DEFAULT_SETTINGS.platform.logging,
            global: 'off',
            app: 'trace',
            api: 'debug',
            mcp: 'warn',
            service_overrides: {
              api: 'trace',
              mcp_stdio: 'debug',
            },
          },
        },
      }),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    const summary = await screen.findByRole('group', { name: 'Log efetivo' });
    expect(within(summary).getAllByText('Off')).toHaveLength(3);
    expect(within(summary).getByText('Aplicação')).toBeTruthy();
    expect(within(summary).getByText('Servidor API')).toBeTruthy();
    expect(within(summary).getByText('Servidor MCP stdio')).toBeTruthy();
    expect(within(summary).getAllByText('Global: Off')).toHaveLength(3);
    expect(within(summary).queryByText(/Sobreposições/)).toBeNull();
  });

  it('shows AI/MCP provenance assurance to settings managers without secret material', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=operacoes'],
    );

    const title = await screen.findByText('Garantia IA/MCP');
    const panel = title.closest('[role="note"]') as HTMLElement | null;
    expect(panel).toBeTruthy();
    expect(within(panel!).getByText(/O MCP fica inativo/)).toBeTruthy();
    expect(within(panel!).getByText(/RBAC por chave API no servidor/)).toBeTruthy();
    expect(within(panel!).getByText(/draft_minutes e draft_act/)).toBeTruthy();
    expect(within(panel!).getByText(/validate_signature_bundle/)).toBeTruthy();
    expect(panel!.textContent ?? '').not.toMatch(/chk_[A-Za-z0-9_]+|Bearer\s+\S+|plaintext/i);
  });

  it('renders the platform log tail with limitations and expandable context', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    expect(await screen.findByText('Cauda estruturada de logs da API')).toBeTruthy();
    expect(await screen.findByText('Platform service status read')).toBeTruthy();
    expect(screen.getByText(/in-memory API-owned structured log ring/)).toBeTruthy();
    expect(screen.getByText('Limite de retenção')).toBeTruthy();
    expect(screen.getByText('Retidas')).toBeTruthy();
    expect(screen.getByText('Ring em memória')).toBeTruthy();
    expect(screen.getByText('process_memory')).toBeTruthy();
    expect(screen.getByText('2 entradas · limite 100 · cronológico')).toBeTruthy();
    expect(screen.getAllByText('Servidor API').length).toBeGreaterThan(0);
    expect(screen.getByText('platform.services')).toBeTruthy();

    const row = screen.getByText('Platform service status read').closest('tr');
    expect(row).toBeTruthy();
    fireEvent.click(within(row!).getByText('Contexto'));
    expect(within(row!).getByText(/service_count/)).toBeTruthy();

    const minimalRow = screen.getByText('MCP supervisor handoff recorded').closest('tr');
    expect(minimalRow).toBeTruthy();
    expect(within(minimalRow!).getByText('Sem contexto')).toBeTruthy();
  });

  it('refetches platform logs with selected filters and manual refresh', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    expect(await screen.findByText('Platform service status read')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Serviço'), { target: { value: 'api' } });
    fireEvent.change(screen.getByLabelText('Nível'), { target: { value: 'info' } });
    fireEvent.change(screen.getByLabelText('Entradas'), { target: { value: '25' } });

    await waitFor(() => {
      expect(
        calls.some((call) => {
          if (!call.url.includes('/v1/platform/logs')) return false;
          const parsed = new URL(call.url, 'http://test.local');
          return (
            parsed.searchParams.get('service_id') === 'api' &&
            parsed.searchParams.get('level') === 'info' &&
            parsed.searchParams.get('tail') === '25'
          );
        }),
      ).toBe(true);
    });

    const refreshButton = await waitFor(() =>
      screen.getByRole('button', { name: 'Atualizar logs' }),
    );
    const beforeRefresh = calls.filter((call) => call.url.includes('/v1/platform/logs')).length;
    fireEvent.click(refreshButton);
    await waitFor(() =>
      expect(calls.filter((call) => call.url.includes('/v1/platform/logs')).length).toBeGreaterThan(
        beforeRefresh,
      ),
    );
  });

  it('shows platform log empty state together with backend limitations', async () => {
    const { fn } = settingsFetch(DEFAULT_SETTINGS, {
      platformLogs: [],
      platformLogLimitations: ['Ring only; no historical process logs are retained.'],
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    expect(await screen.findByText('Sem logs da plataforma')).toBeTruthy();
    expect(screen.getByText('Ring only; no historical process logs are retained.')).toBeTruthy();
    expect(screen.getAllByText('0').length).toBeGreaterThan(0);
    expect(screen.getAllByText('n/a').length).toBeGreaterThan(0);
    expect(screen.getByText('0 entradas · limite 100 · cronológico')).toBeTruthy();
  });

  it('renders a minimal platform log entry without context', async () => {
    const { fn } = settingsFetch(DEFAULT_SETTINGS, {
      platformLogs: [
        {
          id: 'platform-log-1',
          seq: 1,
          timestamp: '2026-07-09T12:05:00Z',
          service_id: 'app',
          level: 'debug',
          target: 'platform.app',
          message: 'App shell observed platform state',
        },
      ],
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    expect(await screen.findByText('App shell observed platform state')).toBeTruthy();
    expect(screen.getAllByText('Aplicação').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Debug').length).toBeGreaterThan(0);
    expect(screen.getByText('Sem contexto')).toBeTruthy();
  });

  it('records a platform MCP start desired state without implying live process control', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    const mcpRow = (await screen.findByText('Chancela MCP stdio server')).closest('section');
    expect(mcpRow).toBeTruthy();
    fireEvent.click(within(mcpRow!).getByRole('button', { name: /Registar arranque/ }));

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'POST' &&
            call.url.includes('/v1/platform/services/mcp_stdio/actions/start'),
        ),
      ).toBe(true),
    );
    expect(
      (await screen.findAllByText(/MCP start desired state was recorded/)).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText('Supervisor necessário').length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Operações')).length).toBeGreaterThan(0);
  });

  it('autosaves platform logging levels through the whole settings document', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    const globalLog = (await screen.findByLabelText('Global')) as HTMLSelectElement;
    fireEvent.change(globalLog, { target: { value: 'debug' } });
    const mcpOverride = screen.getByLabelText('MCP stdio') as HTMLSelectElement;
    fireEvent.change(mcpOverride, { target: { value: 'trace' } });

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.platform.logging.global).toBe('debug');
    expect(sent.platform.logging.service_overrides.mcp_stdio).toBe('trace');
    expect(sent.platform.api_server.desired_state).toBe('running');
  });

  it('shows the backend-owned registry auto-update plan and records a dry-run attempt', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    expect(await screen.findByText('Atualização automática da certidão permanente')).toBeTruthy();
    expect(await screen.findByText('Acme, S.A.')).toBeTruthy();
    expect(screen.getByText('Simulação')).toBeTruthy();
    expect(screen.getByText('Por atualizar')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Pedir tentativa' }));

    const resultTitle = await screen.findByText('Resultado da tentativa');
    const resultPanel = resultTitle.closest('[role="note"]');
    expect(resultPanel).toBeTruthy();
    expect(within(resultPanel as HTMLElement).getByText('Revisão manual')).toBeTruthy();

    const attempt = await waitFor(() =>
      calls.find(
        (call) => call.method === 'POST' && call.url.includes('/v1/entities/ent-1/registry'),
      ),
    );
    expect(attempt).toBeTruthy();
    expect(JSON.parse(attempt!.body as string)).toEqual({ dry_run: true });
  });

  it('round-trips registry auto-update settings through the whole-document autosave', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar trabalhador de atualização',
    })) as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    fireEvent.click(toggle);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.registry_auto_update.enabled).toBe(true);
    expect(sent.registry_auto_update.stale_threshold_hours).toBe(720);
    expect(sent.registry_auto_update.entity_defaults).toEqual({
      enabled: false,
      enabled_profiles: [],
    });
  });

  it('round-trips registered entity table columns through settings autosave', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const seat = (await screen.findByRole('switch', { name: 'Sede' })) as HTMLInputElement;
    expect(seat.checked).toBe(false);
    fireEvent.click(seat);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.ui.registered_entity_columns).toEqual([
      'Name',
      'Nipc',
      'Seat',
      'Type',
      'LastActivity',
      'Actions',
    ]);
  });

  it('applies the theme override to the document root live', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);
    const themeSelect = (await screen.findByLabelText('Tema')) as HTMLSelectElement;

    fireEvent.change(themeSelect, { target: { value: 'dark' } });
    await waitFor(() => expect(document.documentElement.getAttribute('data-theme')).toBe('dark'));

    fireEvent.change(themeSelect, { target: { value: 'system' } });
    await waitFor(() => expect(document.documentElement.hasAttribute('data-theme')).toBe(false));
  });

  it('scales the grain opacity var from the intensity slider live', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);
    const slider = (await screen.findByRole('slider')) as HTMLInputElement;

    fireEvent.change(slider, { target: { value: '30' } });
    await waitFor(() =>
      expect(document.documentElement.style.getPropertyValue('--leather-grain-opacity')).toBe(
        '0.3',
      ),
    );
  });

  it('PUTs the full settings document via autosave, with edits spanning sub-tabs', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // Edit the org name under Documentos (Identidade is a card there now)…
    fireEvent.click(await screen.findByRole('button', { name: 'Documentos' }));
    const nameInput = (await screen.findByLabelText('Nome da organização')) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Encosto Estratégico, Lda.' } });

    const caeUrl = (await screen.findByLabelText(
      'URL de atualização do catálogo CAE',
    )) as HTMLInputElement;
    fireEvent.change(caeUrl, { target: { value: 'https://catalog.example.pt/cae_dataset.json' } });

    // …then the theme under Aparência (the working copy spans sub-tabs).
    fireEvent.click(screen.getByRole('button', { name: 'Aparência' }));
    fireEvent.change(await screen.findByLabelText('Tema'), { target: { value: 'dark' } });

    // Autosave is always-on (no manual "Guardar agora" button while enabled): the debounced
    // autosave PUTs the whole document on its own, spanning every edited sub-tab.
    expect(screen.queryByRole('button', { name: 'Guardar agora' })).toBeNull();
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    // The whole document is sent, not a partial patch.
    expect(sent.organization.name).toBe('Encosto Estratégico, Lda.');
    expect(sent.appearance.theme).toBe('dark');
    expect(sent.documents).toBeTruthy();
    expect(sent.signing).toBeTruthy();
    // The audit actor is passed through (attributed from the session, not edited here).
    expect(sent.organization.default_actor).toBe('api');
    // The catalog section (F1b) is part of the whole-document PUT.
    expect(sent.catalog.cae_update_url).toBe('https://catalog.example.pt/cae_dataset.json');
  });

  it('autosaves an edit after the debounce (no explicit save) and confirms with a success toast', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);

    const nameInput = (await screen.findByLabelText('Nome da organização')) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Encosto Estratégico, Lda.' } });

    // No button was clicked: the debounced autosave PUTs on its own.
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });
    const put = calls.find((c) => c.method === 'PUT');
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.organization.name).toBe('Encosto Estratégico, Lda.');

    // Success is a normal toast (not an inline block message).
    expect(await screen.findByText('Configurações guardadas.')).toBeTruthy();
    // The old inline "Guardado" affordance is gone and the save bar collapses on a clean
    // form (nothing left to save → no block, no leftover status text).
    await waitFor(() => expect(screen.queryByText('Guardado')).toBeNull());
    expect(screen.queryByText('Alterações por guardar…')).toBeNull();
  });

  it('raises a toast and keeps an inline error when an autosave fails', async () => {
    const calls: Recorded[] = [];
    let putAttempts = 0;
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: (init?.body as string) ?? null });
      if (url.includes('/v1/settings')) {
        if (method === 'PUT') {
          putAttempts += 1;
          if (putAttempts === 1) {
            return Promise.resolve(jsonResponse({ error: 'Falha ao guardar' }, 500));
          }
          return Promise.resolve(jsonResponse(JSON.parse(init?.body as string)));
        }
        return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      }
      if (url.includes('/v1/ledger/verify'))
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      if (url.includes('/health'))
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);

    const nameInput = (await screen.findByLabelText('Nome da organização')) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Encosto Estratégico, Lda.' } });

    // The failed autosave surfaces an assertive toast…
    const alert = await screen.findByRole('alert', undefined, { timeout: 3000 });
    expect(alert.textContent).toContain('Falha ao guardar');
    // …and the field stays editable (retryable). Autosave is on, so there is no persistent
    // "Guardar agora"; the error state instead exposes a retry affordance so the save is
    // still recoverable.
    expect(nameInput.disabled).toBe(false);
    expect(screen.queryByRole('button', { name: 'Guardar agora' })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Tentar novamente' }));
    await waitFor(() => expect(putAttempts).toBe(2));
    expect(await screen.findByText('Configurações guardadas.')).toBeTruthy();
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: 'Tentar novamente' })).toBeNull(),
    );
  });

  it('hides "Guardar agora" while autosave is enabled (no persistent flush button)', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    const { container } = renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);

    // The section loaded (its field is present) but the manual flush button is not shown —
    // autosave is always-on today.
    await screen.findByLabelText('Nome da organização');
    expect(screen.queryByRole('button', { name: 'Guardar agora' })).toBeNull();
    // On a clean (untouched) form there is no save bar block at all — it appears only to
    // report a failed save while autosave is enabled.
    expect(container.querySelector('.settings-savebar')).toBeNull();
  });

  it('shows a FieldHelp affordance on config fields (Aparência by default)', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // The theme control is present…
    expect(await screen.findByLabelText('Tema')).toBeTruthy();
    // …and at least one help trigger (accessible name "Ajuda") sits beside a field.
    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThan(0);
  });

  it('hosts a Utilizadores sub-tab that lists users inline', async () => {
    const users = [
      {
        id: 'u1',
        username: 'amelia.marques',
        display_name: 'Amélia Marques',
        active: true,
        has_secret: true,
        has_attestation_key: false,
        has_recovery_phrase: false,
      },
    ];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/users')) return Promise.resolve(jsonResponse(users));
      if (url.includes('/v1/settings')) {
        if (method === 'PUT') return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
        return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      }
      if (url.includes('/v1/ledger/verify'))
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      if (url.includes('/health'))
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=utilizadores']);

    // The sub-tab button exists and the roster renders inline (the fictional example user).
    expect(await screen.findByRole('button', { name: 'Utilizadores' })).toBeTruthy();
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    // The inline "novo utilizador" action stays inside the settings users section.
    const novo = screen.getByRole('link', { name: /novo utilizador/i });
    expect(novo.getAttribute('href')).toBe('/configuracoes?sec=utilizadores&user=novo');
  });

  it('hosts privacy/compliance processor and DPIA registers with search and filters', async () => {
    const { fn } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    expect(await screen.findByRole('button', { name: 'Privacidade' })).toBeTruthy();
    expect(await screen.findByText('Cloud Processor')).toBeTruthy();
    expect(await screen.findByText('Marketing profiling')).toBeTruthy();

    const dpiaPanel = screen.getByText('DPIAs').closest('section');
    expect(dpiaPanel).toBeTruthy();
    fireEvent.change(within(dpiaPanel!).getByLabelText('Pesquisar'), {
      target: { value: 'marketing' },
    });
    expect(within(dpiaPanel!).getByText('Marketing profiling')).toBeTruthy();
    expect(await within(dpiaPanel!).findByText(/Sem submissão à autoridade/)).toBeTruthy();
    expect(await within(dpiaPanel!).findByText('Em revisão local')).toBeTruthy();

    fireEvent.change(within(dpiaPanel!).getByLabelText('Risco'), {
      target: { value: 'critical' },
    });
    expect(await within(dpiaPanel!).findByText('Sem resultados')).toBeTruthy();
  });

  it('renders the static DPIA guidance pack without echoing live register values', async () => {
    const sentinelProcessor = {
      ...PROCESSOR_ONE,
      name: 'SENTINEL_LIVE_PROCESSOR_NAME',
      legal_basis: 'SENTINEL_LIVE_PROCESSOR_LEGAL_BASIS',
      subprocessors: ['SENTINEL_LIVE_SUBPROCESSOR_NAME'],
    };
    const sentinelDpia = {
      ...DPIA_ONE,
      title: 'SENTINEL_LIVE_DPIA_TITLE',
      purpose: 'SENTINEL_LIVE_DPIA_PURPOSE',
      legal_basis: 'SENTINEL_LIVE_DPIA_LEGAL_BASIS',
      subprocessors: ['SENTINEL_LIVE_DPIA_SUBPROCESSOR'],
      evidence_receipts: [
        {
          ...DPIA_ONE.evidence_receipts[0],
          notes: 'SENTINEL_LIVE_DPIA_NOTE',
        },
      ],
    };
    const { fn, calls } = privacyFetch([sentinelProcessor], [sentinelDpia]);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Orientação');

    const panel = (await screen.findByText('Modelo DPIA local')).closest('section');
    expect(panel).toBeTruthy();
    expect(await within(panel!).findByText('privacy-dpia-guidance/v1')).toBeTruthy();
    expect(within(panel!).getByText('Processing description')).toBeTruthy();
    expect(within(panel!).getByText('Risk prompts')).toBeTruthy();
    expect(within(panel!).getByText(/authority_filing_completed:/)).toBeTruthy();
    expect(within(panel!).getByText(/automated_risk_scoring_performed:/)).toBeTruthy();
    expect(within(panel!).getByText(/register_mutation_performed:/)).toBeTruthy();
    expect(within(panel!).getByText(/external_call_performed:/)).toBeTruthy();

    for (const forbidden of [
      'SENTINEL_LIVE_PROCESSOR_NAME',
      'SENTINEL_LIVE_PROCESSOR_LEGAL_BASIS',
      'SENTINEL_LIVE_SUBPROCESSOR_NAME',
      'SENTINEL_LIVE_DPIA_TITLE',
      'SENTINEL_LIVE_DPIA_PURPOSE',
      'SENTINEL_LIVE_DPIA_LEGAL_BASIS',
      'SENTINEL_LIVE_DPIA_SUBPROCESSOR',
      'SENTINEL_LIVE_DPIA_NOTE',
      'password_hash',
      'api_key_secret',
    ]) {
      expect(within(panel!).queryByText(forbidden)).toBeNull();
    }

    await waitFor(() => {
      expect(calls.some((call) => call.url.endsWith('/v1/privacy/dpia-template'))).toBe(true);
    });
    const templateCalls = calls.filter((call) => call.url.endsWith('/v1/privacy/dpia-template'));
    expect(templateCalls.every((call) => call.method === 'GET')).toBe(true);
  });

  it('creates and patches DPIA local review receipts from the privacy settings tab', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    const dpiaPanel = (await screen.findByText('DPIAs')).closest('section');
    expect(dpiaPanel).toBeTruthy();
    expect(await within(dpiaPanel!).findByText('Marketing profiling')).toBeTruthy();
    expect(await within(dpiaPanel!).findByText(/Sem certificação de conformidade/)).toBeTruthy();
    fireEvent.click(within(dpiaPanel!).getByRole('button', { name: 'Novo registo' }));

    let formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    let form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Título da DPIA'), {
      target: { value: 'Biometric entry DPIA' },
    });
    fireEvent.change(within(form!).getByLabelText('Finalidade'), {
      target: { value: 'Entrada segura no edifício' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Interesse legítimo' },
    });
    fireEvent.change(within(form!).getByLabelText('Categorias de dados'), {
      target: { value: 'Identificação\nDados biométricos' },
    });
    fireEvent.change(within(form!).getByLabelText('Subprocessadores'), {
      target: { value: 'Access Processor SA' },
    });
    fireEvent.change(within(form!).getByLabelText('Tipo de evidência'), {
      target: { value: 'drill' },
    });
    fireEvent.change(within(form!).getByLabelText('Notas de evidência'), {
      target: { value: 'Operator DPIA drill receipt only.' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const post = await waitFor(() => {
      const call = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/dpias'));
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(post.body as string)).toMatchObject({
      title: 'Biometric entry DPIA',
      purpose: 'Entrada segura no edifício',
      legal_basis: 'Interesse legítimo',
      data_categories: ['Identificação', 'Dados biométricos'],
      subprocessors: ['Access Processor SA'],
      risk_level: 'medium',
      status: 'draft',
      evidence_receipt: {
        evidence_type: 'drill',
        notes: 'Operator DPIA drill receipt only.',
        authority_filing_completed: false,
        legal_review_accepted: false,
        legal_certification_completed: false,
        external_delivery_completed: false,
        dpia_completed: false,
        compliance_certification_completed: false,
      },
    });
    expect(await screen.findByText('Biometric entry DPIA')).toBeTruthy();

    fireEvent.click(within(dpiaPanel!).getAllByRole('button', { name: 'Editar' })[0]);
    formCard = await screen.findByRole('heading', { name: 'Editar registo' });
    form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Notas de evidência'), {
      target: { value: 'Follow-up local DPIA review only.' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Guardar alterações' }));

    const patch = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'PATCH' &&
          c.url.endsWith('/v1/privacy/dpias/dpia-1') &&
          c.body?.includes('Follow-up local DPIA review only.'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(patch.body as string)).toMatchObject({
      evidence_receipt: {
        evidence_type: 'review',
        notes: 'Follow-up local DPIA review only.',
        authority_filing_completed: false,
        legal_review_accepted: false,
        legal_certification_completed: false,
        external_delivery_completed: false,
        dpia_completed: false,
        compliance_certification_completed: false,
      },
    });
  });

  it('creates and patches GDPR processor records from the privacy settings tab', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    const processorPanel = (await screen.findByText('Processadores GDPR')).closest('section');
    expect(processorPanel).toBeTruthy();
    fireEvent.click(within(processorPanel!).getByRole('button', { name: 'Novo registo' }));

    const formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    const form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Nome do processador'), {
      target: { value: 'Payroll Processor' },
    });
    fireEvent.change(within(form!).getByLabelText('Finalidade'), {
      target: { value: 'Processamento salarial' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Contrato de trabalho' },
    });
    fireEvent.change(within(form!).getByLabelText('Categorias de dados'), {
      target: { value: 'Identificação\nRemuneração' },
    });
    fireEvent.change(within(form!).getByLabelText('Subprocessadores'), {
      target: { value: 'Payroll Backup SA' },
    });
    fireEvent.change(within(form!).getByLabelText('Risco'), { target: { value: 'high' } });
    fireEvent.change(within(form!).getByLabelText('Estado'), { target: { value: 'active' } });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const post = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/processors'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(post!.body as string)).toMatchObject({
      name: 'Payroll Processor',
      purpose: 'Processamento salarial',
      legal_basis: 'Contrato de trabalho',
      data_categories: ['Identificação', 'Remuneração'],
      subprocessors: ['Payroll Backup SA'],
      risk_level: 'high',
      status: 'active',
    });
    expect(await screen.findByText('Payroll Processor')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Estado de Payroll Processor'), {
      target: { value: 'under_review' },
    });

    const patch = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'PATCH' &&
          c.url.endsWith('/v1/privacy/processors/processor-2') &&
          c.body?.includes('under_review'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(patch!.body as string)).toEqual({ status: 'under_review' });
  });

  it('creates breach playbook and transfer-control records from the privacy settings tab', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    const breachPanel = (await screen.findByText('Playbooks de resposta a violações')).closest(
      'section',
    );
    expect(breachPanel).toBeTruthy();
    expect(await within(breachPanel!).findByText('Suspected account compromise')).toBeTruthy();
    expect(await within(breachPanel!).findByText(/Sem notificação à autoridade/)).toBeTruthy();
    expect(await within(breachPanel!).findByText('Revisão atual')).toBeTruthy();
    fireEvent.click(within(breachPanel!).getByRole('button', { name: 'Novo registo' }));

    let formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    let form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Título do playbook'), {
      target: { value: 'Suspected exfiltration' },
    });
    fireEvent.change(within(form!).getByLabelText('Âmbito'), {
      target: { value: 'document exports' },
    });
    fireEvent.change(within(form!).getByLabelText('Canais de deteção'), {
      target: { value: 'DLP alert\nSupport report' },
    });
    fireEvent.change(within(form!).getByLabelText('Passos de contenção'), {
      target: { value: 'Disable export\nPreserve evidence' },
    });
    fireEvent.change(within(form!).getByLabelText('Funções notificadas'), {
      target: { value: 'DPO' },
    });
    fireEvent.change(within(form!).getByLabelText('Notas de evidência'), {
      target: { value: 'Operator tabletop evidence only.' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const breachPost = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/breach-playbooks'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(breachPost.body as string)).toMatchObject({
      title: 'Suspected exfiltration',
      scope: 'document exports',
      detection_channels: ['DLP alert', 'Support report'],
      containment_steps: ['Disable export', 'Preserve evidence'],
      notification_roles: ['DPO'],
      risk_level: 'high',
      status: 'draft',
      evidence_receipt: {
        evidence_type: 'review',
        notes: 'Operator tabletop evidence only.',
        authority_notified: false,
        subjects_notified: false,
      },
    });
    expect(await screen.findByText('Suspected exfiltration')).toBeTruthy();

    const transferPanel = (await screen.findByText('Controlos de transferência')).closest(
      'section',
    );
    expect(transferPanel).toBeTruthy();
    expect(await within(transferPanel!).findByText('EU to UK support access')).toBeTruthy();
    expect(await within(transferPanel!).findByText(/Sem aprovação/)).toBeTruthy();
    expect(await within(transferPanel!).findByText('Revisão atual')).toBeTruthy();
    fireEvent.click(within(transferPanel!).getByRole('button', { name: 'Novo registo' }));

    formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Nome do controlo'), {
      target: { value: 'EU to US analytics export' },
    });
    fireEvent.change(within(form!).getByLabelText('Finalidade'), {
      target: { value: 'Product analytics' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Legitimate interest' },
    });
    fireEvent.change(within(form!).getByLabelText('Categorias de dados'), {
      target: { value: 'Usage metrics\nAccount metadata' },
    });
    fireEvent.change(within(form!).getByLabelText('Destinatário'), {
      target: { value: 'Analytics Inc' },
    });
    fireEvent.change(within(form!).getByLabelText('País de destino'), {
      target: { value: 'United States' },
    });
    fireEvent.change(within(form!).getByLabelText('Mecanismo de transferência'), {
      target: { value: 'SCCs' },
    });
    fireEvent.change(within(form!).getByLabelText('Salvaguardas'), {
      target: { value: 'Pseudonymisation\nAccess review' },
    });
    fireEvent.change(within(form!).getByLabelText('Notas de evidência'), {
      target: { value: 'Operator transfer-control review only.' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const transferPost = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/transfer-controls'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(transferPost.body as string)).toMatchObject({
      name: 'EU to US analytics export',
      purpose: 'Product analytics',
      legal_basis: 'Legitimate interest',
      data_categories: ['Usage metrics', 'Account metadata'],
      recipient: 'Analytics Inc',
      destination_country: 'United States',
      transfer_mechanism: 'SCCs',
      safeguards: ['Pseudonymisation', 'Access review'],
      risk_level: 'medium',
      status: 'draft',
      evidence_receipt: {
        notes: 'Operator transfer-control review only.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    });
    expect(await screen.findByText('EU to US analytics export')).toBeTruthy();
  });

  it('renders due retention candidates from the read-only GET scan', async () => {
    const { fn } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const legalHoldStatusPanel = (
      await screen.findByText('Estado local de legal hold e descarte')
    ).closest('section');
    expect(legalHoldStatusPanel).toBeTruthy();
    expect(within(legalHoldStatusPanel!).getByText(/Evidência operacional local/)).toBeTruthy();
    expect(
      within(legalHoldStatusPanel!).getByText(/não aprova descarte, não resolve candidatos/i),
    ).toBeTruthy();
    expect(
      within(legalHoldStatusPanel!).getByText(
        /destructive_disposal_completed:\s*false.*disposal_approved:\s*false.*legal_compliance_claimed:\s*false/,
      ),
    ).toBeTruthy();

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    expect(await within(candidatesPanel!).findByText('archive-doc-1')).toBeTruthy();
    expect(within(candidatesPanel!).getByText('Livro: book-archive-1')).toBeTruthy();
    expect(within(candidatesPanel!).getByText('Mensagens de suporte')).toBeTruthy();
    expect(within(candidatesPanel!).getByText('Vencimento: 2026-06-01')).toBeTruthy();
    expect(within(candidatesPanel!).getByText(/awaiting_manual_review/)).toBeTruthy();
    expect(within(candidatesPanel!).getByText(/retention_manual_review/)).toBeTruthy();
    expect(within(candidatesPanel!).getAllByText(/would_execute:\s*false/).length).toBeGreaterThan(
      0,
    );
    expect(
      within(candidatesPanel!).getAllByRole('button', { name: 'Registar disposição local' }).length,
    ).toBeGreaterThan(0);
  });

  it('records local evidence-only disposition for due retention candidates', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    const candidateRow = (await within(candidatesPanel!).findByText('archive-doc-1')).closest('tr');
    expect(candidateRow).toBeTruthy();

    fireEvent.click(
      within(candidateRow!).getByRole('button', { name: 'Registar disposição local' }),
    );

    const resolutionPost = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.endsWith('/v1/privacy/retention-due-candidates/retention-candidate-1/resolution'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(resolutionPost.body as string)).toEqual({
      candidate_fingerprint: '1'.repeat(64),
      disposition: 'evidence_acknowledged',
      note: 'Disposicao de evidencia local registada; sem alteracao dos registos fonte.',
      evidence: [
        {
          label: 'candidate_id',
          value: 'retention-candidate-1',
        },
        {
          label: 'record_id',
          value: 'archive-doc-1',
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
    });
    expect(
      await within(candidateRow!).findByText(
        /evidence_acknowledged · retention-candidate-resolution-1/,
      ),
    ).toBeTruthy();
    expect(within(candidateRow!).getByText('Disposição local existente')).toBeTruthy();
    expect(
      calls.some(
        (call) => call.method !== 'GET' && /\/(disposal|erasure|legal-hold)/.test(call.url),
      ),
    ).toBe(false);
    expect(calls.some((call) => call.method === 'DELETE')).toBe(false);
  });

  it('records blocked follow-up disposition for unsafe due retention candidates', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    const blockedRow = (await within(candidatesPanel!).findByText('archive-doc-blocked')).closest(
      'tr',
    );
    expect(blockedRow).toBeTruthy();

    fireEvent.click(within(blockedRow!).getByRole('button', { name: 'Registar disposição local' }));

    const resolutionPost = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.endsWith(
            '/v1/privacy/retention-due-candidates/retention-candidate-unsupported/resolution',
          ),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    const body = JSON.parse(resolutionPost.body as string);
    expect(body).toMatchObject({
      candidate_fingerprint: '2'.repeat(64),
      disposition: 'blocked_follow_up',
      note: 'Seguimento bloqueado registado para evidencia local; sem alteracao dos registos fonte.',
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
    });
    expect(body.disposition).not.toBe('evidence_acknowledged');
    expect(
      await within(blockedRow!).findByText(/blocked_follow_up · retention-candidate-resolution-1/),
    ).toBeTruthy();
  });

  it('shows already queued review state for a due retention candidate without posting again', async () => {
    const queuedReview = cloneJson(RETENTION_EXECUTION_AWAITING) as RetentionExecutionMetadata & {
      requested_policy: Record<string, unknown>;
      candidate: Record<string, unknown>;
      matched_records_summary: Record<string, unknown>;
      execution_result: Record<string, unknown>;
    };
    queuedReview.id = 'retention-exec-queued-due';
    queuedReview.requested_at = '2026-07-09T14:10:00Z';
    queuedReview.requested_policy = {
      ...((queuedReview.requested_policy as Record<string, unknown>) ?? {}),
      id: 'retention-1',
      found: true,
      name: 'Mensagens de suporte',
      scope: 'book_archive',
      category: 'documents',
      schedule_id: 'support-messages-v1',
      retention_period: 'P2Y',
      disposal_action: 'review',
      status: 'active',
      active: true,
      stale: false,
      matches_candidate: true,
      destructive_action: false,
    };
    queuedReview.candidate = {
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-1',
    };
    queuedReview.matched_records_summary = {
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-1',
      record_count: 1,
      policy_match_count: 1,
      destructive_policy_count: 0,
      policy_ids: ['retention-1'],
    };
    queuedReview.execution_result = {
      ...queuedReview.execution_result,
      targets_acted: [],
      destructive_disposal_completed: false,
      full_erasure_completed: false,
    };
    queuedReview.would_execute = false;

    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      [queuedReview],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    const candidateRow = (await within(candidatesPanel!).findByText('archive-doc-1')).closest('tr');
    expect(candidateRow).toBeTruthy();
    expect(within(candidateRow!).getByText('Revisão já na fila')).toBeTruthy();
    expect(
      within(candidateRow!).getByText(/awaiting_review · retention-exec-queued-due/),
    ).toBeTruthy();
    expect(within(candidateRow!).getByText(/Pedido em/)).toBeTruthy();
    expect(
      within(candidateRow!).queryByRole('button', { name: 'Pedir revisão de evidência' }),
    ).toBeNull();
    expect(
      calls.some(
        (call) =>
          call.method === 'POST' && call.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      ),
    ).toBe(false);
  });

  it('closes an open retention execution review from the queue without mutating due candidates', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    expect(await within(candidatesPanel!).findByText('archive-doc-1')).toBeTruthy();
    const dueCandidateGetsBefore = calls.filter(
      (call) => call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
    ).length;

    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    const reviewRow = (await within(executionQueue!).findByText('ticket-456')).closest('tr');
    expect(reviewRow).toBeTruthy();
    fireEvent.click(
      within(reviewRow!).getByRole('button', { name: 'Registar revisão operacional' }),
    );

    const closurePost = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.endsWith('/v1/privacy/retention-executions/retention-exec-awaiting/review-closure'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(closurePost.body as string)).toEqual({
      review_closure_decision: 'review_evidence_acknowledged',
      review_closure_note:
        'Revisão operacional registada para evidência retida; esta ação não altera registos fonte.',
      review_closure_evidence: [
        {
          label: 'fila_operacional',
          value: 'registo revisto na interface de configuracoes',
        },
        {
          label: 'alvo',
          value: 'ticket-456',
        },
      ],
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      legal_hold_mutated: false,
      retention_policy_mutated: false,
    });

    expect(
      await within(executionQueue!).findByText(
        /Revisão operacional registada por amelia\.marques em/,
      ),
    ).toBeTruthy();
    expect(
      within(executionQueue!).getByText(
        'Revisão operacional registada para evidência retida; esta ação não altera registos fonte.',
      ),
    ).toBeTruthy();
    expect(
      within(executionQueue!).getByText(
        'fila_operacional: registo revisto na interface de configuracoes',
      ),
    ).toBeTruthy();
    expect(within(executionQueue!).getByText('alvo: ticket-456')).toBeTruthy();
    expect(
      within(reviewRow!).queryByRole('button', { name: 'Registar revisão operacional' }),
    ).toBeNull();

    fireEvent.change(within(executionQueue!).getByLabelText('Pesquisar'), {
      target: { value: 'interface de configuracoes' },
    });
    expect(await within(executionQueue!).findByText('ticket-456')).toBeTruthy();
    expect(within(executionQueue!).queryByText('ticket-123')).toBeNull();

    expect(await within(candidatesPanel!).findByText('archive-doc-1')).toBeTruthy();
    expect(
      calls.filter(
        (call) =>
          call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
      ).length,
    ).toBe(dueCandidateGetsBefore);
    expect(
      calls.some(
        (call) =>
          call.method === 'POST' && call.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      ),
    ).toBe(false);
    expect(
      calls.some(
        (call) =>
          ['POST', 'PATCH', 'DELETE'].includes(call.method) &&
          call.url.includes('/v1/privacy/retention-policies'),
      ),
    ).toBe(false);
    expect(
      calls.some(
        (call) => call.method !== 'GET' && /\/(disposal|erasure|legal-hold)/.test(call.url),
      ),
    ).toBe(false);
    expect(calls.some((call) => call.method === 'DELETE')).toBe(false);
  });

  it('maps retention execution review closure decisions from outcome categories', async () => {
    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      [RETENTION_EXECUTION_BLOCKED, RETENTION_EXECUTION_EXECUTED],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();

    const blockedRow = (await within(executionQueue!).findByText('ticket-123')).closest('tr');
    expect(blockedRow).toBeTruthy();
    fireEvent.click(
      within(blockedRow!).getByRole('button', { name: 'Registar revisão operacional' }),
    );
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === 'POST' &&
            c.url.endsWith('/retention-exec-blocked/review-closure') &&
            Boolean(c.body?.includes('"blocked_evidence_acknowledged"')),
        ),
      ).toBe(true),
    );
    expect(
      await within(blockedRow!).findByText(/Revisão operacional registada por amelia\.marques em/),
    ).toBeTruthy();

    const boundedRow = (await within(executionQueue!).findByText('ticket-789')).closest('tr');
    expect(boundedRow).toBeTruthy();
    fireEvent.click(
      within(boundedRow!).getByRole('button', { name: 'Registar revisão operacional' }),
    );
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.method === 'POST' &&
            c.url.endsWith('/retention-exec-executed/review-closure') &&
            Boolean(c.body?.includes('"bounded_evidence_acknowledged"')),
        ),
      ).toBe(true),
    );

    const closureBodies = calls
      .filter((call) => call.method === 'POST' && call.url.endsWith('/review-closure'))
      .map((call) => JSON.parse(call.body as string));
    expect(closureBodies).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          review_closure_decision: 'blocked_evidence_acknowledged',
          destructive_disposal_completed: false,
          full_erasure_completed: false,
          legal_hold_mutated: false,
          retention_policy_mutated: false,
        }),
        expect.objectContaining({
          review_closure_decision: 'bounded_evidence_acknowledged',
          destructive_disposal_completed: false,
          full_erasure_completed: false,
          legal_hold_mutated: false,
          retention_policy_mutated: false,
        }),
      ]),
    );
  });

  it('does not show the retention review closure action for already closed records', async () => {
    const closedRecord = closedRetentionReviewRecord({
      id: 'retention-exec-closed-ui',
      candidate: { scope: 'support', category: 'messages', record_id: 'ticket-closed' },
    });
    const { fn } = privacyFetch(undefined, undefined, undefined, undefined, undefined, undefined, [
      closedRecord,
    ]);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    const closedRow = (await within(executionQueue!).findByText('ticket-closed')).closest('tr');
    expect(closedRow).toBeTruthy();
    expect(
      within(closedRow!).queryByRole('button', { name: 'Registar revisão operacional' }),
    ).toBeNull();
    expect(
      within(closedRow!).getByText(/Revisão operacional registada por privacy-manager em/),
    ).toBeTruthy();
    expect(
      within(closedRow!).getByText(
        'Revisão operacional registada para evidência retida; esta ação não altera registos fonte.',
      ),
    ).toBeTruthy();
    expect(
      within(closedRow!).getByText(
        'fila_operacional: registo revisto na interface de configuracoes',
      ),
    ).toBeTruthy();
  });

  it('suppresses projected bounded execution rows and leaves execution history visible', async () => {
    const priorArchiveNextStep =
      'Prior bounded archive evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.';
    const report = retentionDueReportWith([], {
      suppressed_candidate_count: 1,
      suppressed_by_bounded_evidence_count: 1,
      suppression_summary: retentionSuppressionSummary(1),
    });
    const projectedExecution = retentionExecutedEvidenceRecord(
      'archive-doc-1',
      'bounded_archive_recorded',
      {
        id: 'retention-exec-projected-archive',
        evidence_next_step: priorArchiveNextStep,
        workflow: {
          status: 'awaiting_manual_review',
          blockers: [],
          required_approvals: [],
          next_step: priorArchiveNextStep,
        },
      },
    );

    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      report,
      [projectedExecution],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    expect(
      await within(candidatesPanel!).findByText(
        /0 candidato\(s\) ativo\(s\) · 1 suprimido\(s\) por evidência delimitada/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Candidatos suprimidos por evidência delimitada não são listados/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Due candidates with prior safe bounded archive\/no-action evidence/,
      ),
    ).toBeTruthy();
    expect(within(candidatesPanel!).queryByText('archive-doc-1')).toBeNull();
    expect(
      within(candidatesPanel!).queryByRole('button', { name: 'Registar evidência de arquivo' }),
    ).toBeNull();
    expect(
      within(candidatesPanel!).queryByRole('button', { name: 'Pedir revisão de evidência' }),
    ).toBeNull();
    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(await within(executionQueue!).findByText('archive-doc-1')).toBeTruthy();
    expect(within(executionQueue!).getAllByText('bounded_archive_recorded').length).toBeGreaterThan(
      0,
    );
    expect(
      within(executionQueue!).getAllByText(/destructive_disposal_completed:\s*false/).length,
    ).toBeGreaterThan(0);
    expect(
      within(executionQueue!).getAllByText(/full_erasure_completed:\s*false/).length,
    ).toBeGreaterThan(0);
    expect(
      calls.some(
        (call) =>
          call.method === 'POST' && call.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      ),
    ).toBe(false);
  });

  it('records bounded archive evidence from an eligible due retention candidate row', async () => {
    const archivePolicy = retentionArchivePolicy();
    const report = retentionDueReportWith([retentionArchiveCandidate()]);
    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      [archivePolicy],
      report,
      [],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    const candidateRow = (await within(candidatesPanel!).findByText('archive-doc-archive')).closest(
      'tr',
    );
    expect(candidateRow).toBeTruthy();
    expect(
      within(candidateRow!).getByRole('button', { name: 'Registar evidência de arquivo' }),
    ).toBeTruthy();
    expect(
      within(candidateRow!).queryByRole('button', { name: 'Pedir revisão de evidência' }),
    ).toBeNull();
    expect(
      within(candidateRow!).queryByText(/GDPR erasure|legal erasure|full erasure/i),
    ).toBeNull();

    const initialDueCandidateGets = calls.filter(
      (call) => call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
    ).length;
    const initialExecutionGets = calls.filter(
      (call) => call.method === 'GET' && call.url.includes('/v1/privacy/retention-executions'),
    ).length;

    fireEvent.click(
      within(candidateRow!).getByRole('button', { name: 'Registar evidência de arquivo' }),
    );

    const supportedRequest = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.endsWith('/v1/privacy/retention-policies/dry-run') &&
          Boolean(c.body?.includes('execute_supported')),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(supportedRequest.body as string)).toEqual({
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-archive',
      execution_request: {
        requested_policy_id: 'retention-archive',
        execution_mode: 'execute_supported',
      },
    });

    await waitFor(() =>
      expect(
        calls.filter(
          (call) =>
            call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
        ).length,
      ).toBeGreaterThan(initialDueCandidateGets),
    );
    await waitFor(() =>
      expect(
        calls.filter(
          (call) => call.method === 'GET' && call.url.includes('/v1/privacy/retention-executions'),
        ).length,
      ).toBeGreaterThan(initialExecutionGets),
    );
    expect(
      await within(candidatesPanel!).findByText(
        /0 candidato\(s\) ativo\(s\) · 1 suprimido\(s\) por evidência delimitada/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Candidatos suprimidos por evidência delimitada não são listados/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Due candidates with prior safe bounded archive\/no-action evidence/,
      ),
    ).toBeTruthy();
    await waitFor(() =>
      expect(within(candidatesPanel!).queryByText('archive-doc-archive')).toBeNull(),
    );
    expect(
      within(candidatesPanel!).queryByRole('button', { name: 'Registar evidência de arquivo' }),
    ).toBeNull();
    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(await within(executionQueue!).findByText('archive-doc-archive')).toBeTruthy();
    expect(within(executionQueue!).getAllByText('bounded_archive_recorded').length).toBeGreaterThan(
      0,
    );
    expect(
      calls.some(
        (call) => call.method === 'POST' && call.url.includes('/v1/privacy/retention-executions'),
      ),
    ).toBe(false);
    expect(
      calls.some((call) => call.method !== 'GET' && /disposal|erasure|legal-hold/.test(call.url)),
    ).toBe(false);
    expect(
      calls.every(
        (call) =>
          !call.body?.includes('"delete"') &&
          !call.body?.includes('"anonymize"') &&
          !call.body?.includes('destructive_disposal_completed') &&
          !call.body?.includes('full_erasure_completed') &&
          !call.body?.includes('legal_hold'),
      ),
    ).toBe(true);
  });

  it('keeps bounded archive evidence unavailable for unsafe due retention candidates', async () => {
    const priorArchiveNextStep =
      'Prior bounded archive evidence is available for review; do not create duplicate evidence.';
    const candidates = [
      retentionArchiveCandidate({
        candidate_id: 'retention-candidate-archive-empty-record',
        record_id: '',
        book_id: 'book-empty-record',
      }),
      retentionArchiveCandidate({
        candidate_id: 'retention-candidate-archive-destructive',
        record_id: 'archive-doc-archive-destructive',
        destructive_action: true,
      }),
      retentionArchiveCandidate({
        candidate_id: 'retention-candidate-archive-blocker',
        record_id: 'archive-doc-archive-blocker',
        blockers: [{ code: 'unsupported_retention_period', message: 'Unsupported period.' }],
      }),
      retentionArchiveCandidate({
        candidate_id: 'retention-candidate-archive-legal-hold',
        record_id: 'archive-doc-archive-legal-hold',
        legal_hold_blockers: [{ policy_id: 'hold-1', name: 'Hold', reason: 'Active hold.' }],
      }),
      retentionArchiveCandidate({
        candidate_id: 'retention-candidate-archive-queued',
        record_id: 'archive-doc-archive-queued-review',
      }),
      retentionArchiveCandidate({
        candidate_id: 'retention-candidate-archive-state-blocked',
        record_id: 'archive-doc-archive-state-blocked',
        candidate_evidence_state: 'blocked',
        evidence_next_step: 'Resolve evidence blocker before recording archive evidence.',
      }),
    ];
    const suppressedRecordIds = [
      'archive-doc-archive-prior-execution',
      'archive-doc-archive-recorded',
      'archive-doc-archive-no-action-recorded',
      'archive-doc-archive-prior-projected',
    ];
    const priorArchiveExecution = retentionExecutedEvidenceRecord(
      'archive-doc-archive-prior-execution',
      'bounded_archive_recorded',
      {
        id: 'retention-exec-prior-archive',
        evidence_next_step: priorArchiveNextStep,
        workflow: {
          status: 'awaiting_manual_review',
          blockers: [],
          required_approvals: [],
          next_step: priorArchiveNextStep,
        },
      },
    );
    const queuedReview = cloneJson(RETENTION_EXECUTION_AWAITING) as RetentionExecutionMetadata & {
      requested_policy: Record<string, unknown>;
      candidate: Record<string, unknown>;
      matched_records_summary: Record<string, unknown>;
    };
    queuedReview.id = 'retention-exec-queued-archive';
    queuedReview.execution_intent = 'review_only';
    queuedReview.execution_status = 'awaiting_review';
    queuedReview.requested_policy = {
      ...queuedReview.requested_policy,
      id: 'retention-archive',
      scope: 'book_archive',
      category: 'documents',
      disposal_action: 'archive',
      destructive_action: false,
    };
    queuedReview.candidate = {
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-archive-queued-review',
    };
    queuedReview.matched_records_summary = {
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-archive-queued-review',
      record_count: 1,
      policy_match_count: 1,
      destructive_policy_count: 0,
      policy_ids: ['retention-archive'],
    };

    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      [retentionArchivePolicy()],
      retentionDueReportWith(candidates, {
        suppressed_candidate_count: suppressedRecordIds.length,
        suppressed_by_bounded_evidence_count: suppressedRecordIds.length,
        suppression_summary: retentionSuppressionSummary(suppressedRecordIds.length),
      }),
      [queuedReview, priorArchiveExecution],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    expect(
      within(candidatesPanel!).queryByRole('button', { name: 'Registar evidência de arquivo' }),
    ).toBeNull();
    expect(
      await within(candidatesPanel!).findByText(
        /6 candidato\(s\) ativo\(s\) · 4 suprimido\(s\) por evidência delimitada/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Candidatos suprimidos por evidência delimitada não são listados/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Due candidates with prior safe bounded archive\/no-action evidence/,
      ),
    ).toBeTruthy();

    const missingRecordRow = (
      await within(candidatesPanel!).findByText('Livro: book-empty-record')
    ).closest('tr');
    expect(missingRecordRow).toBeTruthy();
    expect(
      within(missingRecordRow!).queryByRole('button', { name: 'Registar evidência de arquivo' }),
    ).toBeNull();

    for (const recordId of [
      'archive-doc-archive-destructive',
      'archive-doc-archive-blocker',
      'archive-doc-archive-legal-hold',
      'archive-doc-archive-queued-review',
      'archive-doc-archive-state-blocked',
    ]) {
      const candidateRow = (await within(candidatesPanel!).findByText(recordId)).closest('tr');
      expect(candidateRow).toBeTruthy();
      expect(
        within(candidateRow!).queryByRole('button', { name: 'Registar evidência de arquivo' }),
      ).toBeNull();
    }
    for (const recordId of suppressedRecordIds) {
      expect(within(candidatesPanel!).queryByText(recordId)).toBeNull();
    }

    const queuedRow = (
      await within(candidatesPanel!).findByText('archive-doc-archive-queued-review')
    ).closest('tr');
    expect(queuedRow).toBeTruthy();
    expect(within(queuedRow!).getByText('Revisão já na fila')).toBeTruthy();
    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(
      await within(executionQueue!).findByText('archive-doc-archive-prior-execution'),
    ).toBeTruthy();
    expect(within(executionQueue!).getAllByText('bounded_archive_recorded').length).toBeGreaterThan(
      0,
    );
    expect(
      within(executionQueue!).getAllByText(/destructive_disposal_completed:\s*false/).length,
    ).toBeGreaterThan(0);
    expect(
      calls.some(
        (call) =>
          call.method === 'POST' &&
          call.url.endsWith('/v1/privacy/retention-policies/dry-run') &&
          Boolean(call.body?.includes('execute_supported')),
      ),
    ).toBe(false);
  });

  it('records bounded no-action evidence from an eligible due retention candidate row', async () => {
    const noActionPolicy = retentionNoActionPolicy();
    const report = retentionDueReportWith([retentionNoActionCandidate()]);
    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      [noActionPolicy],
      report,
      [],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    const candidateRow = (
      await within(candidatesPanel!).findByText('archive-doc-no-action')
    ).closest('tr');
    expect(candidateRow).toBeTruthy();
    expect(
      within(candidateRow!).getByRole('button', { name: 'Registar evidência sem ação' }),
    ).toBeTruthy();
    expect(
      within(candidateRow!).queryByRole('button', { name: 'Pedir revisão de evidência' }),
    ).toBeNull();
    expect(
      within(candidateRow!).queryByText(/GDPR erasure|legal erasure|full erasure/i),
    ).toBeNull();

    const initialDueCandidateGets = calls.filter(
      (call) => call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
    ).length;
    const initialExecutionGets = calls.filter(
      (call) => call.method === 'GET' && call.url.includes('/v1/privacy/retention-executions'),
    ).length;

    fireEvent.click(
      within(candidateRow!).getByRole('button', { name: 'Registar evidência sem ação' }),
    );

    const supportedRequest = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.endsWith('/v1/privacy/retention-policies/dry-run') &&
          Boolean(c.body?.includes('execute_supported')),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(supportedRequest.body as string)).toEqual({
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-no-action',
      execution_request: {
        requested_policy_id: 'retention-no-action',
        execution_mode: 'execute_supported',
      },
    });

    await waitFor(() =>
      expect(
        calls.filter(
          (call) =>
            call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
        ).length,
      ).toBeGreaterThan(initialDueCandidateGets),
    );
    await waitFor(() =>
      expect(
        calls.filter(
          (call) => call.method === 'GET' && call.url.includes('/v1/privacy/retention-executions'),
        ).length,
      ).toBeGreaterThan(initialExecutionGets),
    );
    expect(
      await within(candidatesPanel!).findByText(
        /0 candidato\(s\) ativo\(s\) · 1 suprimido\(s\) por evidência delimitada/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Candidatos suprimidos por evidência delimitada não são listados/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Due candidates with prior safe bounded archive\/no-action evidence/,
      ),
    ).toBeTruthy();
    await waitFor(() =>
      expect(within(candidatesPanel!).queryByText('archive-doc-no-action')).toBeNull(),
    );
    expect(
      within(candidatesPanel!).queryByRole('button', { name: 'Registar evidência sem ação' }),
    ).toBeNull();
    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(await within(executionQueue!).findByText('archive-doc-no-action')).toBeTruthy();
    expect(
      within(executionQueue!).getAllByText('bounded_no_action_recorded').length,
    ).toBeGreaterThan(0);
    expect(
      calls.some(
        (call) => call.method === 'POST' && call.url.includes('/v1/privacy/retention-executions'),
      ),
    ).toBe(false);
    expect(
      calls.some((call) => call.method !== 'GET' && /disposal|erasure|legal-hold/.test(call.url)),
    ).toBe(false);
    expect(
      calls.every(
        (call) =>
          !call.body?.includes('"delete"') &&
          !call.body?.includes('"anonymize"') &&
          !call.body?.includes('destructive_disposal_completed') &&
          !call.body?.includes('full_erasure_completed') &&
          !call.body?.includes('legal_hold'),
      ),
    ).toBe(true);
  });

  it('keeps bounded no-action evidence unavailable for ineligible due retention candidates', async () => {
    const candidates = [
      retentionNoActionCandidate({
        candidate_id: 'retention-candidate-delete',
        record_id: 'archive-doc-action-delete',
        disposal_action: 'delete',
        destructive_action: true,
      }),
      retentionNoActionCandidate({
        candidate_id: 'retention-candidate-anonymize',
        record_id: 'archive-doc-action-anonymize',
        disposal_action: 'anonymize',
        destructive_action: true,
      }),
      retentionNoActionCandidate({
        candidate_id: 'retention-candidate-blocked',
        record_id: 'archive-doc-blocker',
        blockers: [{ code: 'unsupported_retention_period', message: 'Unsupported period.' }],
      }),
      retentionNoActionCandidate({
        candidate_id: 'retention-candidate-legal-hold',
        record_id: 'archive-doc-legal-hold',
        legal_hold_blockers: [{ policy_id: 'hold-1', name: 'Hold', reason: 'Active hold.' }],
      }),
      retentionNoActionCandidate({
        candidate_id: 'retention-candidate-queued',
        record_id: 'archive-doc-queued-review',
      }),
    ];
    const suppressedRecordIds = ['archive-doc-prior-execution'];
    const priorNoActionExecution = retentionExecutedEvidenceRecord(
      'archive-doc-prior-execution',
      'bounded_no_action_recorded',
      { id: 'retention-exec-prior-no-action' },
    );
    const queuedReview = cloneJson(RETENTION_EXECUTION_AWAITING) as RetentionExecutionMetadata & {
      requested_policy: Record<string, unknown>;
      candidate: Record<string, unknown>;
      matched_records_summary: Record<string, unknown>;
    };
    queuedReview.id = 'retention-exec-queued-no-action';
    queuedReview.execution_intent = 'review_only';
    queuedReview.execution_status = 'awaiting_review';
    queuedReview.requested_policy = {
      ...queuedReview.requested_policy,
      id: 'retention-no-action',
      scope: 'book_archive',
      category: 'documents',
      disposal_action: 'no_action',
      destructive_action: false,
    };
    queuedReview.candidate = {
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-queued-review',
    };
    queuedReview.matched_records_summary = {
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-queued-review',
      record_count: 1,
      policy_match_count: 1,
      destructive_policy_count: 0,
      policy_ids: ['retention-no-action'],
    };

    const { fn, calls } = privacyFetch(
      undefined,
      undefined,
      undefined,
      undefined,
      [retentionNoActionPolicy()],
      retentionDueReportWith(candidates, {
        suppressed_candidate_count: suppressedRecordIds.length,
        suppressed_by_bounded_evidence_count: suppressedRecordIds.length,
        suppression_summary: retentionSuppressionSummary(suppressedRecordIds.length),
      }),
      [queuedReview, priorNoActionExecution],
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    expect(
      await within(candidatesPanel!).findByText(
        /5 candidato\(s\) ativo\(s\) · 1 suprimido\(s\) por evidência delimitada/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Candidatos suprimidos por evidência delimitada não são listados/,
      ),
    ).toBeTruthy();
    expect(
      within(candidatesPanel!).getByText(
        /Due candidates with prior safe bounded archive\/no-action evidence/,
      ),
    ).toBeTruthy();
    for (const candidate of candidates) {
      const candidateRow = (
        await within(candidatesPanel!).findByText(candidate.record_id as string)
      ).closest('tr');
      expect(candidateRow).toBeTruthy();
      expect(
        within(candidateRow!).queryByRole('button', { name: 'Registar evidência sem ação' }),
      ).toBeNull();
    }
    for (const recordId of [
      'archive-doc-action-delete',
      'archive-doc-action-anonymize',
      'archive-doc-blocker',
      'archive-doc-legal-hold',
    ]) {
      const candidateRow = (await within(candidatesPanel!).findByText(recordId)).closest('tr');
      expect(candidateRow).toBeTruthy();
      expect(
        within(candidateRow!).getByRole('button', { name: 'Pedir revisão de evidência' }),
      ).toBeTruthy();
    }
    const queuedRow = (
      await within(candidatesPanel!).findByText('archive-doc-queued-review')
    ).closest('tr');
    expect(queuedRow).toBeTruthy();
    expect(within(queuedRow!).getByText('Revisão já na fila')).toBeTruthy();
    for (const recordId of suppressedRecordIds) {
      expect(within(candidatesPanel!).queryByText(recordId)).toBeNull();
    }
    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(await within(executionQueue!).findByText('archive-doc-prior-execution')).toBeTruthy();
    expect(
      within(executionQueue!).getAllByText('bounded_no_action_recorded').length,
    ).toBeGreaterThan(0);
    expect(
      within(executionQueue!).getAllByText(/destructive_disposal_completed:\s*false/).length,
    ).toBeGreaterThan(0);
    expect(
      calls.some(
        (call) =>
          call.method === 'POST' &&
          call.url.endsWith('/v1/privacy/retention-policies/dry-run') &&
          Boolean(call.body?.includes('execute_supported')),
      ),
    ).toBe(false);
  });

  it('records a review-only request from a due retention candidate row', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    const candidateRow = (await within(candidatesPanel!).findByText('archive-doc-1')).closest('tr');
    expect(candidateRow).toBeTruthy();
    expect(
      within(candidateRow!).getByRole('button', { name: 'Pedir revisão de evidência' }),
    ).toBeTruthy();

    const initialDueCandidateGets = calls.filter(
      (call) => call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
    ).length;
    const initialExecutionGets = calls.filter(
      (call) => call.method === 'GET' && call.url.includes('/v1/privacy/retention-executions'),
    ).length;

    fireEvent.click(
      within(candidateRow!).getByRole('button', { name: 'Pedir revisão de evidência' }),
    );

    const reviewRequest = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.endsWith('/v1/privacy/retention-policies/dry-run') &&
          Boolean(c.body?.includes('execution_request')),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(reviewRequest.body as string)).toEqual({
      scope: 'book_archive',
      category: 'documents',
      record_id: 'archive-doc-1',
      execution_request: {
        requested_policy_id: 'retention-1',
        execution_mode: 'review_only',
      },
    });

    await waitFor(() =>
      expect(
        calls.filter(
          (call) =>
            call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
        ).length,
      ).toBeGreaterThan(initialDueCandidateGets),
    );
    await waitFor(() =>
      expect(
        calls.filter(
          (call) => call.method === 'GET' && call.url.includes('/v1/privacy/retention-executions'),
        ).length,
      ).toBeGreaterThan(initialExecutionGets),
    );
    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(await within(executionQueue!).findByText('archive-doc-1')).toBeTruthy();
    expect(
      calls.some(
        (call) => call.method === 'POST' && call.url.includes('/v1/privacy/retention-executions'),
      ),
    ).toBe(false);
    expect(
      calls.some(
        (call) =>
          ['POST', 'PATCH', 'DELETE'].includes(call.method) &&
          call.url.includes('/v1/privacy/retention-policies') &&
          !call.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      ),
    ).toBe(false);
    expect(
      calls.some((call) => call.method !== 'GET' && /disposal|erasure|legal-hold/.test(call.url)),
    ).toBe(false);
    expect(
      calls.every(
        (call) =>
          !call.body?.includes('execute_supported') &&
          !call.body?.includes('"execute"') &&
          !call.body?.includes('"delete"') &&
          !call.body?.includes('"anonymize"'),
      ),
    ).toBe(true);
  });

  it('loads retention due candidates without posting execution, disposal, or erasure requests', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    await screen.findByText('Candidatos de retenção vencidos');
    cleanup();
    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');
    await screen.findByText('Candidatos de retenção vencidos');

    await waitFor(() =>
      expect(
        calls.filter(
          (call) =>
            call.method === 'GET' && call.url.endsWith('/v1/privacy/retention-due-candidates'),
        ).length,
      ).toBeGreaterThanOrEqual(2),
    );
    expect(
      calls.some(
        (call) =>
          call.method === 'POST' &&
          (call.url.includes('/v1/privacy/retention-executions') ||
            call.url.includes('/disposal') ||
            call.url.includes('/erasure') ||
            call.url.includes('/retention-policies/dry-run')),
      ),
    ).toBe(false);
  });

  it('shows unsupported-period blocked due candidates without a destructive completion claim', async () => {
    const { fn } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const candidatesPanel = (await screen.findByText('Candidatos de retenção vencidos')).closest(
      'section',
    );
    expect(candidatesPanel).toBeTruthy();
    expect(await within(candidatesPanel!).findByText('archive-doc-blocked')).toBeTruthy();
    expect(within(candidatesPanel!).getByText('Unsupported archival period')).toBeTruthy();
    expect(
      within(candidatesPanel!).getAllByText(/unsupported_retention_period/).length,
    ).toBeGreaterThan(0);
    expect(
      within(candidatesPanel!).getAllByText(/Retention period PXBROKEN is not supported/).length,
    ).toBeGreaterThan(0);
    expect(within(candidatesPanel!).getByText(/Board preservation hold/)).toBeTruthy();
    expect(within(candidatesPanel!).getByText(/unsupported_period_review/)).toBeTruthy();
    expect(
      within(candidatesPanel!).queryByText(/destructive_disposal_completed:\s*true/),
    ).toBeNull();
    expect(
      within(candidatesPanel!).getAllByText(/destructive_disposal_completed:\s*false/).length,
    ).toBeGreaterThan(0);
    expect(
      within(candidatesPanel!).getAllByText(/full_erasure_completed:\s*false/).length,
    ).toBeGreaterThan(0);
  });

  it('lists, creates, patches, and dry-runs retention policies without destructive execution', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);
    await openPrivacySubTab('Retenção');

    const retentionPanel = (await screen.findByText('Políticas de retenção')).closest('section');
    expect(retentionPanel).toBeTruthy();
    expect(await within(retentionPanel!).findByText('Mensagens de suporte')).toBeTruthy();
    expect(
      within(retentionPanel!).getByText('destructive_execution_supported: false'),
    ).toBeTruthy();

    const executionQueue = (await screen.findByText('Fila de revisão de execução')).closest(
      'section',
    );
    expect(executionQueue).toBeTruthy();
    expect(await within(executionQueue!).findByText('ticket-123')).toBeTruthy();
    expect(within(executionQueue!).getByText('destructive_action_disabled')).toBeTruthy();
    expect(within(executionQueue!).getAllByText('retention_manual_review').length).toBeGreaterThan(
      0,
    );
    expect(
      within(executionQueue!).getAllByText(/destructive_disposal_completed:\s*false/).length,
    ).toBeGreaterThan(0);
    fireEvent.change(within(executionQueue!).getByLabelText('Estado da execução'), {
      target: { value: 'executed' },
    });
    await waitFor(() =>
      expect(
        calls.some((c) => c.url.endsWith('/v1/privacy/retention-executions?status=executed')),
      ).toBe(true),
    );
    expect(await within(executionQueue!).findByText('ticket-789')).toBeTruthy();
    expect(within(executionQueue!).getByText('privacy-board-42')).toBeTruthy();
    await waitFor(() => expect(within(executionQueue!).queryByText('ticket-123')).toBeNull());

    fireEvent.click(within(retentionPanel!).getByRole('button', { name: 'Novo registo' }));

    let formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    let form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Nome da política'), {
      target: { value: 'Registos de auditoria' },
    });
    fireEvent.change(within(form!).getByLabelText('Âmbito'), {
      target: { value: 'audit' },
    });
    fireEvent.change(within(form!).getByLabelText('Categoria'), {
      target: { value: 'events' },
    });
    fireEvent.change(within(form!).getByLabelText('Identificador do calendário'), {
      target: { value: 'audit-events-v1' },
    });
    fireEvent.change(within(form!).getByLabelText('Período de retenção'), {
      target: { value: 'P10Y' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Obrigação legal' },
    });
    fireEvent.change(within(form!).getByLabelText('Ação prevista'), {
      target: { value: 'archive' },
    });
    fireEvent.change(within(form!).getByLabelText('Estado'), {
      target: { value: 'active' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const retentionPost = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/retention-policies'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(retentionPost.body as string)).toMatchObject({
      name: 'Registos de auditoria',
      scope: 'audit',
      category: 'events',
      schedule_id: 'audit-events-v1',
      retention_period: 'P10Y',
      legal_basis: 'Obrigação legal',
      disposal_action: 'archive',
      status: 'active',
      active: true,
    });
    expect(await screen.findByText('Registos de auditoria')).toBeTruthy();

    const updatedPanel = screen.getByText('Políticas de retenção').closest('section');
    expect(updatedPanel).toBeTruthy();
    fireEvent.click(within(updatedPanel!).getAllByRole('button', { name: 'Editar' }).at(-1)!);

    formCard = await screen.findByRole('heading', { name: 'Editar registo' });
    form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Estado'), {
      target: { value: 'suspended' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Guardar alterações' }));

    const retentionPatch = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'PATCH' &&
          c.url.endsWith('/v1/privacy/retention-policies/retention-2') &&
          c.body?.includes('suspended'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(retentionPatch.body as string)).toMatchObject({
      status: 'suspended',
      disposal_action: 'archive',
    });

    const dryRunPanel = (await screen.findByText('Simulação de retenção')).closest('section');
    expect(dryRunPanel).toBeTruthy();
    fireEvent.change(within(dryRunPanel!).getByLabelText('Âmbito'), {
      target: { value: 'support' },
    });
    fireEvent.change(within(dryRunPanel!).getByLabelText('Categoria'), {
      target: { value: 'messages' },
    });
    fireEvent.change(within(dryRunPanel!).getByLabelText('ID do registo'), {
      target: { value: 'ticket-123' },
    });
    fireEvent.click(within(dryRunPanel!).getByRole('button', { name: 'Simular retenção' }));

    const dryRun = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(dryRun.body as string)).toEqual({
      scope: 'support',
      category: 'messages',
      record_id: 'ticket-123',
    });
    expect(await within(dryRunPanel!).findByText(/destructive_execution_supported:/)).toBeTruthy();
    expect(await within(dryRunPanel!).findByText(/would_execute: false/)).toBeTruthy();
    const retentionCalls = calls.filter((call) =>
      call.url.includes('/v1/privacy/retention-policies'),
    );
    expect(
      retentionCalls.every(
        (call) =>
          call.url.endsWith('/v1/privacy/retention-policies') ||
          call.url.endsWith('/v1/privacy/retention-policies/retention-2') ||
          call.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      ),
    ).toBe(true);
    expect(
      calls.some(
        (call) =>
          /execute|delete|anonymize/.test(call.url) &&
          !call.url.includes('dry-run') &&
          !call.url.includes('/v1/privacy/retention-executions'),
      ),
    ).toBe(false);
    expect(
      calls.every(
        (call) =>
          !call.body?.includes('execution_request') &&
          !call.body?.includes('execute_supported') &&
          !call.body?.includes('"execute"') &&
          !call.body?.includes('"delete"') &&
          !call.body?.includes('"anonymize"'),
      ),
    ).toBe(true);
  });

  it('matches privacy register permission gating to user.manage or settings.manage', async () => {
    const allowed = privacyFetch();
    vi.stubGlobal('fetch', allowed.fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=privacidade'],
    );

    expect(await screen.findByText('Cloud Processor')).toBeTruthy();
    expect(allowed.calls.some((c) => c.url.includes('/v1/privacy/processors'))).toBe(true);

    cleanup();
    const denied = privacyFetch();
    vi.stubGlobal('fetch', denied.fn);

    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=privacidade'],
    );

    expect(await screen.findByText('Sem permissão')).toBeTruthy();
    expect(denied.calls.some((c) => c.url.includes('/v1/privacy/'))).toBe(false);
  });

  it('resets a signing URL to its default via the icon-only reset button', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    const tsa = (await screen.findByLabelText(
      'URL da autoridade de selo temporal (TSA)',
    )) as HTMLInputElement;
    // The reset control is an icon-only button; its accessible name comes from the Tooltip
    // `label` (aria-label), so `getByRole(..., { name })` still resolves it. Since t36 each
    // default URL sits in the card for the grid it backs, so TSL comes first and TSA second.
    const reset = () =>
      screen.getAllByRole('button', { name: 'Repor predefinição' })[1] as HTMLButtonElement;

    // At the default value the reset is inert…
    expect(reset().disabled).toBe(true);

    // …editing away from the default enables it…
    fireEvent.change(tsa, { target: { value: 'https://exemplo.pt/tsa' } });
    expect(reset().disabled).toBe(false);

    // …and clicking it restores the committed default.
    fireEvent.click(reset());
    expect(tsa.value).toBe(DEFAULT_SETTINGS.signing.tsa_url ?? '');
  });

  it('surfaces signing provider modes without secret inputs', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    expect(await screen.findByText('Modos de prestador configurados')).toBeTruthy();
    expect(screen.getByText(/Chave Móvel Digital \(CMD\/SCMD\)/)).toBeTruthy();
    expect(screen.getAllByText(/Cartão de Cidadão/).length).toBeGreaterThan(0);
    expect(screen.getByText(/CSC\/QTSP remote provider/)).toBeTruthy();
    expect(screen.getByText(/Local soft certificate \(PKCS#12\/PFX\)/)).toBeTruthy();
    expect(screen.getAllByText('Bloqueado em produção').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Apenas local').length).toBeGreaterThan(0);
    expect(screen.queryByLabelText(/passphrase|chave privada|private key|pin/i)).toBeNull();
  });

  it('defaults provider metadata when an older settings payload omits it', async () => {
    const { fn } = settingsFetch(settingsWithoutProviderMetadata());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    expect(await screen.findByText(/Local soft certificate \(PKCS#12\/PFX\)/)).toBeTruthy();
  });

  it('renders multiple configured TSL sources and TSA providers from settings', async () => {
    const { fn } = settingsFetch(settingsWithMultipleTrustSources());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    // Every source is now one grid row whose name is an editable cell, so the names read back as
    // input values rather than headings — that is the point of the redesign: two sources can be
    // compared down a column instead of across two stacked blocks.
    expect(await screen.findByText('Fontes TSL')).toBeTruthy();
    expect(screen.getByDisplayValue('Portugal GNS Trusted List')).toBeTruthy();
    expect(screen.getByDisplayValue('EU List of Trusted Lists')).toBeTruthy();
    const cachedSource = screen.getByRole('group', { name: 'Operator cached TSL' });
    expect(within(cachedSource).getByDisplayValue('operator-cache')).toBeTruthy();
    expect(
      within(cachedSource).getByDisplayValue('F:\\Projects\\chancela\\fixtures\\operator-tsl.xml'),
    ).toBeTruthy();

    expect(screen.getByText('Prestadores TSA')).toBeTruthy();
    const backupTsa = screen.getByRole('group', { name: 'Backup Timestamp TSA' });
    expect(within(backupTsa).getByDisplayValue('http://tsa.backup.example.test/tsa')).toBeTruthy();
    expect(within(backupTsa).getByDisplayValue('1.2.3.4.5')).toBeTruthy();
    expect(screen.getAllByText('Predefinido').length).toBe(1);
  });

  it('autosaves trust-source management actions through the settings document', async () => {
    const { fn, calls } = settingsFetch(settingsWithMultipleTrustSources());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    const cachedSource = await screen.findByRole('group', { name: 'Operator cached TSL' });
    // One control per row, and its label states the row's current state (t36) — the row used to
    // carry a status badge AND a separately-worded switch saying the same thing.
    const enabled = within(cachedSource).getByRole('switch', {
      name: 'Inativa',
    }) as HTMLInputElement;
    expect(enabled.checked).toBe(false);
    fireEvent.click(enabled);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.filter((c) => c.method === 'PUT').at(-1);
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.signing.tsl_sources.find((source) => source.id === 'operator-cache')).toMatchObject(
      {
        enabled: true,
        path: 'F:\\Projects\\chancela\\fixtures\\operator-tsl.xml',
      },
    );
  });

  it('keeps exactly one enabled default TSA provider when the operator changes it', async () => {
    const { fn, calls } = settingsFetch(settingsWithMultipleTrustSources());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    const backupTsa = await screen.findByRole('group', { name: 'Backup Timestamp TSA' });
    fireEvent.click(within(backupTsa).getByRole('button', { name: 'Tornar predefinido' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const sent = JSON.parse(
      calls.filter((c) => c.method === 'PUT').at(-1)!.body as string,
    ) as typeof DEFAULT_SETTINGS;
    expect(
      sent.signing.tsa_providers.filter((provider) => provider.enabled && provider.default),
    ).toEqual([expect.objectContaining({ id: 'backup-tsa' })]);
    expect(sent.signing.tsa_providers.find((provider) => provider.id === 'pt-cc')).toMatchObject({
      default: false,
    });
  });

  it('defaults TSL/TSA source arrays when an older settings payload omits them', async () => {
    const { fn } = settingsFetch(settingsWithoutTrustSourceMetadata());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    expect(await screen.findByDisplayValue('Portugal GNS Trusted List')).toBeTruthy();
    expect(screen.getByDisplayValue('Portugal Cartao de Cidadao TSA')).toBeTruthy();
  });

  it('adds, normalizes, disables, and removes trust sources with collision-free ids', async () => {
    const initial = materializeSettings({
      ...DEFAULT_SETTINGS,
      signing: {
        ...DEFAULT_SETTINGS.signing,
        tsl_sources: [
          {
            ...DEFAULT_SETTINGS.signing.tsl_sources[0],
            id: 'trust-source-2',
            name: 'Existing collision source',
          },
        ],
        tsa_providers: [
          {
            ...DEFAULT_SETTINGS.signing.tsa_providers[0],
            id: 'tsa-provider-2',
            name: 'Existing collision TSA',
            enabled: false,
            default: false,
          },
        ],
      },
    });
    const { fn, calls } = settingsFetch(initial);
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    fireEvent.click(await screen.findByRole('button', { name: 'Adicionar fonte TSL' }));
    const newSource = screen.getByRole('group', { name: 'Nova fonte TSL' });
    expect(within(newSource).getByText('trust-source-3')).toBeTruthy();
    fireEvent.change(within(newSource).getByLabelText('Nome'), {
      target: { value: '  Source Three  ' },
    });
    fireEvent.change(within(newSource).getByLabelText('URL'), {
      target: { value: '  https://trust.example.test/list.xml  ' },
    });
    fireEvent.change(within(newSource).getByLabelText('Caminho local'), {
      target: { value: '   ' },
    });
    fireEvent.change(within(newSource).getByLabelText('Território'), {
      target: { value: '  PT  ' },
    });
    fireEvent.change(within(newSource).getByLabelText('Esquema'), {
      target: { value: '  eidas  ' },
    });
    fireEvent.click(within(newSource).getByRole('switch', { name: 'Inativa' }));

    fireEvent.click(screen.getByRole('button', { name: 'Adicionar TSA' }));
    const newTsa = screen.getByRole('group', { name: 'Novo prestador TSA' });
    expect(within(newTsa).getByText('tsa-provider-3')).toBeTruthy();
    expect(
      (within(newTsa).getByRole('switch', { name: 'Ativa' }) as HTMLInputElement).checked,
    ).toBe(true);
    fireEvent.change(within(newTsa).getByLabelText('Nome'), {
      target: { value: '  TSA Three  ' },
    });
    fireEvent.change(within(newTsa).getByLabelText('URL'), {
      target: { value: '  https://tsa.example.test/  ' },
    });
    fireEvent.change(within(newTsa).getByLabelText('Caminho local'), {
      target: { value: '  C:\\tsa\\fallback  ' },
    });
    fireEvent.change(within(newTsa).getByLabelText('Política aceite'), {
      target: { value: '  1.2.3.4  ' },
    });
    fireEvent.click(within(newTsa).getByRole('switch', { name: 'Ativa' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });
    const sent = JSON.parse(
      calls.filter((call) => call.method === 'PUT').at(-1)!.body as string,
    ) as typeof DEFAULT_SETTINGS;
    expect(sent.signing.tsl_sources.find((source) => source.id === 'trust-source-3')).toMatchObject(
      {
        name: 'Source Three',
        enabled: true,
        url: 'https://trust.example.test/list.xml',
        path: null,
        country: 'PT',
        scheme: 'eidas',
      },
    );
    expect(
      sent.signing.tsa_providers.find((provider) => provider.id === 'tsa-provider-3'),
    ).toMatchObject({
      name: 'TSA Three',
      enabled: false,
      default: false,
      url: 'https://tsa.example.test/',
      path: 'C:\\tsa\\fallback',
      policy: '1.2.3.4',
    });

    fireEvent.click(
      within(screen.getByRole('group', { name: 'Source Three' })).getByRole('button', {
        name: 'Remover',
      }),
    );
    fireEvent.click(
      within(screen.getByRole('group', { name: 'TSA Three' })).getByRole('button', {
        name: 'Remover',
      }),
    );
    expect(screen.queryByRole('group', { name: 'Source Three' })).toBeNull();
    expect(screen.queryByRole('group', { name: 'TSA Three' })).toBeNull();
  });

  it('lists API keys as persisted metadata including returned rate limits', async () => {
    const { fn } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    expect(await screen.findByRole('button', { name: 'Chaves API' })).toBeTruthy();
    expect(await screen.findByText('ERP bridge')).toBeTruthy();
    expect(screen.getByText('chk_ab12cd34ef56')).toBeTruthy();
    expect(screen.getByText('60 req/min · rajada 20')).toBeTruthy();
    expect(screen.queryByText('chk_new_plaintext_secret')).toBeNull();
  });

  // The checklist is a checkbox group, not one control, so it used to carry a
  // `<label for="">` — an orphan label naming nothing. It must be a named group instead.
  it('names the API key permission checklist as a group instead of orphaning its label', async () => {
    const { fn } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova chave API' }));

    const group = await screen.findByRole('group', { name: 'Permissões' });
    expect(group.contains(await screen.findByLabelText('ledger.read'))).toBe(true);
    expect(document.querySelectorAll('label[for=""]')).toHaveLength(0);
  });

  it('creates an API key with a scoped permission grant and shows the plaintext once', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova chave API' }));
    fireEvent.change(await screen.findByLabelText('Nome da chave'), {
      target: { value: 'Ledger export' },
    });
    fireEvent.click(await screen.findByLabelText('ledger.read'));
    fireEvent.change(screen.getByLabelText('Pedidos por minuto'), { target: { value: '120' } });
    fireEvent.change(screen.getByLabelText('Rajada'), { target: { value: '10' } });
    fireEvent.click(screen.getByRole('button', { name: 'Criar chave' }));

    expect(await screen.findByText('Guarde este segredo agora')).toBeTruthy();
    expect(screen.getByText('chk_new_plaintext_secret')).toBeTruthy();
    expect(screen.queryByLabelText('role.manage')).toBeNull();

    const post = await waitFor(() =>
      calls.find((c) => c.method === 'POST' && c.url.includes('/v1/api-keys')),
    );
    expect(JSON.parse(post!.body as string)).toMatchObject({
      name: 'Ledger export',
      grant: {
        kind: 'permissions',
        permissions: ['ledger.read'],
        scope: { kind: 'global' },
      },
      rate_limit: { rpm: 120, burst: 10 },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Concluído' }));
    await waitFor(() => expect(screen.queryByText('chk_new_plaintext_secret')).toBeNull());
    expect(await screen.findByText('chk_new')).toBeTruthy();
  });

  it('rotates an active API key and shows the replacement secret once', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Rodar chave' }));

    expect(await screen.findByText('Guarde este segredo agora')).toBeTruthy();
    expect(screen.getByText('chk_rotated_plaintext_secret')).toBeTruthy();
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.includes('/v1/api-keys/key-1/rotate')),
      ).toBe(true),
    );

    fireEvent.click(screen.getByRole('button', { name: 'Concluído' }));
    await waitFor(() => expect(screen.queryByText('chk_rotated_plaintext_secret')).toBeNull());
    expect(await screen.findByText('chk_rotated')).toBeTruthy();
  });

  it('does not offer API-key actions for revoked keys', async () => {
    const { fn } = apiKeysFetch([API_KEY_ONE, API_KEY_REVOKED]);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    const activeRow = (await screen.findByText('ERP bridge')).closest('tr');
    const revokedRow = (await screen.findByText('Retired bridge')).closest('tr');
    expect(activeRow).toBeTruthy();
    expect(revokedRow).toBeTruthy();

    expect(within(activeRow!).getByRole('button', { name: 'Rodar chave' })).toBeTruthy();
    expect(within(revokedRow!).queryByRole('button', { name: 'Rodar chave' })).toBeNull();
    expect(within(revokedRow!).queryByRole('button', { name: 'Revogar' })).toBeNull();
    expect(within(revokedRow!).getByText('—')).toBeTruthy();
  });

  it('revokes API keys from the settings tab', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Revogar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar revogação' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/api-keys/key-1'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('Revogada')).toBeTruthy();
  });

  it('shows the page title exactly once, as the level-1 heading', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    // The browser tab title is owned by index.html; no page may clobber it.
    document.title = 'Chancela — Livro de Atas Digital';
    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // The header used to repeat the title as a self-referential breadcrumb, in the
    // singular ("Configuração") above the plural <h1>; only the <h1> survives.
    expect(await screen.findByRole('heading', { level: 1, name: 'Configurações' })).toBeTruthy();
    expect(screen.getAllByText('Configurações')).toHaveLength(1);
    expect(screen.queryByText('Configuração')).toBeNull();
    expect(document.querySelector('.page-header__crumbs')).toBeNull();
    expect(document.title).toBe('Chancela — Livro de Atas Digital');
  });
});
