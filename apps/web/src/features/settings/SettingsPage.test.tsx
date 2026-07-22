import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation, useNavigationType } from 'react-router-dom';
import { SettingsPage } from './SettingsPage';
import { MCP_TAB_PATH } from './PlatformOperationsSection';
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
    // The Operações › Armazenamento / Cópias e recuperação subtabs (t28) host the two policy
    // editors, so a settings test that opens one pulls in the data-management readouts too. Those
    // panes belong to `GestaoDadosSection.test.tsx`, which owns their fixtures; here they only need
    // to render without a live backend, so the status is the empty state and the ZK interlock is
    // reported disabled — the same benign shapes the t105/t28 gate tests use.
    if (url.includes('/v1/zk-repositories/storage-status')) {
      return Promise.resolve(
        jsonResponse({
          ready: false,
          reason:
            'zero-knowledge repository storage is disabled on PostgreSQL/HA until CHANCELA_ZK_SHARED_OBJECT_ROOT explicitly names the shared mounted <data_dir>/zk-repositories root',
          requires_shared_root: true,
          declared_root: null,
          source: 'unset',
        }),
      );
    }
    if (url.includes('/v1/data/status')) {
      return Promise.resolve(jsonResponse(null));
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

    renderWithProviders(<SettingsPage />, ['/settings']);

    // A segmented sub-tab per section (Gestão included).
    for (const name of ['Aparência', 'Documentos', 'Assinaturas', 'Gestão', 'Operações', 'Sobre']) {
      expect(await screen.findByRole('button', { name })).toBeTruthy();
    }
    // Aparência is the default section: its theme control is present…
    expect(await screen.findByLabelText('Tema')).toBeTruthy();
    // …while a Documentos-only field is not rendered until that sub-tab is active.
    expect(screen.queryByLabelText('URL de atualização do catálogo CAE')).toBeNull();
  });

  it('deep-links to a section via a path segment and navigates between sub-tabs', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/documents']);

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
    renderWithProviders(<SettingsPage />, ['/settings/identity']);
    expect(await screen.findByLabelText('Nome da organização')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Identidade' })).toBeNull();

    // …but the old link lands on Documentos, which shows both cards, each under its own
    // heading, and marks Documentos as the active sub-tab.
    expect(screen.getByRole('heading', { name: 'Identidade', level: 3 })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Documentos', level: 3 })).toBeTruthy();
    expect(screen.getByLabelText('URL de atualização do catálogo CAE')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Documentos' }).getAttribute('aria-pressed')).toBe(
      'true',
    );
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

    renderWithProviders(<SettingsPage />, ['/settings']);

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

    renderWithProviders(<SettingsPage />, ['/settings/about']);

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
    renderWithProviders(<SettingsPage />, ['/settings/documents']);

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
    renderWithProviders(<SettingsPage />, ['/settings']);

    fireEvent.click(await screen.findByRole('button', { name: 'Regenerar grão' }));
    expect(reroll).toHaveBeenCalledOnce();
    fireEvent.click(screen.getByRole('switch', { name: 'Textura de couro (fundo)' }));
    fireEvent.click(screen.getByRole('switch', { name: 'Textura de couro nos botões' }));

    // The native `<input type="color">` was replaced by the themed <ColorPicker> (t11): each
    // field is now a trigger button that opens a portaled dialog carrying the hex text field
    // and a per-field clear. Drive it the way an operator does — open, type a hex, clear.
    const setColor = (fieldLabel: string, hex: string): void => {
      fireEvent.click(screen.getByRole('button', { name: `Escolher cor: ${fieldLabel}` }));
      const dialog = screen.getByRole('dialog', { name: `${fieldLabel} — Seletor de cor` });
      fireEvent.change(within(dialog).getByLabelText('Código hexadecimal'), {
        target: { value: hex },
      });
    };

    setColor('Primária', '#112233');
    expect(colorStore.get().primary).toBe('#112233');
    // The per-field clear lives inside the panel and appears only once the field is set.
    const primaryDialog = screen.getByRole('dialog', { name: 'Primária — Seletor de cor' });
    fireEvent.click(within(primaryDialog).getByRole('button', { name: 'Repor esta cor' }));
    expect(colorStore.get().primary).toBeUndefined();

    setColor('Secundária', '#445566');
    setColor('Fundo', '#778899');
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

    renderWithProviders(<SettingsPage />, [MCP_TAB_PATH]);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar IA/MCP',
    })) as HTMLInputElement;
    expect(toggle.checked).toBe(false);
  });

  it('round-trips the AI/MCP tenant gate through the settings autosave from its new home', async () => {
    // The gate moved out of Gestão into the IA e MCP tab (user ruling). It must write the SAME
    // field on the SAME whole-document PUT it wrote from Gestão — a relocation, not a rewrite.
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, [MCP_TAB_PATH]);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar IA/MCP',
    })) as HTMLInputElement;
    fireEvent.click(toggle);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    expect(new URL(put!.url, 'http://localhost').pathname).toBe('/v1/settings');
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.ai).toEqual({ enabled: true });
  });

  it('leaves Gestão a read-only pointer to the gate, never a second writer', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/management']);

    expect(await screen.findByRole('heading', { name: 'Gestão' })).toBeTruthy();
    // The label is still here, so the absence of the control is not mysterious…
    expect(screen.getByText('Ativar IA/MCP')).toBeTruthy();
    expect(screen.getByText('Ativa-se em Operações › IA e MCP.')).toBeTruthy();
    // …but there is no control, and nothing here can write the setting.
    expect(screen.queryByRole('switch', { name: 'Ativar IA/MCP' })).toBeNull();
    expect(calls.some((c) => c.method === 'PUT')).toBe(false);
    // And it links to the one writer.
    expect(screen.getAllByRole('link', { name: 'IA e MCP' })[0].getAttribute('href')).toBe(
      MCP_TAB_PATH,
    );
  });

  it('hides the AI/MCP tenant gate, in both places, from users without settings.manage', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    const readerOnly = permissionsValue((permission) => permission !== 'settings.manage');

    renderWithProviders(
      <StaticPermissionsProvider value={readerOnly}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/management'],
    );

    // Gestão hid the toggle entirely (not merely disabled it) from a reader before the move.
    expect(await screen.findByRole('heading', { name: 'Gestão' })).toBeTruthy();
    expect(screen.queryByRole('switch', { name: 'Ativar IA/MCP' })).toBeNull();
    expect(screen.queryByText('Ativar IA/MCP')).toBeNull();
    cleanup();

    // The new home reproduces that exactly: hidden, not a disabled control the reader can see.
    vi.stubGlobal('fetch', settingsFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={readerOnly}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      [MCP_TAB_PATH],
    );

    expect(await screen.findByRole('heading', { name: 'Servidor MCP' })).toBeTruthy();
    expect(screen.queryByRole('switch', { name: 'Ativar IA/MCP' })).toBeNull();
    expect(screen.queryByText('Ativar IA/MCP')).toBeNull();
  });

  it('renders and autosaves the workflow reminder policy fields', { timeout: 15_000 }, async () => {
    const olderSettings = cloneJson(DEFAULT_SETTINGS) as Partial<typeof DEFAULT_SETTINGS>;
    delete olderSettings.workflow;
    const { fn, calls } = settingsFetch(olderSettings);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/management']);

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

    // The retained-export-cleanup policy editor moved to Operações › Armazenamento (t28).
    renderWithProviders(<SettingsPage />, ['/settings/operations/storage']);

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

    // The backup-recovery policy editor moved to Operações › Cópias e recuperação (t28).
    renderWithProviders(<SettingsPage />, ['/settings/operations/backups']);

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

  it('routes Plataforma to the per-service tabs instead of listing services it no longer holds', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

    expect(await screen.findByRole('button', { name: 'Operações' })).toBeTruthy();

    // Both service rows moved out (t82, t82b). `GET /v1/platform/services` returns exactly these
    // two, so the list here is empty by design — the pane routes rather than showing "no services".
    expect(screen.queryByText('Chancela API server')).toBeNull();
    expect(screen.queryByText('Chancela MCP stdio server')).toBeNull();
    expect(screen.queryByText(/cannot observe or spawn/)).toBeNull();
    expect(screen.queryByRole('button', { name: /Registar reinício/ })).toBeNull();

    const links = Object.fromEntries(
      screen.getAllByRole('link').map((a) => [a.textContent?.trim(), a.getAttribute('href')]),
    );
    expect(links['Servidor API']).toBe('/settings/operations/api');
    expect(links['Servidor MCP']).toBe('/settings/operations/mcp');
  });

  it('gathers every API-server control on the API sub-tab, at its own deep link', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/api']);

    // The service row, with the honest backend limitations it carried in Plataforma.
    expect(await screen.findByText('Chancela API server')).toBeTruthy();
    expect(screen.getAllByText('Reinício necessário').length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: /Registar reinício/ })).toBeTruthy();

    // The API log area level and the API service override, off the generic logging grid. Their
    // labels are now distinct: both read "API" before, in one panel, which named two controls
    // identically.
    expect((screen.getByLabelText('API') as HTMLSelectElement).value).toBe('info');
    expect((screen.getByLabelText('Servidor API') as HTMLSelectElement).value).toBe('');

    // The launch-time security posture, read-only — surfaced in the product for the first time.
    expect(screen.getByText('CHANCELA_CORS_ALLOWED_ORIGINS')).toBeTruthy();
    expect(screen.getByText('CHANCELA_RATE_LIMIT_PER_SECOND')).toBeTruthy();
    expect(screen.getByText('CHANCELA_HSTS_MAX_AGE')).toBeTruthy();
    expect(screen.getByText('CHANCELA_SESSION_MAX_LIFETIME')).toBeTruthy();

    // The connector allow-list is OUTBOUND connector egress, not the API's inbound surface — and
    // it is far likelier to look at home here, beside CORS and the rate limiter, than it was on
    // the MCP tab. So the same absence assertion applies, harder: no editor, and the env var is
    // NOT a row of the API's launch-configuration table, which would present it as API config.
    expect(screen.queryByLabelText(/Anfitriões permitidos/)).toBeNull();
    expect(screen.queryByRole('textbox', { name: /Anfitriões permitidos/ })).toBeNull();
    const envTable = screen.getByRole('table', { name: 'Configuração de arranque (ambiente)' });
    expect(within(envTable).getByText('CHANCELA_CORS_ALLOWED_ORIGINS')).toBeTruthy();
    expect(within(envTable).queryByText('CHANCELA_CONNECTOR_ALLOWED_HOSTS')).toBeNull();
    // It is named on the tab in exactly one place: the cross-reference that says it is NOT this.
    expect(screen.getByText(/não a superfície de entrada da API/)).toBeTruthy();
  });

  it('keeps the API keys pane on its own address, gate and disclosure inside the API tab', async () => {
    const { fn } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/api-keys']);

    // The bookmarkable address still lands on the keys pane, now under the API button.
    expect(await screen.findByRole('heading', { name: 'Chaves API' })).toBeTruthy();
    const operations = within(screen.getByRole('group', { name: 'Áreas de operações' }));
    expect(operations.getByRole('button', { name: 'API' }).getAttribute('aria-pressed')).toBe(
      'true',
    );
    const panes = within(screen.getByRole('group', { name: 'Áreas da API' }));
    expect(panes.getByRole('button', { name: 'Chaves API' }).getAttribute('aria-pressed')).toBe(
      'true',
    );

    // Disclosure unchanged: the table shows the non-secret prefix, never a `chk_` secret.
    expect(document.body.textContent ?? '').not.toMatch(/chk_[a-z0-9]+_[a-z0-9]{8,}/i);
    cleanup();

    // …and the gate did not narrow. Key management is `user.manage`, NOT `settings.manage`: a
    // holder of the former without the latter must still be able to work here. Nesting the pane
    // inside the server pane would have put it in the disabled fieldset and taken that away.
    vi.stubGlobal('fetch', apiKeysFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/operations/api-keys'],
    );

    const create = await screen.findByRole('button', { name: 'Nova chave API' });
    const fieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
    expect(fieldset.contains(create)).toBe(true);
    expect(fieldset.disabled).toBe(false);
    expect(create.hasAttribute('disabled')).toBe(false);
    expect(create.getAttribute('data-gated')).toBeNull();
  });

  it('gathers every MCP control on the MCP sub-tab, at its own deep link', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/mcp']);

    // The service row, with the same honest backend limitations it carried in Plataforma.
    expect(await screen.findByText('Chancela MCP stdio server')).toBeTruthy();
    expect(screen.getAllByText('Supervisor necessário').length).toBeGreaterThan(0);
    expect(screen.getByText(/cannot observe or spawn/)).toBeTruthy();

    // The MCP log level and the MCP service override, both moved off the generic logging grid.
    expect((screen.getByLabelText('MCP') as HTMLSelectElement).value).toBe('info');
    expect((screen.getByLabelText('MCP stdio') as HTMLSelectElement).value).toBe('');

    // The launch-time environment surface, read-only, with the API key named but never valued.
    expect(screen.getByText('CHANCELA_MCP_ENABLED_TOOLS')).toBeTruthy();
    expect(screen.getByText('CHANCELA_MCP_API_KEY')).toBeTruthy();
    // The connector egress allow-list is NOT MCP configuration and must not be implied to be:
    // `chancela-mcp` never reads it. It stays in Plataforma and is not even named here.
    expect(screen.queryByText('CHANCELA_CONNECTOR_ALLOWED_HOSTS')).toBeNull();
    expect(screen.queryByLabelText('Anfitriões permitidos')).toBeNull();

    // The AI/MCP gate is now WRITTEN here — this tab is its only writer, and Gestão holds a
    // read-only pointer rather than a second control.
    expect(screen.getByRole('switch', { name: 'Ativar IA/MCP' })).toBeTruthy();
    expect(screen.queryByRole('link', { name: 'Gestão' })).toBeNull();
  });

  it('carries the settings.manage gate onto the API tab with the controls it moved', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/operations/api'],
    );

    const restart = await screen.findByRole('button', { name: /Registar reinício/ });
    expect(restart.hasAttribute('disabled')).toBe(true);
    fireEvent.click(restart);
    expect(calls.some((c) => c.method === 'POST' && c.url.includes('/actions/'))).toBe(false);

    const fieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
    expect(fieldset.disabled).toBe(true);
    expect(fieldset.contains(screen.getByLabelText('API'))).toBe(true);
    expect(fieldset.contains(screen.getByLabelText('Servidor API'))).toBe(true);
    expect(screen.getByText('Sem permissão')).toBeTruthy();
  });

  it('autosaves the API log level and override to the same settings document', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/api']);

    fireEvent.change(await screen.findByLabelText('API'), { target: { value: 'debug' } });
    fireEvent.change(screen.getByLabelText('Servidor API'), { target: { value: 'trace' } });

    await waitFor(
      () => {
        const put = calls.filter((c) => c.method === 'PUT').at(-1);
        expect(put).toBeTruthy();
        const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
        expect(sent.platform.logging.api).toBe('debug');
        expect(sent.platform.logging.service_overrides.api).toBe('trace');
        // Untouched fields ride along unchanged — this is the whole-document autosave, same as
        // when these two selects lived in the Plataforma grid.
        expect(sent.platform.logging.global).toBe('info');
        expect(sent.platform.api_server.desired_state).toBe('running');
      },
      { timeout: 5000 },
    );
  });

  it('records an API restart desired state from the API tab, on the same endpoint', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/api']);

    fireEvent.click(await screen.findByRole('button', { name: /Registar reinício/ }));

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'POST' &&
            call.url.includes('/v1/platform/services/api/actions/restart'),
        ),
      ).toBe(true),
    );
  });

  it('carries the settings.manage gate onto the MCP tab with the controls it moved', async () => {
    // The point of the whole task: a relocated control must keep the gate it had. Both MCP
    // controls are admin-reserved — the service action through `canManage`, the two log selects
    // through the page's disabled fieldset — and neither may widen by having moved.
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/operations/mcp'],
    );

    const start = await screen.findByRole('button', { name: /Registar arranque/ });
    expect(start.hasAttribute('disabled')).toBe(true);
    fireEvent.click(start);
    expect(calls.some((c) => c.method === 'POST' && c.url.includes('/actions/start'))).toBe(false);

    const fieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
    expect(fieldset.disabled).toBe(true);
    expect(fieldset.contains(screen.getByLabelText('MCP'))).toBe(true);
    expect(fieldset.contains(screen.getByLabelText('MCP stdio'))).toBe(true);
    expect(screen.getByText('Sem permissão')).toBeTruthy();
  });

  it('keeps `/settings/mcp` resolvable as a hand-written deep link into the sub-tab', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/mcp']);

    expect(
      (await screen.findByRole('group', { name: 'Áreas de operações' })).querySelector(
        'button[aria-pressed="true"]',
      )?.textContent,
    ).toContain('MCP');
  });

  it('renders only meaningful platform action buttons from backend capabilities', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    // Each row now lives on the tab that owns its service; the rows themselves are unchanged.
    renderWithProviders(<SettingsPage />, ['/settings/operations/api']);

    const apiRow = (await screen.findByText('Chancela API server')).closest('section');
    expect(apiRow).toBeTruthy();
    expect(within(apiRow!).queryByRole('button', { name: /Registar arranque/ })).toBeNull();
    expect(within(apiRow!).getByRole('button', { name: /Registar paragem/ })).toBeTruthy();
    expect(within(apiRow!).getByRole('button', { name: /Registar reinício/ })).toBeTruthy();
    expect(within(apiRow!).getAllByText('Não suportado').length).toBeGreaterThan(0);
    expect(
      within(apiRow!).getByText('The current API process cannot start another copy of itself.'),
    ).toBeTruthy();

    // The same assertion for MCP, on the tab the row moved to (t82): same component, same
    // backend capabilities, same rendering — only the address changed.
    cleanup();
    vi.stubGlobal('fetch', settingsFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/operations/mcp']);

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

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

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
      ['/settings/operations/mcp'],
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

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

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

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

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

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

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

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    expect(await screen.findByText('App shell observed platform state')).toBeTruthy();
    expect(screen.getAllByText('Aplicação').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Debug').length).toBeGreaterThan(0);
    expect(screen.getByText('Sem contexto')).toBeTruthy();
  });

  it('records a platform MCP start desired state without implying live process control', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/mcp']);

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

  it('autosaves platform logging levels through the whole settings document, across Registos and MCP', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations']);

    fireEvent.click(await screen.findByRole('button', { name: 'Registos' }));

    const globalLog = (await screen.findByLabelText('Global')) as HTMLSelectElement;
    fireEvent.change(globalLog, { target: { value: 'debug' } });

    // The MCP area level and the MCP service override moved to their own sub-tab (t82). The
    // point of this assertion is that they still write the SAME field of the SAME working copy:
    // one PUT carries an edit made on Registos and an edit made on MCP.
    expect(screen.queryByLabelText('MCP stdio')).toBeNull();
    fireEvent.click(
      within(screen.getByRole('group', { name: 'Áreas de operações' })).getByRole('button', {
        name: 'IA e MCP',
      }),
    );
    const mcpOverride = (await screen.findByLabelText('MCP stdio')) as HTMLSelectElement;
    fireEvent.change(mcpOverride, { target: { value: 'trace' } });
    fireEvent.change(screen.getByLabelText('MCP') as HTMLSelectElement, {
      target: { value: 'warn' },
    });

    await waitFor(
      () => {
        const put = calls.filter((c) => c.method === 'PUT').at(-1);
        expect(put).toBeTruthy();
        const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
        expect(sent.platform.logging.global).toBe('debug');
        expect(sent.platform.logging.mcp).toBe('warn');
        expect(sent.platform.logging.service_overrides.mcp_stdio).toBe('trace');
        expect(sent.platform.api_server.desired_state).toBe('running');
      },
      { timeout: 5000 },
    );
  });

  it('shows the backend-owned registry auto-update plan and records a dry-run attempt', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/management']);

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

    renderWithProviders(<SettingsPage />, ['/settings/management']);

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

    renderWithProviders(<SettingsPage />, ['/settings/management']);

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

    renderWithProviders(<SettingsPage />, ['/settings']);
    const themeSelect = (await screen.findByLabelText('Tema')) as HTMLSelectElement;

    fireEvent.change(themeSelect, { target: { value: 'dark' } });
    await waitFor(() => expect(document.documentElement.getAttribute('data-theme')).toBe('dark'));

    fireEvent.change(themeSelect, { target: { value: 'system' } });
    await waitFor(() => expect(document.documentElement.hasAttribute('data-theme')).toBe(false));
  });

  it('scales the grain opacity var from the intensity slider live', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings']);
    // The themed <ColorPicker> (t11) contributes its own `role="slider"` controls (the
    // saturation/brightness area and the hue rail) to this tab, so name the grain control.
    const slider = (await screen.findByRole('slider', {
      name: /Intensidade da textura/,
    })) as HTMLInputElement;

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

    renderWithProviders(<SettingsPage />, ['/settings']);

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

    renderWithProviders(<SettingsPage />, ['/settings/identity']);

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

    renderWithProviders(<SettingsPage />, ['/settings/identity']);

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

    const { container } = renderWithProviders(<SettingsPage />, ['/settings/identity']);

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

    renderWithProviders(<SettingsPage />, ['/settings']);

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
        has_totp: false,
        two_factor_required: false,
        language: 'auto',
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

    renderWithProviders(<SettingsPage />, ['/settings/users']);

    // The sub-tab button exists and the roster renders inline (the fictional example user).
    // Scoped to the TOP strip since t106: Utilizadores now has a second-level strip whose first
    // button carries the same label (it reuses the roster's own card title), so an unscoped query
    // legitimately finds two. Both are wanted; this assertion is about the top-level one.
    const sections = await screen.findByRole('group', { name: 'Secções de configuração' });
    expect(within(sections).getByRole('button', { name: 'Utilizadores' })).toBeTruthy();
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    // t71: the roster stays here, but creating a user leaves for its own screen — a create
    // that also grants authority needs the room, and there is now exactly one place to do it.
    const novo = screen.getByRole('link', { name: /novo utilizador/i });
    expect(novo.getAttribute('href')).toBe('/users/new');
    // t89: and editing left too. No inline edit panel is reachable from this tab at all.
    expect(screen.queryByLabelText('Nome a apresentar')).toBeNull();
  });

  it('redirects the retired inline edit state out to the edit screen, keeping the fragment', async () => {
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/users')) return Promise.resolve(jsonResponse([]));
      if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      if (url.includes('/v1/ledger/verify'))
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      if (url.includes('/health'))
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    // A bookmark of the old inline address must resolve, not 404 and not render a second copy
    // of the credential controls — the whole point of deleting the panel.
    function LocationProbe() {
      const location = useLocation();
      return <output aria-label="location">{`${location.pathname}${location.hash}`}</output>;
    }

    renderWithProviders(
      <>
        <Routes>
          <Route path="/settings/:sec?/:sub?" element={<SettingsPage />} />
          <Route path="/users/:id" element={null} />
        </Routes>
        <LocationProbe />
      </>,
      ['/settings/users?user=u1#acesso'],
    );

    await waitFor(() =>
      expect(screen.getByLabelText('location').textContent).toBe('/users/u1#acesso'),
    );
  });

  it('hosts privacy/compliance processor and DPIA registers with search and filters', async () => {
    const { fn } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);

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
    // t102: the panel now also offers an advisory-review FILTER, whose options carry the same
    // labels as the row badges. Assert the badge specifically — the row's review state is what
    // this covers, not the filter's option list.
    await within(dpiaPanel!).findAllByText('Em revisão local');
    expect(
      within(dpiaPanel!)
        .getAllByText('Em revisão local')
        .some((el) => el.classList.contains('badge')),
    ).toBe(true);

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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
    await openPrivacySubTab('Orientação');

    const panel = (await screen.findByText('Modelo DPIA local')).closest('section');
    expect(panel).toBeTruthy();
    expect(await within(panel!).findByText('privacy-dpia-guidance/v1')).toBeTruthy();
    // t15: the guidance template's wire copy stays English, but the panel resolves each stable
    // section id to a pt-PT catalog key, so the reader sees the translated title — never the raw
    // backend English (asserted absent below alongside the live-value sentinels).
    expect(within(panel!).getByText('Descrição do tratamento')).toBeTruthy();
    expect(within(panel!).getByText('Perguntas de risco')).toBeTruthy();
    expect(within(panel!).queryByText('Processing description')).toBeNull();
    expect(within(panel!).queryByText('Risk prompts')).toBeNull();
    // t102: the "Flags sem alegação" disclosure is a two-column table now, so each flag
    // identifier is its own cell rather than the `key:` half of an inline pair.
    expect(within(panel!).getByText('authority_filing_completed')).toBeTruthy();
    expect(within(panel!).getByText('automated_risk_scoring_performed')).toBeTruthy();
    expect(within(panel!).getByText('register_mutation_performed')).toBeTruthy();
    expect(within(panel!).getByText('external_call_performed')).toBeTruthy();

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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);

    const dpiaPanel = (await screen.findByText('DPIAs')).closest('section');
    expect(dpiaPanel).toBeTruthy();
    expect(await within(dpiaPanel!).findByText('Marketing profiling')).toBeTruthy();
    expect(await within(dpiaPanel!).findByText(/Sem certificação de conformidade/)).toBeTruthy();
    fireEvent.click(within(dpiaPanel!).getByRole('button', { name: 'Novo registo' }));

    // t15: the register editor is now its own modal window, not an inline card. The form lives
    // inside the dialog; drive it there.
    let form = await screen.findByRole('dialog');
    expect(within(form).getByText('Novo registo')).toBeTruthy();
    fireEvent.change(within(form).getByLabelText('Título da DPIA'), {
      target: { value: 'Biometric entry DPIA' },
    });
    fireEvent.change(within(form).getByLabelText('Finalidade'), {
      target: { value: 'Entrada segura no edifício' },
    });
    fireEvent.change(within(form).getByLabelText('Base legal'), {
      target: { value: 'Interesse legítimo' },
    });
    fireEvent.change(within(form).getByLabelText('Categorias de dados'), {
      target: { value: 'Identificação\nDados biométricos' },
    });
    fireEvent.change(within(form).getByLabelText('Subprocessadores'), {
      target: { value: 'Access Processor SA' },
    });
    fireEvent.change(within(form).getByLabelText('Tipo de evidência'), {
      target: { value: 'drill' },
    });
    fireEvent.change(within(form).getByLabelText('Notas de evidência'), {
      target: { value: 'Operator DPIA drill receipt only.' },
    });
    fireEvent.click(within(form).getByRole('button', { name: 'Criar registo' }));

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
    form = await screen.findByRole('dialog');
    expect(within(form).getByText('Editar registo')).toBeTruthy();
    fireEvent.change(within(form).getByLabelText('Notas de evidência'), {
      target: { value: 'Follow-up local DPIA review only.' },
    });
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar alterações' }));

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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);

    const processorPanel = (await screen.findByText('Processadores GDPR')).closest('section');
    expect(processorPanel).toBeTruthy();
    fireEvent.click(within(processorPanel!).getByRole('button', { name: 'Novo registo' }));

    // t15: the register editor is now its own modal window, not an inline card.
    const form = await screen.findByRole('dialog');
    expect(within(form).getByText('Novo registo')).toBeTruthy();
    fireEvent.change(within(form).getByLabelText('Nome do processador'), {
      target: { value: 'Payroll Processor' },
    });
    fireEvent.change(within(form).getByLabelText('Finalidade'), {
      target: { value: 'Processamento salarial' },
    });
    fireEvent.change(within(form).getByLabelText('Base legal'), {
      target: { value: 'Contrato de trabalho' },
    });
    fireEvent.change(within(form).getByLabelText('Categorias de dados'), {
      target: { value: 'Identificação\nRemuneração' },
    });
    fireEvent.change(within(form).getByLabelText('Subprocessadores'), {
      target: { value: 'Payroll Backup SA' },
    });
    fireEvent.change(within(form).getByLabelText('Risco'), { target: { value: 'high' } });
    fireEvent.change(within(form).getByLabelText('Estado'), { target: { value: 'active' } });
    fireEvent.click(within(form).getByRole('button', { name: 'Criar registo' }));

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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);

    const breachPanel = (await screen.findByText('Playbooks de resposta a violações')).closest(
      'section',
    );
    expect(breachPanel).toBeTruthy();
    expect(await within(breachPanel!).findByText('Suspected account compromise')).toBeTruthy();
    expect(await within(breachPanel!).findByText(/Sem notificação à autoridade/)).toBeTruthy();
    // t102: as in the DPIA register, the review-state filter's options share the badge labels.
    await within(breachPanel!).findAllByText('Revisão atual');
    expect(
      within(breachPanel!)
        .getAllByText('Revisão atual')
        .some((el) => el.classList.contains('badge')),
    ).toBe(true);
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
    // t102: as above — the review-state filter's options share the badge labels.
    await within(transferPanel!).findAllByText('Revisão atual');
    expect(
      within(transferPanel!)
        .getAllByText('Revisão atual')
        .some((el) => el.classList.contains('badge')),
    ).toBe(true);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
    await openPrivacySubTab('Retenção');

    await screen.findByText('Candidatos de retenção vencidos');
    cleanup();
    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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

    renderWithProviders(<SettingsPage />, ['/settings/privacy']);
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
      ['/settings/privacy'],
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
      ['/settings/privacy'],
    );

    expect(await screen.findByText('Sem permissão')).toBeTruthy();
    expect(denied.calls.some((c) => c.url.includes('/v1/privacy/'))).toBe(false);
  });

  it('resets a signing URL to its default via the icon-only reset button', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/signing/tsa']);

    const tsa = (await screen.findByLabelText(
      'URL da autoridade de selo temporal (TSA)',
    )) as HTMLInputElement;
    // The reset control is an icon-only button; its accessible name comes from the Tooltip
    // `label` (aria-label), so `getByRole(..., { name })` still resolves it. Since t73 the TSL
    // and TSA grids are separate sub-tabs, so this panel holds exactly one default-URL reset.
    const reset = () =>
      screen.getByRole('button', { name: 'Repor predefinição' }) as HTMLButtonElement;

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

    renderWithProviders(<SettingsPage />, ['/settings/signing/trust-services']);

    // By `heading`, not by text: since t73 the sub-tab that opens this card is a button carrying
    // the very same words, so a bare text query would match two nodes.
    expect(
      await screen.findByRole('heading', { name: 'Modos de prestador configurados' }),
    ).toBeTruthy();
    expect(screen.getByText(/Chave Móvel Digital \(CMD\/SCMD\)/)).toBeTruthy();
    expect(screen.getAllByText(/Cartão de Cidadão/).length).toBeGreaterThan(0);
    expect(screen.getByText(/CSC\/QTSP remote provider/)).toBeTruthy();
    expect(screen.getByText(/Local soft certificate \(PKCS#12\/PFX\)/)).toBeTruthy();
    expect(screen.getAllByText('Bloqueado em produção').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Apenas local').length).toBeGreaterThan(0);
    expect(screen.queryByLabelText(/passphrase|chave privada|private key|pin/i)).toBeNull();
  });

  it('adds an Actions column with its own tooltip to the provider modes table', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/signing/trust-services']);

    // The new column is a real `columnheader` named "Ações" carrying its own FieldHelp glyph —
    // distinct from the four column tooltips t101 already built, which this must not disturb.
    expect(await screen.findByRole('columnheader', { name: 'Ações' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Ajuda sobre a coluna Ações' })).toBeTruthy();
  });

  it('deep-links each configurable mode and leaves Cartão de Cidadão a note, not a button', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    // Record every location the router renders. The producer navigates to
    // `…/providers?configure=csc`; the co-mounted consumer (ProviderCredentialsSection, t12-e3)
    // reads that param on mount and immediately clears it, so the FINAL location has no query.
    // Recording each rendered location captures the emitted URL regardless of that clearing —
    // this asserts the producer's contract, not the consumer's cleanup.
    const seen: string[] = [];
    function LocationRecorder() {
      const location = useLocation();
      seen.push(location.pathname + location.search);
      return null;
    }

    renderWithProviders(
      <>
        <LocationRecorder />
        <SettingsPage />
      </>,
      ['/settings/signing/trust-services'],
    );

    // The three configurable modes each expose a "Configurar" control; CC does not.
    expect(await screen.findByRole('button', { name: 'Configurar o modo CMD/SCMD' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Configurar o modo CSC/QTSP' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Configurar o modo PKCS#12 local' })).toBeTruthy();

    // Cartão de Cidadão is configured on the operator's own machine — a muted note, no route.
    expect(screen.getByText('Configurado na máquina do operador')).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: 'Configurar o modo Cartão de Cidadão' }),
    ).toBeNull();

    // Clicking one navigates to the frozen deep-link contract ProviderCredentialsSection consumes.
    fireEvent.click(screen.getByRole('button', { name: 'Configurar o modo CSC/QTSP' }));
    expect(seen).toContain('/settings/signing/providers?configure=csc');
  });

  it('explains what each signing mode is for below the table', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/signing/trust-services']);

    expect(
      await screen.findByRole('heading', {
        name: 'Para que serve cada modo e como configurá-lo',
      }),
    ).toBeTruthy();
    // One guidance entry per mode; assert each mode's distinctive purpose sentence is present.
    expect(screen.getByText(/assina remotamente na infraestrutura da AMA/)).toBeTruthy();
    expect(screen.getByText(/assina localmente com o certificado do próprio cartão/)).toBeTruthy();
    expect(screen.getByText(/Cloud Signature Consortium/)).toBeTruthy();
    expect(screen.getByText(/certificado guardado num ficheiro/)).toBeTruthy();
  });

  it('defaults provider metadata when an older settings payload omits it', async () => {
    const { fn } = settingsFetch(settingsWithoutProviderMetadata());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/signing/trust-services']);

    expect(await screen.findByText(/Local soft certificate \(PKCS#12\/PFX\)/)).toBeTruthy();
  });

  it('renders multiple configured TSL sources and TSA providers from settings', async () => {
    const { fn } = settingsFetch(settingsWithMultipleTrustSources());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/signing/tsl']);

    // Every source is now one grid row whose name is an editable cell, so the names read back as
    // input values rather than headings — that is the point of the redesign: two sources can be
    // compared down a column instead of across two stacked blocks.
    expect(await screen.findByRole('heading', { name: 'Fontes TSL' })).toBeTruthy();
    expect(screen.getByDisplayValue('Portugal GNS Trusted List')).toBeTruthy();
    expect(screen.getByDisplayValue('EU List of Trusted Lists')).toBeTruthy();
    const cachedSource = screen.getByRole('group', { name: 'Operator cached TSL' });
    expect(within(cachedSource).getByDisplayValue('operator-cache')).toBeTruthy();
    expect(
      within(cachedSource).getByDisplayValue('F:\\Projects\\chancela\\fixtures\\operator-tsl.xml'),
    ).toBeTruthy();

    // TSL and TSA are neighbouring sub-tabs since t73; the working copy spans both, so stepping
    // across the strip is how one reads the other half.
    fireEvent.click(screen.getByRole('button', { name: 'Prestadores TSA' }));

    expect(await screen.findByRole('heading', { name: 'Prestadores TSA' })).toBeTruthy();
    const backupTsa = screen.getByRole('group', { name: 'Backup Timestamp TSA' });
    expect(within(backupTsa).getByDisplayValue('http://tsa.backup.example.test/tsa')).toBeTruthy();
    expect(within(backupTsa).getByDisplayValue('1.2.3.4.5')).toBeTruthy();
    expect(screen.getAllByText('Predefinido').length).toBe(1);
  });

  it('autosaves trust-source management actions through the settings document', async () => {
    const { fn, calls } = settingsFetch(settingsWithMultipleTrustSources());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/signing/tsl']);

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

    renderWithProviders(<SettingsPage />, ['/settings/signing/tsa']);

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

    renderWithProviders(<SettingsPage />, ['/settings/signing/tsl']);

    expect(await screen.findByDisplayValue('Portugal GNS Trusted List')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Prestadores TSA' }));
    expect(await screen.findByDisplayValue('Portugal Cartao de Cidadao TSA')).toBeTruthy();
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
    renderWithProviders(<SettingsPage />, ['/settings/signing/tsl']);

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

    // TSA lives on its own sub-tab since t73; the draft carries across the strip untouched.
    fireEvent.click(screen.getByRole('button', { name: 'Prestadores TSA' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Adicionar TSA' }));
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

    // Remove each row from the sub-tab that owns it — TSA first (we are standing on it), then
    // back across the strip for the TSL row.
    fireEvent.click(
      within(screen.getByRole('group', { name: 'TSA Three' })).getByRole('button', {
        name: 'Remover',
      }),
    );
    expect(screen.queryByRole('group', { name: 'TSA Three' })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Fontes TSL' }));
    fireEvent.click(
      within(await screen.findByRole('group', { name: 'Source Three' })).getByRole('button', {
        name: 'Remover',
      }),
    );
    expect(screen.queryByRole('group', { name: 'Source Three' })).toBeNull();
  });

  it('lists API keys as persisted metadata including returned rate limits', async () => {
    const { fn } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);

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

    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova chave API' }));

    const group = await screen.findByRole('group', { name: 'Permissões' });
    expect(group.contains(await screen.findByLabelText('ledger.read'))).toBe(true);
    expect(document.querySelectorAll('label[for=""]')).toHaveLength(0);
  });

  it('creates an API key with a scoped permission grant and shows the plaintext once', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);

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

    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);

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

    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);

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

    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);

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
    renderWithProviders(<SettingsPage />, ['/settings']);

    // The header used to repeat the title as a self-referential breadcrumb, in the
    // singular ("Configuração") above the plural <h1>; only the <h1> survives.
    expect(await screen.findByRole('heading', { level: 1, name: 'Configurações' })).toBeTruthy();
    expect(screen.getAllByText('Configurações')).toHaveLength(1);
    expect(screen.queryByText('Configuração')).toBeNull();
    expect(document.querySelector('.page-header__crumbs')).toBeNull();
    expect(document.title).toBe('Chancela — Livro de Atas Digital');
  });
});

/**
 * t73 — eight flat sub-tabs folded into two parents.
 *
 * Email and Chaves API moved under Operações; Fornecedores de assinatura joined the five signing
 * cards, each now its own sub-tab, under Assinaturas. The second level is `/settings/<parent>/<sub>`,
 * rendered with the same shared `<SubNav>`; the three retired top-level addresses still resolve.
 */
describe('SettingsPage — second-level sub-tabs (t73)', () => {
  /** Reports the live query string and how the last navigation happened (PUSH vs REPLACE). */
  // The section and its sub-tab are path segments now, so the probe reports the pathname.
  function NavProbe() {
    return (
      <>
        <span data-testid="search-probe">{useLocation().pathname}</span>
        <span data-testid="navtype-probe">{useNavigationType()}</span>
      </>
    );
  }

  const path = () => screen.getByTestId('search-probe').textContent;

  /** The page renders a loader until the settings document arrives; the strips come with it. */
  const loaded = async () =>
    within(await screen.findByRole('group', { name: 'Secções de configuração' }));

  /** The parent strip and the child strip are two separate `role="group"` landmarks. */
  const childStrip = (name: string) => within(screen.getByRole('group', { name }));
  const labels = (scope: ReturnType<typeof within>): (string | undefined)[] =>
    scope
      .getAllByRole('button')
      .map((b: HTMLElement) => b.textContent?.replace(/\s+/gu, ' ').trim());

  it('collapses the eight former top-level sub-tabs into Operações and Assinaturas', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<SettingsPage />, ['/settings/operations']);

    // The three that moved are gone from the TOP strip…
    const top = await loaded();
    expect(top.getByRole('button', { name: 'Operações' })).toBeTruthy();
    expect(top.getByRole('button', { name: 'Assinaturas' })).toBeTruthy();
    expect(top.queryByRole('button', { name: 'Email' })).toBeNull();
    expect(top.queryByRole('button', { name: 'Chaves API' })).toBeNull();
    expect(top.queryByRole('button', { name: 'Fornecedores de assinatura' })).toBeNull();

    // …and two of them are here, in Operações' own strip, behind the platform controls.
    const operations = childStrip('Áreas de operações');
    // "Chaves API" is no longer a button here: since t82b it is a pane of the API tab, reached
    // from the API tab's own strip while keeping its `/operations/chaves-api` address.
    // "IA e MCP", not "MCP": the tab holds the tenant AI gate as well, so the strip says so.
    // "Serviços" and "Registos" replace "Plataforma" (t101): they were a third level inside it,
    // and are now siblings here — the panel they used to share no longer exists as an id.
    // "Base de dados" and "Redis e estado partilhado" arrive with t105 (new read-only environment
    // panes). "Gestão de Dados" was one button (t105) until t28 split its three internal panes into
    // sibling subtabs — "Armazenamento", "Cópias e recuperação" and "Chaves e reposição" — so each
    // has its own address. They sit after API and before IA e MCP, so the strip reads outwards from
    // the API surface through the stores behind it.
    expect(labels(operations)).toEqual([
      'Serviços',
      'Registos',
      'API',
      'Base de dados',
      'Redis e estado partilhado',
      'Armazenamento',
      'Cópias e recuperação',
      'Chaves e reposição',
      'IA e MCP',
      'Email',
      // Ambiente do servidor (t14) — the editable env-override superset, last as the advanced
      // surface. Its label resolves through the serverEnvFallback module, not the frozen catalog.
      'Ambiente do servidor',
    ]);

    // Serviços is the default and carries no `sub` segment, mirroring the `sec` rule.
    expect(await screen.findByRole('heading', { name: 'Operações' })).toBeTruthy();
    expect(operations.getByRole('button', { name: 'Serviços' }).getAttribute('aria-pressed')).toBe(
      'true',
    );
  });

  it('promotes Serviços and Registos to addressable siblings under Operações', async () => {
    // The user: "the logging should be a subtab under operations not a 2nd sub level. services
    // too." They were a `useState` strip inside Plataforma, so neither had an address, neither
    // could be linked to, and Back did not walk through them. This asserts the three things that
    // could regress: the addresses exist, the old one still resolves, and the moved controls
    // still write what they wrote.
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<SettingsPage />, ['/settings/operations/logs']);
    await loaded();

    // Deep-linkable in its own right, and the strip agrees with the address.
    const operations = childStrip('Áreas de operações');
    expect(operations.getByRole('button', { name: 'Registos' }).getAttribute('aria-pressed')).toBe(
      'true',
    );
    // No third-level strip survives: two identically-named landmarks on one page was the defect.
    expect(screen.queryByRole('navigation', { name: 'Secções de operações' })).toBeNull();

    // The moved control still writes to the same place in the same document. `platform.logging`
    // is the object the MCP and API tabs also read out of, so this is the assertion that moving
    // the panel that renders it did not fork it.
    fireEvent.change(await screen.findByLabelText('Global'), { target: { value: 'debug' } });
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });
    const body = JSON.parse(
      calls.filter((c) => c.method === 'PUT').at(-1)!.body as string,
    ) as typeof DEFAULT_SETTINGS;
    expect(body.platform.logging.global).toBe('debug');

    cleanup();

    // The retired address keeps resolving — onto the pane it always opened on, not a 404 and not
    // Aparência.
    vi.stubGlobal('fetch', settingsFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/operations/platform']);
    await loaded();
    expect(
      childStrip('Áreas de operações')
        .getByRole('button', { name: 'Serviços' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('lists the six Assinaturas sub-tabs in the requested order', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(<SettingsPage />, ['/settings/signing']);
    await loaded();

    expect(labels(childStrip('Áreas de assinaturas'))).toEqual([
      'Fornecedores de assinatura',
      'Política de assinatura',
      'Fontes TSL',
      'Prestadores TSA',
      'Modos de prestador configurados',
      'Chave Móvel Digital (CMD)',
    ]);
    // The first is the default: bare `/settings/signing` opens the credentials manager. Asserted
    // on the strip, not on the card heading — that section loads its own data over its own
    // endpoint, which this settings-document stub deliberately does not serve.
    expect(
      childStrip('Áreas de assinaturas')
        .getByRole('button', { name: 'Fornecedores de assinatura' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('widens only the tabular Assinaturas sub-tabs, from a deep link as well as a switch', async () => {
    // Configurações renders ONE panel for every section, so `wide-page` has to ride on that
    // panel (Arquivo's pattern) rather than on the page root. The three grids scrolled
    // sideways inside `.table-wrap` at every viewport at the shell measure; their siblings
    // are prose- or control-shaped and read worse when widened.
    const panel = () => document.querySelector('.route-transition');

    for (const [sub, wide] of [
      ['tsl', true],
      ['tsa', true],
      ['providers', true],
      ['policy', false],
      ['trust-services', false],
      ['cmd', false],
    ] as const) {
      vi.stubGlobal('fetch', settingsFetch(settingsWithMultipleTrustSources()).fn);
      renderWithProviders(<SettingsPage />, [`/settings/signing/${sub}`]);
      await loaded();
      expect(panel(), sub).toBeTruthy();
      expect(panel()?.classList.contains('wide-page'), sub).toBe(wide);
      cleanup();
    }

    // …and it follows a live tab switch, not only the first paint.
    vi.stubGlobal('fetch', settingsFetch(settingsWithMultipleTrustSources()).fn);
    renderWithProviders(<SettingsPage />, ['/settings/signing/tsl']);
    await loaded();
    expect(panel()?.classList.contains('wide-page')).toBe(true);
    fireEvent.click(
      childStrip('Áreas de assinaturas').getByRole('button', { name: 'Política de assinatura' }),
    );
    await waitFor(() => expect(panel()?.classList.contains('wide-page')).toBe(false));
    fireEvent.click(
      childStrip('Áreas de assinaturas').getByRole('button', { name: 'Prestadores TSA' }),
    );
    await waitFor(() => expect(panel()?.classList.contains('wide-page')).toBe(true));

    // The shared rule, not a bespoke override: `.app` keeps the prose measure every other
    // settings tab inherits, and its own padding, so the gutters survive. t18 named the two shell
    // measures + the gutter as custom props on `.app` (so the header shrink-back rule can be
    // derived from them exactly), so the measure/gutter/wide cap are asserted through those vars.
    const nodeFs = 'node:fs';
    const { readFileSync } = (await import(nodeFs)) as {
      readFileSync(path: string, encoding: 'utf8'): string;
    };
    const css = readFileSync('src/theme.css', 'utf8').replace(/\r\n/g, '\n');
    const appRule = css.match(/\.app\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(appRule).toContain('--app-measure: 1080px;');
    expect(appRule).toContain('--app-gutter: clamp(1.25rem, 4vw, 3rem);');
    expect(appRule).toContain('max-width: var(--app-measure);');
    expect(appRule).toContain('padding: var(--app-gutter);');
    const wideRule = css.match(/\.app:has\(\.wide-page\)\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(appRule).toContain('--app-measure-wide: 92rem;');
    expect(wideRule).toContain('max-width: var(--app-measure-wide);');
    // The header is pinned back to the narrow content box and re-centred so the sub-tab strip
    // keeps its left edge when a wide panel widens the shell (t18's actual fix).
    const headerRule =
      css.match(/\.app:has\(\.wide-page\)\s+\.page-header\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(headerRule).toContain('max-width: calc(var(--app-measure) - 2 * var(--app-gutter));');
    expect(headerRule).toContain('margin-inline: auto;');
    // `.settings-section` must not re-impose a cap the opt-out would then fight.
    const sectionRule = css.match(/\.settings-section\s*{(?<body>[^}]*)}/s)?.groups?.body ?? '';
    expect(sectionRule).toContain('max-width: none;');
  });

  it('explains every Assinaturas column through a focusable, described help trigger', async () => {
    // The user asked for "tooltip indicators … describing what each field does" on these three
    // grids. The point of the ticket is that the explanation reaches a keyboard and a screen
    // reader, not only a mouse — so this asserts the wiring, not the presence of a glyph:
    //
    //  - the trigger is a real `<button>` (a tab stop) whose accessible NAME names its column,
    //    so someone who tabs onto it out of visual context still knows what it belongs to;
    //  - the sentence is reachable through `aria-describedby`, resolving to a mounted node;
    //  - the `<th>` itself is still named by the bare column label, because a screen reader
    //    re-announces the column header on every cell and must not recite the help each time.
    const grids = [
      {
        sub: 'tsl',
        columns: ['Nome', 'Estado', 'URL', 'Caminho local', 'Território', 'Esquema', 'Ações'],
        // One spot-check per grid that the RIGHT sentence is wired to the right column.
        probe: 'Esquema',
        describes: /eidas, lotl/,
      },
      {
        sub: 'tsa',
        columns: ['Nome', 'Estado', 'URL', 'Caminho local', 'Política aceite', 'Limites', 'Ações'],
        probe: 'Política aceite',
        describes: /OID da política de carimbo/,
      },
      {
        sub: 'trust-services',
        columns: ['Prestador', 'Modo', 'Estado', 'Notas'],
        probe: 'Modo',
        describes: /onde fica a chave privada/,
      },
    ] as const;

    for (const grid of grids) {
      vi.stubGlobal('fetch', settingsFetch(settingsWithMultipleTrustSources()).fn);
      renderWithProviders(<SettingsPage />, [`/settings/signing/${grid.sub}`]);
      await loaded();

      for (const column of grid.columns) {
        // The header's own accessible name is the column label alone.
        const header = screen.getByRole('columnheader', { name: column });
        const trigger = within(header).getByRole('button', {
          name: `Ajuda sobre a coluna ${column}`,
        });

        // Reachable without a pointer: a real button takes focus.
        trigger.focus();
        expect(document.activeElement, `${grid.sub}/${column}`).toBe(trigger);

        // …and carries a description that actually resolves to a mounted node with text.
        const describedBy = trigger.getAttribute('aria-describedby');
        expect(describedBy, `${grid.sub}/${column}`).toBeTruthy();
        const bubble = document.getElementById(describedBy as string);
        expect(bubble, `${grid.sub}/${column}`).toBeTruthy();
        const sentence = bubble?.textContent ?? '';
        // A real explanation, not a restatement of the header.
        expect(sentence.length, `${grid.sub}/${column}`).toBeGreaterThan(60);
        expect(sentence.trim(), `${grid.sub}/${column}`).not.toBe(column);

        if (column === grid.probe) expect(sentence).toMatch(grid.describes);
      }

      cleanup();
    }
  });

  it('preserves every retired top-level address as a deep link into its new home', async () => {
    // /settings/email → Operações › Email
    vi.stubGlobal('fetch', settingsFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/email']);
    await loaded();
    expect(
      childStrip('Áreas de operações')
        .getByRole('button', { name: 'Email' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
    cleanup();

    // /settings/api-keys → Operações › API › Chaves API. Both hops of the address
    // still resolve: the API button in the operations strip, and the keys pane inside it.
    vi.stubGlobal('fetch', apiKeysFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/api-keys']);
    await loaded();
    expect(
      childStrip('Áreas de operações')
        .getByRole('button', { name: 'API' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
    expect(
      childStrip('Áreas da API')
        .getByRole('button', { name: 'Chaves API' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
    cleanup();

    // /settings/signing-providers → Assinaturas › Fornecedores
    vi.stubGlobal('fetch', settingsFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/signing-providers']);
    await loaded();
    expect(
      childStrip('Áreas de assinaturas')
        .getByRole('button', { name: 'Fornecedores de assinatura' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('deep-links a sub-tab, pushes history when one is chosen, and drops it on the default', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <>
        <NavProbe />
        <SettingsPage />
      </>,
      ['/settings/signing/tsl'],
    );

    // Deep-linkable: the URL alone selects the sub-tab.
    expect(await screen.findByRole('heading', { name: 'Fontes TSL' })).toBeTruthy();

    // Choosing another PUSHES, so browser Back is what undoes it (the t34/t62 rule).
    fireEvent.click(
      childStrip('Áreas de assinaturas').getByRole('button', {
        name: 'Chave Móvel Digital (CMD)',
      }),
    );
    expect(await screen.findByRole('heading', { name: 'Chave Móvel Digital (CMD)' })).toBeTruthy();
    expect(path()).toBe('/settings/signing/cmd');
    expect(screen.getByTestId('navtype-probe').textContent).toBe('PUSH');

    // The default sub-tab carries no segment at all, exactly like the default section.
    fireEvent.click(
      childStrip('Áreas de assinaturas').getByRole('button', {
        name: 'Fornecedores de assinatura',
      }),
    );
    expect(path()).toBe('/settings/signing');
  });

  it('falls back to the first sub-tab for an unknown one, and drops it when the section changes', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <>
        <NavProbe />
        <SettingsPage />
      </>,
      ['/settings/signing/naoexiste'],
    );

    await loaded();
    expect(
      childStrip('Áreas de assinaturas')
        .getByRole('button', { name: 'Fornecedores de assinatura' })
        .getAttribute('aria-pressed'),
    ).toBe('true');

    // A `sub` belongs to the section that declared it: leaving Assinaturas discards it rather
    // than carrying a stale child id into Operações.
    fireEvent.click((await loaded()).getByRole('button', { name: 'Operações' }));
    expect(path()).toBe('/settings/operations');
    expect(await screen.findByRole('heading', { name: 'Operações' })).toBeTruthy();
  });

  it('keeps the sub-tab strip operable for a reader who may not edit the settings', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/signing/policy'],
    );

    // The editable card is inerted by the disabled fieldset, with the honest explanation…
    expect(await screen.findByRole('heading', { name: 'Política de assinatura' })).toBeTruthy();
    expect(screen.getByText('Sem permissão')).toBeTruthy();
    const fieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
    expect(fieldset.disabled).toBe(true);
    expect(fieldset.contains(screen.getByLabelText('Família de assinatura preferida'))).toBe(true);

    // …but the strip lives OUTSIDE that fieldset, so navigating away is still possible.
    const cmd = childStrip('Áreas de assinaturas').getByRole('button', {
      name: 'Chave Móvel Digital (CMD)',
    });
    expect(fieldset.contains(cmd)).toBe(false);
    expect(cmd.hasAttribute('disabled')).toBe(false);
    fireEvent.click(cmd);
    expect(await screen.findByRole('heading', { name: 'Chave Móvel Digital (CMD)' })).toBeTruthy();
  });
});

/**
 * Utilizadores, Delegações and Funções were three top-level tabs; they are one tab with three
 * sub-tabs (t106). Two things must survive that move and both are asserted here rather than
 * argued in a comment: every address that resolved before still resolves, and **no principal
 * gains or loses reach to any of the three**.
 *
 * The gating half is the point. Grouping panels under a parent is exactly how a subtree silently
 * inherits a gate it was never designed under — the failure t102 flagged on the privacy registers.
 * These three were designed under three DIFFERENT gates (`user.manage`, `delegation.grant`,
 * `role.manage`), and none of them is `settings.manage`, which is the gate the Configurações page
 * itself applies to its own working-copy sections.
 */
describe('SettingsPage — Utilizadores sub-tabs (t106)', () => {
  function usersFetch(): { fn: typeof fetch; calls: Recorded[] } {
    const calls: Recorded[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, method: init?.method ?? 'GET', body: (init?.body as string) ?? null });
      if (url.includes('/v1/users')) return Promise.resolve(jsonResponse([]));
      if (url.includes('/v1/roles')) return Promise.resolve(jsonResponse([]));
      if (url.includes('/v1/delegations')) return Promise.resolve(jsonResponse([]));
      if (url.includes('/v1/permissions')) return Promise.resolve(jsonResponse(PERMISSION_CATALOG));
      if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      if (url.includes('/v1/ledger/verify')) {
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      }
      if (url.includes('/health')) {
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      }
      return Promise.resolve(jsonResponse([]));
    }) as typeof fetch;
    return { fn, calls };
  }

  const topStrip = async () =>
    within(await screen.findByRole('group', { name: 'Secções de configuração' }));
  const userStrip = () => within(screen.getByRole('group', { name: 'Áreas de utilizadores' }));
  const stripLabels = (scope: ReturnType<typeof within>): (string | undefined)[] =>
    scope
      .getAllByRole('button')
      .map((b: HTMLElement) => b.textContent?.replace(/\s+/gu, ' ').trim());

  it('groups the three former top-level tabs into one Utilizadores tab', async () => {
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/users']);

    // Funções and Delegações are gone from the TOP strip…
    const top = await topStrip();
    expect(top.getByRole('button', { name: 'Utilizadores' })).toBeTruthy();
    expect(top.queryByRole('button', { name: 'Funções' })).toBeNull();
    expect(top.queryByRole('button', { name: 'Delegações' })).toBeNull();

    // …and are here instead, in the order the user asked for.
    expect(stripLabels(userStrip())).toEqual(['Utilizadores', 'Delegações', 'Funções']);

    // The roster is the default sub-tab, so `/settings/users` is unchanged for anyone who
    // bookmarked it.
    expect(
      userStrip().getByRole('button', { name: 'Utilizadores' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('mounts each panel at its own second-level address', async () => {
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/users/delegations']);
    expect(await screen.findByRole('heading', { name: 'Delegações' })).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Funções' })).toBeNull();
    cleanup();

    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/users/roles']);
    expect(await screen.findByRole('heading', { name: 'Funções' })).toBeTruthy();
    expect(screen.queryByRole('heading', { name: 'Delegações' })).toBeNull();
  });

  it('keeps both former top-level addresses resolving to the panel they always showed', async () => {
    // These were real, linkable addresses. A restructure that 404s them breaks somebody's link.
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/roles']);
    expect(await screen.findByRole('heading', { name: 'Funções' })).toBeTruthy();
    // And it lands ON the sub-tab, not merely on the parent's default.
    expect(userStrip().getByRole('button', { name: 'Funções' }).getAttribute('aria-pressed')).toBe(
      'true',
    );
    cleanup();

    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/delegations']);
    expect(await screen.findByRole('heading', { name: 'Delegações' })).toBeTruthy();
    expect(
      userStrip().getByRole('button', { name: 'Delegações' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('moves the panels without moving who may use them', async () => {
    // A principal holding `role.manage` and `delegation.grant` but NOT `settings.manage`. Before
    // the move all three panels were top-level STANDALONE sections, so the settings fieldset never
    // inerted them. Had Utilizadores not stayed standalone, this operator would now find authority
    // they genuinely hold greyed out by a gate that has nothing to do with it.
    const noSettingsManage = permissionsValue((permission) => permission !== 'settings.manage');

    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={noSettingsManage}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/users/roles'],
    );

    expect(await screen.findByRole('heading', { name: 'Funções' })).toBeTruthy();
    const newRole = screen.getByRole('button', { name: 'Nova função' });
    // Not inerted by the settings fieldset. Asserted on the FIELDSET, not on the button's
    // `disabled` property: jsdom does not propagate `fieldset[disabled]` to descendant controls,
    // so `button.disabled` stays false under a disabled fieldset and an assertion on it would
    // pass whether or not the panel had been inerted. Verified by mutation — removing `users`
    // from STANDALONE_SECTIONS must fail this test.
    const rolesFieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
    expect(rolesFieldset.contains(newRole)).toBe(true);
    expect(rolesFieldset.disabled).toBe(false);
    // The page also drops its "Sem permissão" note for a standalone sub-tab, because nothing here
    // is locked and saying otherwise would be false.
    expect(screen.queryByText('Sem permissão')).toBeNull();
    // …and the panel's OWN gate does not block either, because this principal holds `role.manage`.
    expect(newRole.getAttribute('data-gated')).toBeNull();
    cleanup();

    // Same for Delegações, whose gate is `delegation.grant`.
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={noSettingsManage}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/users/delegations'],
    );
    expect(await screen.findByRole('heading', { name: 'Delegações' })).toBeTruthy();
    const grant = screen.getByRole('button', { name: 'Nova delegação' });
    const delegFieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
    expect(delegFieldset.contains(grant)).toBe(true);
    expect(delegFieldset.disabled).toBe(false);
    expect(screen.queryByText('Sem permissão')).toBeNull();
    expect(grant.getAttribute('data-gated')).toBeNull();
  });

  it('does not widen access: each sub-tab still refuses its own action on its own gate', async () => {
    // The mirror of the test above. Grouping must not hand anyone an affordance they lacked, so a
    // principal denied each panel's specific verb must still be refused it — one sub-tab at a time,
    // because the three verbs are genuinely different and a shared parent must not conflate them.
    const noRoleManage = permissionsValue((permission) => permission !== 'role.manage');

    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={noRoleManage}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/users/roles'],
    );

    // Reachable — the panel is not hidden, which is the other half of "must not narrow"…
    expect(await screen.findByRole('heading', { name: 'Funções' })).toBeTruthy();
    // …but refused, by the panel's own gate rather than by the page's.
    expect(screen.getByRole('button', { name: 'Nova função' }).getAttribute('data-gated')).toBe(
      'true',
    );
    cleanup();

    // Denying `role.manage` must NOT have reached Delegações, gated on a different verb.
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={noRoleManage}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/users/delegations'],
    );
    expect(await screen.findByRole('heading', { name: 'Delegações' })).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Nova delegação' }).getAttribute('data-gated'),
    ).toBeNull();
    cleanup();

    // And the converse: denying `delegation.grant` must not reach Funções.
    const noGrant = permissionsValue((permission) => permission !== 'delegation.grant');
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={noGrant}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/users/delegations'],
    );
    expect(await screen.findByRole('heading', { name: 'Delegações' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Nova delegação' }).getAttribute('data-gated')).toBe(
      'true',
    );
    cleanup();

    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={noGrant}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/users/roles'],
    );
    expect(await screen.findByRole('heading', { name: 'Funções' })).toBeTruthy();
    expect(
      screen.getByRole('button', { name: 'Nova função' }).getAttribute('data-gated'),
    ).toBeNull();
  });

  it('keeps the roster `?user=` redirect on the roster alone', async () => {
    // `?user=` is the roster's own legacy state and redirects out to the edit screen. Left
    // section-wide it would fire on the sibling sub-tabs too and throw an operator off the panel
    // they actually asked for.
    vi.stubGlobal('fetch', usersFetch().fn);
    renderWithProviders(<SettingsPage />, ['/settings/users/roles?user=u1']);
    expect(await screen.findByRole('heading', { name: 'Funções' })).toBeTruthy();
  });
});

/**
 * Gestão de dados under Operações (t105), split into three subtabs (t28).
 *
 * t105 moved Gestão de dados under Operações; t28 promoted its three internal panes
 * (Armazenamento / Cópias e recuperação / Chaves e reposição) to sibling route subtabs. The thing
 * that can go wrong silently is the gate: Gestão de dados was a STANDALONE section, so the page's
 * `settings.manage` fieldset never inerted it. Under a parent that is NOT standalone, dropping the
 * three subs from `STANDALONE_SUBSECTIONS` would have handed each its parent's gating — exactly the
 * inherited-gate hole t102 flagged on the privacy registers. These tests are what stops that
 * regression being invisible, and also that the two co-located policy editors (t28) do not silently
 * widen who may edit them.
 */
describe('Operações › Gestão de dados (t105/t28)', () => {
  function dataFetch(): typeof fetch {
    return ((input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes('/v1/permissions')) return Promise.resolve(jsonResponse(PERMISSION_CATALOG));
      if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      if (url.includes('/v1/zk-repositories/storage-status')) {
        return Promise.resolve(
          jsonResponse({
            ready: false,
            reason:
              'zero-knowledge repository storage is disabled on PostgreSQL/HA until CHANCELA_ZK_SHARED_OBJECT_ROOT explicitly names the shared mounted <data_dir>/zk-repositories root',
            requires_shared_root: true,
            declared_root: null,
            source: 'unset',
          }),
        );
      }
      if (url.includes('/health')) {
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      }
      // These tests are about the gate, the ZK pane and the policy-editor placement; the data
      // readouts belong to `GestaoDadosSection.test.tsx`, which owns their fixtures. `null` puts
      // that panel in its own empty state instead of duplicating a 200-line status document here.
      if (url.includes('/v1/data/status')) return Promise.resolve(jsonResponse(null));
      return Promise.resolve(jsonResponse([]));
    }) as typeof fetch;
  }

  const opsStrip = () => within(screen.getByRole('group', { name: 'Áreas de operações' }));

  it('mounts Armazenamento at the former `/operations/data` address (sub-level alias)', async () => {
    // `/settings/operations/data` was a real, bookmarkable address before the split. It resolves
    // through RETIRED_SUBSECTIONS to Armazenamento rather than falling through to Serviços.
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(<SettingsPage />, ['/settings/operations/data']);
    expect(await screen.findByLabelText('Raiz de objetos partilhada')).toBeTruthy();
    expect(
      opsStrip().getByRole('button', { name: 'Armazenamento' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('keeps the former top-level `/settings/data` address resolving to Armazenamento', async () => {
    // `/settings/data` was a real, linkable address. A restructure that drops it to the Aparência
    // fallback breaks somebody's bookmark without telling them.
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(<SettingsPage />, ['/settings/data']);
    expect(await screen.findByLabelText('Raiz de objetos partilhada')).toBeTruthy();
    expect(
      opsStrip().getByRole('button', { name: 'Armazenamento' }).getAttribute('aria-pressed'),
    ).toBe('true');
  });

  it('keeps all three split subtabs standalone (a data.manage holder is not locked out)', async () => {
    // A principal WITHOUT `settings.manage`. Each subtab was standalone before the split and must
    // stay so. Removing any of `operations:storage`/`backups`/`keys` from STANDALONE_SUBSECTIONS
    // must fail this test — that is the mutation this assertion exists to catch. Asserted on the
    // page FIELDSET rather than a control's `disabled`: jsdom does not propagate `fieldset[disabled]`
    // to descendants, so a per-control assertion would pass either way.
    const noSettingsManage = permissionsValue((permission) => permission !== 'settings.manage');
    const cases: [address: string, button: string][] = [
      ['/settings/operations/storage', 'Armazenamento'],
      ['/settings/operations/backups', 'Cópias e recuperação'],
      ['/settings/operations/keys', 'Chaves e reposição'],
    ];
    for (const [address, button] of cases) {
      cleanup();
      vi.stubGlobal('fetch', dataFetch());
      renderWithProviders(
        <StaticPermissionsProvider value={noSettingsManage}>
          <SettingsPage />
        </StaticPermissionsProvider>,
        [address],
      );
      // Wait until the subtab is the active one, then check the page fieldset. The page-level
      // settings fieldset is the FIRST `.settings-fieldset` (it wraps the whole panel body; a
      // co-located policy editor's inner fieldset comes later in the DOM). For a standalone subtab
      // it must not be disabled.
      await waitFor(() =>
        expect(opsStrip().getByRole('button', { name: button }).getAttribute('aria-pressed')).toBe(
          'true',
        ),
      );
      const pageFieldset = document.querySelector('.settings-fieldset') as HTMLFieldSetElement;
      expect(pageFieldset.disabled).toBe(false);
      expect(screen.queryByText('Sem permissão')).toBeNull();
    }
  });

  it('keeps the co-located policy editors `settings.manage`-gated on their subtab', async () => {
    // The retained-export-cleanup and backup-recovery policy editors are `settings.manage`
    // working-copy. Co-locating them onto standalone subtabs (t28) must NOT widen who may edit
    // them: each rides its own inner fieldset that inerts for a principal without `settings.manage`.
    const noSettingsManage = permissionsValue((permission) => permission !== 'settings.manage');
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(
      <StaticPermissionsProvider value={noSettingsManage}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/operations/storage'],
    );
    const policyCard = (
      await screen.findByText('Política de limpeza de exportações retidas')
    ).closest('.panel')!;
    const policyFieldset = policyCard.closest('.settings-fieldset') as HTMLFieldSetElement;
    expect(policyFieldset.disabled).toBe(true);
  });

  it('co-locates the two policy editors on the correct subtabs, off the Gestão tab', async () => {
    // Confirmation (t28): retained-export-cleanup policy lives on Armazenamento next to the export
    // cleanup action; backup-recovery policy lives on Cópias e recuperação next to its readout.
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(<SettingsPage />, ['/settings/operations/storage']);
    expect(await screen.findByText('Política de limpeza de exportações retidas')).toBeTruthy();
    expect(screen.queryByText('Política local de recuperação de backups')).toBeNull();

    cleanup();
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(<SettingsPage />, ['/settings/operations/backups']);
    expect(await screen.findByText('Política local de recuperação de backups')).toBeTruthy();
    expect(screen.queryByText('Política de limpeza de exportações retidas')).toBeNull();
  });

  it('keeps the save/error feedback on a policy subtab even though it is standalone (t28)', async () => {
    // The co-located policy editors write the settings document, so — unlike the other standalone
    // subtabs — a failed policy save must still surface the retry affordance (`hostsSettingsPolicy`).
    // Otherwise a settings.manage operator edits the policy here and never learns the save failed.
    const calls: Recorded[] = [];
    let putAttempts = 0;
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: (init?.body as string) ?? null });
      if (url.includes('/v1/permissions')) return Promise.resolve(jsonResponse(PERMISSION_CATALOG));
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
      if (url.includes('/v1/zk-repositories/storage-status')) {
        return Promise.resolve(
          jsonResponse({
            ready: false,
            reason: 'disabled',
            requires_shared_root: true,
            declared_root: null,
            source: 'unset',
          }),
        );
      }
      if (url.includes('/v1/data/status')) return Promise.resolve(jsonResponse(null));
      if (url.includes('/v1/ledger/verify')) {
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      }
      if (url.includes('/health')) {
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      }
      return Promise.resolve(jsonResponse([]));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/settings/operations/storage']);

    const minAge = (await screen.findByLabelText(
      'Idade mínima das exportações',
    )) as HTMLInputElement;
    fireEvent.change(minAge, { target: { value: '45' } });

    // The failed save surfaces the assertive toast and the retry affordance — the bar is NOT
    // suppressed the way it is on a data.manage-only standalone subtab.
    const alert = await screen.findByRole('alert', undefined, { timeout: 3000 });
    expect(alert.textContent).toContain('Falha ao guardar');
    fireEvent.click(screen.getByRole('button', { name: 'Tentar novamente' }));
    await waitFor(() => expect(putAttempts).toBe(2));
    expect(await screen.findByText('Configurações guardadas.')).toBeTruthy();
  });

  it('still refuses the ZK declaration to a principal without `settings.manage`', async () => {
    // The other half of "must not widen". The pane is reachable — it is a status surface an
    // operator needs — but the one control on it that changes a safety interlock stays refused.
    const noSettingsManage = permissionsValue((permission) => permission !== 'settings.manage');
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(
      <StaticPermissionsProvider value={noSettingsManage}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/settings/operations/data'],
    );

    expect(
      (await screen.findByLabelText('Raiz de objetos partilhada')).hasAttribute('disabled'),
    ).toBe(true);
    expect(
      screen.getByRole('button', { name: 'Guardar declaração' }).hasAttribute('disabled'),
    ).toBe(true);
  });

  it('states why the interlock is closed rather than merely that it is', async () => {
    // Misconfiguration must never be silent: the pane carries the server's own reason verbatim.
    vi.stubGlobal('fetch', dataFetch());
    renderWithProviders(<SettingsPage />, ['/settings/operations/data']);
    expect(await screen.findByText('Desativado (fecho seguro)')).toBeTruthy();
    expect(screen.getByText(/CHANCELA_ZK_SHARED_OBJECT_ROOT/)).toBeTruthy();
    // And it does not imply an assurance the server never made.
    expect(
      screen.getByText(/Não consegue verificar que é realmente uma montagem partilhada/),
    ).toBeTruthy();
  });
});
