import type { ActState, ActView, ComplianceReport } from '../../api/types';

const MISSING_BUCKET = 'missing';
const UNKNOWN_BUCKET = 'unknown';
const OTHER_BUCKET = 'other';

export const MCP_WORKFLOW_PROVENANCE_REVIEW_URI = 'chancela://mcp/workflow-provenance-review';
export const WORKFLOW_PROVENANCE_REVIEW_PACKET_SCHEMA_VERSION =
  'workflow-provenance-review-packet/v1';

export const WORKFLOW_PROVENANCE_REVIEW_NO_CLAIM_FLAGS = {
  ai_01_complete: false,
  ai_02_complete: false,
  full_ai_mcp_completion: false,
  legal_validity: false,
  workflow_completion: false,
  source_certification: false,
  extraction_accuracy: false,
  signature_validation: false,
  qualified_signature: false,
  trust_validation: false,
  provider_assurance: false,
  registry_validation: false,
  ownership_validation: false,
  live_ai_provider: false,
  api_from_mcp: false,
  non_stdio_transport: false,
} as const;

export type WorkflowLifecycleBucket =
  | 'draft'
  | 'review'
  | 'pending'
  | 'approved'
  | 'sealed'
  | 'archived'
  | typeof MISSING_BUCKET
  | typeof UNKNOWN_BUCKET
  | typeof OTHER_BUCKET;

export type WorkflowHumanReviewBucket =
  | 'pending'
  | 'accepted'
  | 'rejected'
  | typeof MISSING_BUCKET
  | typeof UNKNOWN_BUCKET
  | typeof OTHER_BUCKET;

export interface WorkflowProvenanceReviewEvidence {
  schema_version: typeof WORKFLOW_PROVENANCE_REVIEW_PACKET_SCHEMA_VERSION;
  generated_from: 'act.workflow.aggregate';
  aggregate_counts_only: true;
  raw_values_echoed: false;
  workflows: Array<{
    workflow_state: WorkflowLifecycleBucket;
    human_review: {
      status: WorkflowHumanReviewBucket;
      present: boolean;
    };
    evidence_present: {
      ledger_ref: boolean;
      archive_ref: boolean;
      signature_ref: boolean;
      digest: boolean;
      generated_document_ref: boolean;
    };
  }>;
  workflow_summary: {
    record_count: number;
    lifecycle_buckets: Record<string, number>;
    ai_human_review_buckets: Record<string, number>;
    marker_counts: {
      ledger: number;
      archive: number;
      signature: number;
      fingerprint: number;
      docs: number;
      ai_statement_sources: number;
      convening_dispatch: number;
      written_resolution_reviews: number;
      compliance_findings: number;
    };
    missing_unknown_counts: {
      lifecycle: number;
      ai_human_review: number;
      ai_statement_source_fields: number;
      compliance_report: number;
      fingerprint: number;
      seal_event: number;
      convening_dispatch: number;
      written_resolution_review: number;
      total: number;
    };
    compliance_buckets: {
      errors: number;
      warnings: number;
      seal_allowed: boolean | null;
      report_present: boolean;
    };
    raw_values_echoed: false;
  };
  no_claim_flags: typeof WORKFLOW_PROVENANCE_REVIEW_NO_CLAIM_FLAGS;
}

export interface WorkflowProvenanceReviewCopyPayload {
  uri: typeof MCP_WORKFLOW_PROVENANCE_REVIEW_URI;
  arguments: {
    workflow_evidence: WorkflowProvenanceReviewEvidence;
  };
}

function normalizedString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function normalizedLabel(value: unknown): string | null {
  const text = normalizedString(value);
  return text
    ? text
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_+|_+$/g, '')
    : null;
}

function hasText(value: unknown): boolean {
  return normalizedString(value) !== null;
}

function countByStableKey<T>(
  values: T[],
  keyFor: (value: T) => string | null,
): Record<string, number> {
  const counts = new Map<string, number>();
  for (const value of values) {
    const key = keyFor(value) ?? MISSING_BUCKET;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  return Object.fromEntries(
    Array.from(counts.entries()).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function isUnknownLabel(label: string | null): boolean {
  return (
    label == null ||
    label === '' ||
    label === UNKNOWN_BUCKET ||
    label === 'not_available' ||
    label === 'n_a' ||
    label === 'none' ||
    label === 'null' ||
    label === 'undefined'
  );
}

export function workflowLifecycleBucket(state: unknown): WorkflowLifecycleBucket {
  const normalized = normalizedLabel(state);
  if (normalized == null) return MISSING_BUCKET;
  if (isUnknownLabel(normalized)) return UNKNOWN_BUCKET;
  switch (normalized as ActState | string) {
    case 'Draft':
    case 'draft':
      return 'draft';
    case 'Review':
    case 'review':
      return 'review';
    case 'Convened':
    case 'convened':
    case 'Deliberated':
    case 'deliberated':
    case 'Signing':
    case 'signing':
      return 'pending';
    case 'TextApproved':
    case 'textapproved':
    case 'text_approved':
      return 'approved';
    case 'Sealed':
    case 'sealed':
      return 'sealed';
    case 'Archived':
    case 'archived':
      return 'archived';
    default:
      return OTHER_BUCKET;
  }
}

export function workflowHumanReviewBucket(status: unknown): WorkflowHumanReviewBucket {
  const normalized = normalizedLabel(status);
  if (normalized == null) return MISSING_BUCKET;
  if (isUnknownLabel(normalized)) return UNKNOWN_BUCKET;
  switch (normalized) {
    case 'pending':
    case 'pending_human_verification':
    case 'awaiting_review':
    case 'needs_review':
    case 'review_required':
      return 'pending';
    case 'accepted':
    case 'accepted_by_human':
    case 'approved':
    case 'verified':
    case 'verified_by_human':
      return 'accepted';
    case 'rejected':
    case 'rejected_by_human':
    case 'declined':
    case 'denied':
      return 'rejected';
    default:
      return OTHER_BUCKET;
  }
}

function aiStatementSourceMissingField(
  source: Partial<NonNullable<NonNullable<ActView['ai_provenance']>['statement_sources']>[number]>,
): boolean {
  return (
    !hasText(source.path) ||
    !hasText(source.source_type) ||
    !hasText(source.source_label) ||
    !hasText(source.human_verification_status)
  );
}

function complianceWarningCount(report: ComplianceReport | null | undefined): number {
  if (!report) return 0;
  return report.warnings + (report.convening_advisories?.length ?? 0);
}

function conveningDispatchCount(act: ActView): number {
  return (act.convening?.recipients ?? []).filter(
    (recipient) =>
      hasText(recipient.dispatched_at) || hasText(recipient.reference) || recipient.channel != null,
  ).length;
}

function missingConveningDispatchCount(act: ActView): number {
  return (act.convening?.recipients ?? []).filter(
    (recipient) =>
      !hasText(recipient.dispatched_at) &&
      !hasText(recipient.reference) &&
      recipient.channel == null,
  ).length;
}

function writtenResolutionReviewCount(
  act: ActView,
  report: ComplianceReport | null | undefined,
): number {
  return (
    act.written_resolution_evidence?.review_receipts?.length ??
    act.written_resolution_evidence?.status?.review_receipts ??
    report?.written_resolution_evidence_status?.review_receipts ??
    0
  );
}

function writtenResolutionReviewMissingCount(
  act: ActView,
  report: ComplianceReport | null | undefined,
  reviewCount: number,
): number {
  const status =
    act.written_resolution_evidence?.status?.status ??
    report?.written_resolution_evidence_status?.status;
  const reviewApplies =
    act.channel === 'WrittenResolution' ||
    act.written_resolution_evidence != null ||
    (status != null && status !== 'not_applicable');
  return reviewApplies && reviewCount === 0 ? 1 : 0;
}

export function buildWorkflowProvenanceReviewEvidence(
  act: ActView,
  complianceReport?: ComplianceReport | null,
): WorkflowProvenanceReviewEvidence {
  const lifecycleBucket = workflowLifecycleBucket(act.state);
  const aiHumanReviewBucket = workflowHumanReviewBucket(
    act.ai_provenance?.human_verification.status,
  );
  const statementSources = act.ai_provenance?.statement_sources ?? [];
  const missingAiStatementSourceFields = statementSources.filter(
    aiStatementSourceMissingField,
  ).length;
  const signedSignatoryCount = act.signatories.filter((signatory) => signatory.signed).length;
  const fingerprintCount = hasText(act.payload_digest) ? 1 : 0;
  const ledgerCount = act.seal_event_seq == null ? 0 : 1;
  const archiveCount = lifecycleBucket === 'archived' ? 1 : 0;
  const documentCount = act.referenced_documents.length + act.attachments.length;
  const conveningDispatchMarkers = conveningDispatchCount(act);
  const writtenReviewCount = writtenResolutionReviewCount(act, complianceReport);
  const complianceFindings = complianceReport?.issues.length ?? 0;
  const markerCounts = {
    ledger: ledgerCount,
    archive: archiveCount,
    signature: signedSignatoryCount,
    fingerprint: fingerprintCount,
    docs: documentCount,
    ai_statement_sources: statementSources.length,
    convening_dispatch: conveningDispatchMarkers,
    written_resolution_reviews: writtenReviewCount,
    compliance_findings: complianceFindings,
  };
  const missingUnknownCounts = {
    lifecycle:
      lifecycleBucket === MISSING_BUCKET ||
      lifecycleBucket === UNKNOWN_BUCKET ||
      lifecycleBucket === OTHER_BUCKET
        ? 1
        : 0,
    ai_human_review:
      aiHumanReviewBucket === MISSING_BUCKET ||
      aiHumanReviewBucket === UNKNOWN_BUCKET ||
      aiHumanReviewBucket === OTHER_BUCKET
        ? 1
        : 0,
    ai_statement_source_fields: missingAiStatementSourceFields,
    compliance_report: complianceReport ? 0 : 1,
    fingerprint: fingerprintCount === 0 ? 1 : 0,
    seal_event: ledgerCount === 0 ? 1 : 0,
    convening_dispatch: missingConveningDispatchCount(act),
    written_resolution_review: writtenResolutionReviewMissingCount(
      act,
      complianceReport,
      writtenReviewCount,
    ),
    total: 0,
  };
  missingUnknownCounts.total =
    missingUnknownCounts.lifecycle +
    missingUnknownCounts.ai_human_review +
    missingUnknownCounts.ai_statement_source_fields +
    missingUnknownCounts.compliance_report +
    missingUnknownCounts.fingerprint +
    missingUnknownCounts.seal_event +
    missingUnknownCounts.convening_dispatch +
    missingUnknownCounts.written_resolution_review;

  return {
    schema_version: WORKFLOW_PROVENANCE_REVIEW_PACKET_SCHEMA_VERSION,
    generated_from: 'act.workflow.aggregate',
    aggregate_counts_only: true,
    raw_values_echoed: false,
    workflows: [
      {
        workflow_state: lifecycleBucket,
        human_review: {
          status: aiHumanReviewBucket,
          present: act.ai_provenance != null,
        },
        evidence_present: {
          ledger_ref: ledgerCount > 0,
          archive_ref: archiveCount > 0,
          signature_ref: signedSignatoryCount > 0,
          digest: fingerprintCount > 0,
          generated_document_ref: documentCount > 0,
        },
      },
    ],
    workflow_summary: {
      record_count: 1,
      lifecycle_buckets: countByStableKey([lifecycleBucket], (bucket) => bucket),
      ai_human_review_buckets: countByStableKey([aiHumanReviewBucket], (bucket) => bucket),
      marker_counts: markerCounts,
      missing_unknown_counts: missingUnknownCounts,
      compliance_buckets: {
        errors: complianceReport?.errors ?? 0,
        warnings: complianceWarningCount(complianceReport),
        seal_allowed: complianceReport?.seal_allowed ?? null,
        report_present: complianceReport != null,
      },
      raw_values_echoed: false,
    },
    no_claim_flags: WORKFLOW_PROVENANCE_REVIEW_NO_CLAIM_FLAGS,
  };
}

export function buildWorkflowProvenanceReviewCopyPayload(
  act: ActView,
  complianceReport?: ComplianceReport | null,
): WorkflowProvenanceReviewCopyPayload {
  return {
    uri: MCP_WORKFLOW_PROVENANCE_REVIEW_URI,
    arguments: {
      workflow_evidence: buildWorkflowProvenanceReviewEvidence(act, complianceReport),
    },
  };
}

export function formatWorkflowProvenanceReviewCopyPayload(
  act: ActView,
  complianceReport?: ComplianceReport | null,
): string {
  return `${JSON.stringify(buildWorkflowProvenanceReviewCopyPayload(act, complianceReport), null, 2)}\n`;
}
