/**
 * Status / risk / advisory / retention labels, their tones, and the one badge that reads them —
 * shared by the Privacidade list panels and by the five record pages (t55).
 *
 * Extracted VERBATIM from `PrivacyComplianceSection.tsx`. Both sides need the same words: a risk
 * level must read "Elevado" in the table cell and in the `<Select>` the operator changes it with,
 * and the two must not be allowed to drift.
 *
 * These are DISPLAY strings resolved from a wire identifier, one way only. Nothing here is
 * persisted, digested, matched or exported; the raw identifier is what the ledger keeps.
 */
import type { ReactNode } from 'react';
import {
  PRIVACY_RECORD_STATUSES,
  PRIVACY_RISK_LEVELS,
  type BreachEvidenceKind,
  type PrivacyAdvisoryReviewStatus,
  type PrivacyAdvisoryReviewSummary,
  type PrivacyRecordStatus,
  type PrivacyRiskLevel,
  type RetentionDisposalAction,
  type RetentionPolicyStatus,
} from '../../../api/types';
import { formatTimestamp } from '../../../format';
import { useT, type MessageKey, type TFunction } from '../../../i18n';
import { Badge } from '../../../ui';

export const STATUS_LABEL_KEYS: Record<PrivacyRecordStatus, MessageKey> = {
  draft: 'settings.privacy.status.draft',
  active: 'settings.privacy.status.active',
  under_review: 'settings.privacy.status.underReview',
  retired: 'settings.privacy.status.retired',
};

export const RISK_LABEL_KEYS: Record<PrivacyRiskLevel, MessageKey> = {
  low: 'settings.privacy.risk.low',
  medium: 'settings.privacy.risk.medium',
  high: 'settings.privacy.risk.high',
  critical: 'settings.privacy.risk.critical',
};

export const ADVISORY_REVIEW_LABEL_KEYS: Record<PrivacyAdvisoryReviewStatus, MessageKey> = {
  no_receipt: 'settings.privacy.advisory.noReceipt',
  current: 'settings.privacy.advisory.current',
  due_soon: 'settings.privacy.advisory.dueSoon',
  overdue: 'settings.privacy.advisory.overdue',
  under_review: 'settings.privacy.advisory.underReview',
};

export const RETENTION_STATUS_LABEL_KEYS: Record<RetentionPolicyStatus, MessageKey> = {
  draft: 'settings.privacy.retention.status.draft',
  active: 'settings.privacy.retention.status.active',
  suspended: 'settings.privacy.retention.status.suspended',
  retired: 'settings.privacy.retention.status.retired',
};

export const RETENTION_DISPOSAL_LABEL_KEYS: Record<RetentionDisposalAction, MessageKey> = {
  review: 'settings.privacy.retention.disposal.review',
  archive: 'settings.privacy.retention.disposal.archive',
  anonymize: 'settings.privacy.retention.disposal.anonymize',
  delete: 'settings.privacy.retention.disposal.delete',
  legal_hold: 'settings.privacy.retention.disposal.legal_hold',
  no_action: 'settings.privacy.retention.disposal.no_action',
};

export function statusLabel(t: TFunction, status: PrivacyRecordStatus): string {
  return t(STATUS_LABEL_KEYS[status]);
}

export function riskLabel(t: TFunction, risk: PrivacyRiskLevel): string {
  return t(RISK_LABEL_KEYS[risk]);
}

export function advisoryReviewLabel(t: TFunction, status: PrivacyAdvisoryReviewStatus): string {
  return t(ADVISORY_REVIEW_LABEL_KEYS[status]);
}

export function retentionStatusLabel(t: TFunction, status: RetentionPolicyStatus): string {
  return t(RETENTION_STATUS_LABEL_KEYS[status]);
}

export function retentionDisposalLabel(t: TFunction, action: RetentionDisposalAction): string {
  return t(RETENTION_DISPOSAL_LABEL_KEYS[action]);
}

export function statusSelectOptionsFor(t: TFunction) {
  return PRIVACY_RECORD_STATUSES.map((status) => ({
    value: status,
    label: statusLabel(t, status),
  }));
}

export function riskSelectOptionsFor(t: TFunction) {
  return PRIVACY_RISK_LEVELS.map((risk) => ({ value: risk, label: riskLabel(t, risk) }));
}

export function breachEvidenceOptionsFor(
  t: TFunction,
): { value: BreachEvidenceKind; label: string }[] {
  return [
    { value: 'review', label: t('settings.privacy.evidence.kind.review') },
    { value: 'drill', label: t('settings.privacy.evidence.kind.drill') },
  ];
}

export function riskTone(risk: PrivacyRiskLevel): 'neutral' | 'warn' | 'error' | 'ok' {
  if (risk === 'low') return 'ok';
  if (risk === 'high') return 'warn';
  if (risk === 'critical') return 'error';
  return 'neutral';
}

export function statusTone(status: PrivacyRecordStatus): 'neutral' | 'warn' | 'ok' {
  if (status === 'active') return 'ok';
  if (status === 'under_review') return 'warn';
  return 'neutral';
}

export function retentionStatusTone(status: RetentionPolicyStatus): 'neutral' | 'warn' | 'ok' {
  if (status === 'active') return 'ok';
  if (status === 'suspended') return 'warn';
  return 'neutral';
}

export function advisoryReviewTone(
  status: PrivacyAdvisoryReviewStatus,
): 'neutral' | 'accent' | 'warn' | 'ok' {
  if (status === 'current') return 'ok';
  if (status === 'due_soon') return 'accent';
  if (status === 'overdue' || status === 'under_review') return 'warn';
  return 'neutral';
}

export function advisoryReviewDetail(t: TFunction, review: PrivacyAdvisoryReviewSummary): string {
  if (review.status === 'no_receipt') return t('settings.privacy.advisory.detail.noReceipt');
  if (review.status === 'under_review') return t('settings.privacy.advisory.detail.underReview');
  const due = review.next_review_due_at
    ? t('settings.privacy.advisory.detail.nextReview', { date: review.next_review_due_at })
    : '';
  const last = review.last_reviewed_at ?? review.last_drill_at;
  // Receipts are evidence, so they render at evidentiary precision through the shared date family.
  const lastText = last
    ? t('settings.privacy.advisory.detail.lastEvidence', { date: formatTimestamp(last) })
    : '';
  return [due, lastText, t('settings.privacy.advisory.detail.noClaims')].filter(Boolean).join(' ');
}

export function AdvisoryReviewBadge({
  review,
}: {
  review: PrivacyAdvisoryReviewSummary;
}): ReactNode {
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
