/**
 * The working-copy shapes for the five RGPD compliance registers, and the pure functions that
 * convert between a server record, that working copy, and a create/patch body (t55).
 *
 * Extracted VERBATIM from `PrivacyComplianceSection.tsx`, where they were reachable only by the
 * list panels. The record editors are real pages now (`privacy/{…}RecordPage.tsx`) and need the
 * same conversions, so they live here rather than being duplicated or re-exported through a
 * 4000-line component module. Nothing here renders; it is all data.
 *
 * **Every `EMPTY_*` defaults `status` to `'draft'` on purpose.** That is the product's own
 * resumability primitive: an incomplete compliance record is saved as a rascunho and returned to
 * through its now-stable deep link. It is also why t55 writes NO draft to `localStorage` — these
 * forms carry categories of personal data, named subcontratantes and breach-response detail, and
 * mirroring a half-filled DPIA into unencrypted browser storage would be a privacy regression
 * inside the privacy surface.
 */
import type {
  BreachEvidenceKind,
  BreachPlaybookView,
  CreateBreachPlaybookBody,
  CreateDpiaRecordBody,
  CreateProcessorRecordBody,
  CreateRetentionPolicyBody,
  CreateTransferControlBody,
  DpiaEvidenceKind,
  DpiaRecordView,
  PatchDpiaRecordBody,
  PatchProcessorRecordBody,
  PrivacyRecordStatus,
  PrivacyRiskLevel,
  ProcessorRecordView,
  RetentionDisposalAction,
  RetentionPolicyStatus,
  RetentionPolicyView,
  TransferControlView,
} from '../../../api/types';

/** Processors and DPIAs share one register shape; `kind` is the only difference. */
export type RegisterKind = 'processor' | 'dpia';
export type RegisterRecord = ProcessorRecordView | DpiaRecordView;
export type PrivacyCreateBody = CreateProcessorRecordBody | CreateDpiaRecordBody;
export type PrivacyPatchBody = PatchProcessorRecordBody | PatchDpiaRecordBody;

export interface RegisterFormState {
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

export interface BreachPlaybookFormState {
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

export interface TransferControlFormState {
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

export interface RetentionPolicyFormState {
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

export const EMPTY_FORM: RegisterFormState = {
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

export const EMPTY_BREACH_FORM: BreachPlaybookFormState = {
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

export const EMPTY_TRANSFER_FORM: TransferControlFormState = {
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

export const EMPTY_RETENTION_FORM: RetentionPolicyFormState = {
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

export function primaryValue(kind: RegisterKind, record: RegisterRecord): string {
  return kind === 'processor'
    ? (record as ProcessorRecordView).name
    : (record as DpiaRecordView).title;
}

export function splitList(value: string): string[] {
  const items = value
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
  return [...new Set(items)];
}

export function joinList(items: string[]): string {
  return items.join('\n');
}

export function optionalText(value: string): string | undefined {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

export function formFromRecord(kind: RegisterKind, record: RegisterRecord): RegisterFormState {
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

export function breachFormFromRecord(record: BreachPlaybookView): BreachPlaybookFormState {
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

export function transferFormFromRecord(record: TransferControlView): TransferControlFormState {
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

export function retentionFormFromRecord(record: RetentionPolicyView): RetentionPolicyFormState {
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

export function createBody(kind: RegisterKind, form: RegisterFormState): PrivacyCreateBody {
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

export function patchBody(kind: RegisterKind, form: RegisterFormState): PrivacyPatchBody {
  const body = createBody(kind, form);
  return body;
}

export function breachCreateBody(form: BreachPlaybookFormState): CreateBreachPlaybookBody {
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

export function transferCreateBody(form: TransferControlFormState): CreateTransferControlBody {
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

export function retentionCreateBody(form: RetentionPolicyFormState): CreateRetentionPolicyBody {
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
