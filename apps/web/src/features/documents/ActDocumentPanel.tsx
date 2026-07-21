/**
 * ActDocumentPanel — the document surface mounted on the ata editor (plan t48-e6).
 *
 * Composes the three deliverables into one card on the act screen:
 *   • the template picker (which model applies — informational, before the Signing snapshot);
 *   • the live draft preview ("Pré-visualizar") that renders the server `DocumentModel`
 *     so the operator sees the document as they fill the record — including an HONEST
 *     "sem modelo disponível" state when the family has no template (the endpoint 422s);
 *   • the frozen Signing PDF/A download, gated on the DOC-03 bundle actually existing (so an
 *     act whose family has no template shows an honest "não gerado" note, not a
 *     broken download), with the pdf digest surfaced as an integrity note.
 *
 * Reads render inline errors only; the one mutation here (the download) follows the toast
 * idiom (success + error) per CONVENTIONS §2/§3.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState } from 'react';
import { DISPATCH_CHANNELS } from '../../api/types';
import type {
  ActView,
  DocumentBundlePdfAccessibilityEvidenceIndex,
  DocumentBundleValidationReport,
  DispatchChannel,
  DocumentImportValidationFinding,
  DocumentImportValidationReport,
  EntityFamily,
  LifecycleStage,
  GeneratedDocumentDispatchEvidenceList,
  GeneratedDocumentDispatchEvidenceRecord,
  GeneratedDocumentDispatchEvidenceRequest,
  GeneratedDocumentDispatchEvidenceStatus,
  GeneratedDocumentView,
  ImportDocumentBody,
  ImportedDocumentReviewGuardrail,
  ImportedDocumentReviewPatchStatus,
  ImportedDocumentView,
} from '../../api/types';
import {
  ApiError,
  SESSION_HEADER,
  api,
  parseResponse,
  type ActDocumentWorkingCopyFormat,
} from '../../api/client';
import { clearSessionToken, getSessionToken } from '../../api/session';
import {
  useActDocumentBundle,
  useActDocumentPreview,
  useDownloadActDocument,
  useDownloadActDocumentOffice,
  useDownloadActDocumentWorkingCopy,
  useGenerateActDocument,
  useGeneratedDocumentDispatchEvidence,
  useGeneratedDocuments,
  useRecordGeneratedDocumentDispatchEvidence,
  useReviewImportedDocument,
  useTemplates,
  keys,
} from '../../api/hooks';
import { GateButton, scopeBook } from '../session/permissions';
import { useT, type TFunction } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  DateTime,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  Input,
  InlineWarning,
  Select,
  Skeleton,
  TextArea,
  Truncate,
  useToast,
} from '../../ui';
import { hasTemplateName, templateDisplayName, templateName } from '../templates/templateNames';
import { DocumentPreview } from './DocumentPreview';
import { TemplatePicker } from './TemplatePicker';
import './documents.css';

export interface ActDocumentPanelTarget {
  generatedDocumentId?: string | null;
  importedDocumentId?: string | null;
  focus?: 'dispatch-evidence' | 'import-review' | null;
}

/** A 422/404 from the document endpoints is the "family has no template" signal. */
export function isNoDocumentTemplate(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 422 || error.status === 404);
}

/** Slugify an entity/title fragment for a filesystem-friendly download name. */
export function documentDownloadSlug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

export async function listImportedDocumentsForAct(actId: string): Promise<ImportedDocumentView[]> {
  try {
    return await api.listImportedDocuments({ act_id: actId });
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return [];
    throw e;
  }
}

export async function validateImportedDocument(
  body: ImportDocumentBody,
): Promise<DocumentImportValidationReport> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getSessionToken();
  if (token) headers[SESSION_HEADER] = token;
  const res = await fetch('/v1/documents/import/validate', {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
  if (res.status === 401) clearSessionToken();
  return parseResponse<DocumentImportValidationReport>(res, '/v1/documents/import/validate');
}

export function documentArrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function readDocumentFileAsBase64(file: File, t: TFunction): Promise<string> {
  if (typeof FileReader === 'undefined') {
    return file.arrayBuffer().then(documentArrayBufferToBase64);
  }

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== 'string') {
        reject(new Error(t('documents.import.readError.imported')));
        return;
      }
      const base64 = result.includes(',') ? result.slice(result.indexOf(',') + 1) : result;
      resolve(base64);
    };
    reader.onerror = () => reject(reader.error ?? new Error(t('documents.import.readError.file')));
    reader.readAsDataURL(file);
  });
}

export function documentMetadataText(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

export function formatDocumentBytes(value: number, t: TFunction): string {
  if (!Number.isFinite(value) || value < 0) return t('documents.import.sizeUnknown');
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = value;
  let unit = 'bytes';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  const decimals = amount >= 10 || Number.isInteger(amount) ? 0 : 1;
  return `${amount.toFixed(decimals)} ${unit}`;
}

export function importedDisplayName(document: ImportedDocumentView, t: TFunction): string {
  return documentMetadataText(document.filename) ?? t('documents.import.unnamed');
}

export function importedDownloadName(document: ImportedDocumentView): string {
  return (
    documentMetadataText(document.filename) ??
    `documento-importado-${documentDownloadSlug(document.id)}.bin`
  );
}

const IMPORTED_DOCUMENT_REVIEW_NOTE_LIMIT = 2000;
const FALLBACK_IMPORTED_DOCUMENT_REVIEW_GUARDRAILS: ImportedDocumentReviewGuardrail[] = [
  'preserved_original_bytes_remain_non_canonical_evidence',
  'canonical_pdfa_record_is_not_replaced',
  'signed_pdf_artifact_is_not_created_or_validated',
  'ocr_or_conversion_output_is_not_promoted_to_canonical_records',
];

export function buildImportedDocumentReviewOptions(t: TFunction): {
  value: ImportedDocumentReviewPatchStatus;
  label: string;
}[] {
  return [
    {
      value: 'reviewed_non_canonical_original_only',
      label: t('documents.import.review.status.reviewedNonCanonical'),
    },
    {
      value: 'rejected_non_canonical_evidence',
      label: t('documents.import.review.status.rejected'),
    },
  ];
}

const DISPATCH_EVIDENCE_NOTE_LIMIT = 2000;
const EMPTY_GENERATED_RECIPIENTS: string[] = [];

export function generatedDispatchStatusLabel(
  status: GeneratedDocumentDispatchEvidenceStatus | null | undefined,
  t: TFunction,
): string {
  switch (status?.status) {
    case 'required_pending':
      return t('documents.generated.status.requiredPending');
    case 'operator_evidence_partial':
      return t('documents.generated.status.partial');
    case 'operator_evidence_covered':
      return t('documents.generated.status.covered');
    default:
      return t('documents.generated.status.notRequired');
  }
}

export function generatedDispatchStatusTone(
  status: GeneratedDocumentDispatchEvidenceStatus | null | undefined,
): 'neutral' | 'warn' | 'error' | 'ok' {
  if (status?.status === 'operator_evidence_covered') return 'ok';
  if (status?.status === 'required_pending' || status?.status === 'operator_evidence_partial') {
    return 'warn';
  }
  return 'neutral';
}

export function dispatchChannelLabel(channel: string | null | undefined, t: TFunction): string {
  if (!channel) return t('documents.generated.evidence.notIndicated');
  switch (channel) {
    case 'RegisteredLetter':
      return t('enum.dispatchChannel.RegisteredLetter');
    case 'RegisteredLetterAR':
      return t('enum.dispatchChannel.RegisteredLetterAR');
    case 'Email':
      return t('enum.dispatchChannel.Email');
    case 'HandDelivery':
      return t('enum.dispatchChannel.HandDelivery');
    case 'Publication':
      return t('enum.dispatchChannel.Publication');
    case 'Portal':
      return t('enum.dispatchChannel.Portal');
    default:
      return channel;
  }
}

export function lifecycleStageLabel(stage: LifecycleStage, t: TFunction) {
  return t(`enum.lifecycleStage.${stage}` as Parameters<TFunction>[0]);
}

export function localDateTimeInputValue(date = new Date()): string {
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function localDateTimeToRfc3339(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
}

export function trimDocumentTextOrNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function generatedDocumentDownloadName(document: GeneratedDocumentView): string {
  return `generated-${documentDownloadSlug(document.template_id)}-${documentDownloadSlug(document.id)}.pdf`;
}

export function importedReviewStatusLabel(status: unknown, t: TFunction): string {
  switch (documentMetadataText(status)) {
    case 'operator_review_required':
      return t('documents.import.review.status.operatorRequired');
    case 'ocr_review_required':
      return t('documents.import.review.status.ocrRequired');
    case 'canonical_conversion_review_required':
      return t('documents.import.review.status.legacyRequired');
    case 'reviewed_non_canonical_original_only':
      return t('documents.import.review.status.reviewedNonCanonical');
    case 'rejected_non_canonical_evidence':
      return t('documents.import.review.status.rejected');
    default:
      return documentMetadataText(status) ?? t('documents.import.review.status.notIndicated');
  }
}

export function importedReviewStatusTone(status: unknown): 'neutral' | 'warn' | 'error' | 'ok' {
  switch (documentMetadataText(status)) {
    case 'reviewed_non_canonical_original_only':
      return 'ok';
    case 'rejected_non_canonical_evidence':
      return 'error';
    case 'operator_review_required':
    case 'ocr_review_required':
    case 'canonical_conversion_review_required':
      return 'warn';
    default:
      return 'neutral';
  }
}

export function importedCanonicalRecordStatusLabel(status: unknown, t: TFunction): string | null {
  switch (documentMetadataText(status)) {
    case 'not_canonical_record':
      return t('documents.import.guardrails.canonical.notCanonical');
    case null:
      return null;
    default:
      return documentMetadataText(status);
  }
}

export function importedSignedArtifactStatusLabel(status: unknown, t: TFunction): string | null {
  switch (documentMetadataText(status)) {
    case 'not_signed_artifact':
      return t('documents.import.guardrails.signed.notSigned');
    case null:
      return null;
    default:
      return documentMetadataText(status);
  }
}

export function importedGuardrailChecklist(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const text = documentMetadataText(item);
    return text ? [text] : [];
  });
}

export function uniqueImportedGuardrails(guardrails: string[]): ImportedDocumentReviewGuardrail[] {
  return Array.from(new Set(guardrails)) as ImportedDocumentReviewGuardrail[];
}

export function importedRequiredReviewGuardrails(
  document: ImportedDocumentView,
): ImportedDocumentReviewGuardrail[] {
  const checklist = importedGuardrailChecklist(document.review_guardrail_checklist);
  if (checklist.length > 0) return uniqueImportedGuardrails(checklist);

  const policyChecklist = importedGuardrailChecklist(
    document.preservation_policy?.review_guardrail_checklist,
  );
  if (policyChecklist.length > 0) return uniqueImportedGuardrails(policyChecklist);

  return FALLBACK_IMPORTED_DOCUMENT_REVIEW_GUARDRAILS;
}

export function importedGuardrailLabel(guardrail: string, t: TFunction): string {
  switch (guardrail) {
    case 'preserved_original_bytes_remain_non_canonical_evidence':
      return t('documents.import.guardrails.checklist.originalBytes');
    case 'canonical_pdfa_record_is_not_replaced':
      return t('documents.import.guardrails.checklist.canonicalPdfa');
    case 'signed_pdf_artifact_is_not_created_or_validated':
      return t('documents.import.guardrails.checklist.signedArtifact');
    case 'ocr_or_conversion_output_is_not_promoted_to_canonical_records':
      return t('documents.import.guardrails.checklist.noPromotion');
    default:
      return t('documents.import.guardrails.checklist.unknown', { code: guardrail });
  }
}

export function importedAcknowledgedReviewGuardrails(
  document: ImportedDocumentView,
): ImportedDocumentReviewGuardrail[] {
  return uniqueImportedGuardrails(importedGuardrailChecklist(document.acknowledged_guardrail_ids));
}

export function importedDocumentHasReviewReceipt(document: ImportedDocumentView): boolean {
  const status = documentMetadataText(document.operator_review_status);
  if (
    status === 'reviewed_non_canonical_original_only' ||
    status === 'rejected_non_canonical_evidence'
  ) {
    return true;
  }

  return (
    documentMetadataText(document.operator_reviewed_at) != null ||
    documentMetadataText(document.operator_reviewed_by) != null ||
    documentMetadataText(document.operator_review_note) != null ||
    importedAcknowledgedReviewGuardrails(document).length > 0
  );
}

export function reviewPatchStatusFromDocument(
  status: ImportedDocumentView['operator_review_status'] | undefined,
): ImportedDocumentReviewPatchStatus {
  return status === 'rejected_non_canonical_evidence'
    ? 'rejected_non_canonical_evidence'
    : 'reviewed_non_canonical_original_only';
}

export function mergeImportedDocument(
  current: ImportedDocumentView[] | undefined,
  document: ImportedDocumentView,
): ImportedDocumentView[] {
  const existing = current ?? [];
  return [document, ...existing.filter((item) => item.id !== document.id)];
}

export function documentYesNo(value: boolean, t: TFunction): string {
  return value ? t('common.yes') : t('common.no');
}

export function shouldShowCanonicalConversionPreflight(
  preflight: DocumentImportValidationReport['canonical_conversion_preflight'] | undefined,
): boolean {
  if (!preflight) return false;
  const source = documentMetadataText(preflight.source_format);
  return (
    source === 'legacy_word_doc' ||
    source === 'ole_compound_file' ||
    documentMetadataText(preflight.status) === 'blocked'
  );
}

export function canonicalConversionPreflightStatusLabel(status: unknown, t: TFunction): string {
  switch (documentMetadataText(status)) {
    case 'blocked':
      return t('documents.import.preflight.status.blocked');
    case 'not_attempted':
      return t('documents.import.preflight.status.notAttempted');
    case null:
      return t('documents.import.preflight.notIndicated');
    default:
      return documentMetadataText(status) ?? t('documents.import.preflight.notIndicated');
  }
}

export function canonicalConversionPreflightSourceLabel(source: unknown, t: TFunction): string {
  switch (documentMetadataText(source)) {
    case 'legacy_word_doc':
      return t('documents.import.preflight.source.legacyDoc');
    case 'ole_compound_file':
      return t('documents.import.preflight.source.ole');
    case 'not_legacy_doc_or_ole':
      return t('documents.import.preflight.source.notLegacy');
    case null:
      return t('documents.import.preflight.notIndicated');
    default:
      return documentMetadataText(source) ?? t('documents.import.preflight.notIndicated');
  }
}

function CanonicalConversionPreflightEvidence({
  preflight,
  t,
}: {
  preflight:
    | DocumentImportValidationReport['canonical_conversion_preflight']
    | ImportedDocumentView['canonical_conversion_preflight']
    | undefined;
  t: TFunction;
}) {
  if (!shouldShowCanonicalConversionPreflight(preflight)) return null;

  return (
    <div className="stack--tight">
      <p className="card__label">{t('documents.import.preflight.title')}</p>
      <p className="field__hint">{t('documents.import.preflight.hint')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.import.preflight.field.status')}</dt>
          <dd>{canonicalConversionPreflightStatusLabel(preflight?.status, t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.format')}</dt>
          <dd>{canonicalConversionPreflightSourceLabel(preflight?.source_format, t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.evidenceBasis')}</dt>
          <dd>
            {preflight?.bounded_evidence_status ? (
              <code className="mono">{preflight.bounded_evidence_status}</code>
            ) : (
              <span className="muted">{t('documents.import.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.originalBytes')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.original_bytes_preserved), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.conversion')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.canonical_conversion_performed), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.pdfa')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.canonical_pdfa_generated), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.signatureValidation')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.signature_validation_performed), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.ocr')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.ocr_performed), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.legalAcceptance')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.legal_acceptance_claimed), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.externalProvider')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.external_provider_contacted), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.import.preflight.field.recordReplaced')}</dt>
          <dd>{documentYesNo(Boolean(preflight?.canonical_record_replaced), t)}</dd>
        </div>
      </dl>
      {preflight?.evidence_basis?.length ? (
        <div className="stack--tight">
          <p className="card__label">{t('documents.import.preflight.evidenceObserved')}</p>
          <ul className="plain-list">
            {preflight.evidence_basis.map((evidence) => (
              <li key={evidence}>
                <code className="mono">{evidence}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {preflight?.blockers?.length ? (
        <div className="stack--tight">
          <p className="card__label">{t('documents.import.preflight.blockers')}</p>
          <ul className="plain-list">
            {preflight.blockers.map((blocker) => (
              <li key={blocker}>
                <code className="mono">{blocker}</code>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function validationFindingTone(
  finding: DocumentImportValidationFinding,
): 'neutral' | 'warn' | 'error' {
  if (finding.severity === 'error') return 'error';
  if (finding.severity === 'warning') return 'warn';
  return 'neutral';
}

function DocumentImportValidationEvidence({
  report,
  t,
}: {
  report: DocumentImportValidationReport | null;
  t: TFunction;
}) {
  if (!report) return null;

  const legacyWord = report.legacy_word;
  const hasOleEvidence = legacyWord.is_ole_cfb || legacyWord.is_legacy_word_doc;
  if (!hasOleEvidence && report.findings.length === 0) return null;

  const accepted = report.can_accept_non_canonical_import;
  const title = legacyWord.is_legacy_word_doc
    ? t('documents.import.legacyWord.title')
    : accepted
      ? t('documents.import.validationTitle')
      : t('documents.import.validationRejectedTitle');

  return (
    <div className="stack--tight" role="group" aria-label={t('documents.import.validationAria')}>
      <InlineWarning tone={accepted ? 'info' : 'error'} title={title}>
        <div className="stack--tight">
          {legacyWord.is_legacy_word_doc ? (
            <p>{t('documents.import.legacyWord.body')}</p>
          ) : !accepted ? (
            <p>{t('documents.import.validationRejectedBody')}</p>
          ) : null}

          {hasOleEvidence ? (
            <dl className="deflist deflist--tight">
              <div>
                <dt>{t('documents.import.legacyWord.detectedType')}</dt>
                <dd className="mono">{report.content_type.detected}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.oleCfb')}</dt>
                <dd>{documentYesNo(legacyWord.is_ole_cfb, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.legacyDoc')}</dt>
                <dd>{documentYesNo(legacyWord.is_legacy_word_doc, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.macrosExecuted')}</dt>
                <dd>{documentYesNo(legacyWord.macro_execution_performed, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.conversion')}</dt>
                <dd>{documentYesNo(legacyWord.conversion_performed, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.canonicalPdfa')}</dt>
                <dd>{documentYesNo(legacyWord.canonical_pdfa_generated, t)}</dd>
              </div>
            </dl>
          ) : null}

          <CanonicalConversionPreflightEvidence
            preflight={report.canonical_conversion_preflight}
            t={t}
          />

          {report.findings.length > 0 ? (
            <div className="stack--tight">
              <p className="card__label">{t('documents.import.findings')}</p>
              <ul className="plain-list">
                {report.findings.map((finding, index) => (
                  <li className="chainrow" key={`${finding.code}-${index}`}>
                    <div className="stack--tight">
                      <p className="row-wrap">
                        <Badge tone={validationFindingTone(finding)}>{finding.severity}</Badge>
                        <code className="mono">{finding.code}</code>
                      </p>
                      <p className="chainrow__meta">{finding.message}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      </InlineWarning>
    </div>
  );
}

function GuardrailList({
  empty,
  guardrails,
  t,
}: {
  empty: string;
  guardrails: ImportedDocumentReviewGuardrail[];
  t: TFunction;
}) {
  if (guardrails.length === 0) return <span className="muted">{empty}</span>;

  return (
    <ul className="plain-list">
      {guardrails.map((guardrail) => (
        <li key={guardrail}>{importedGuardrailLabel(guardrail, t)}</li>
      ))}
    </ul>
  );
}

function ImportedDocumentReviewReceipt({
  document,
  t,
}: {
  document: ImportedDocumentView;
  t: TFunction;
}) {
  const hasReceipt = importedDocumentHasReviewReceipt(document);
  const requiredGuardrails = importedRequiredReviewGuardrails(document);
  const acknowledgedGuardrails = importedAcknowledgedReviewGuardrails(document);
  const reviewedAt = documentMetadataText(document.operator_reviewed_at);
  const reviewedBy = documentMetadataText(document.operator_reviewed_by);
  const reviewNote = documentMetadataText(document.operator_review_note);
  const receiptStatus = hasReceipt
    ? importedReviewStatusLabel(document.operator_review_status, t)
    : t('documents.import.receipt.none');

  return (
    <div className="stack--tight" role="group" aria-label={t('documents.import.receipt.title')}>
      <p className="card__label">{t('documents.import.receipt.title')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.import.receipt.status')}</dt>
          <dd>
            <Badge
              tone={
                hasReceipt ? importedReviewStatusTone(document.operator_review_status) : 'neutral'
              }
            >
              {receiptStatus}
            </Badge>
          </dd>
        </div>
        {hasReceipt ? (
          <>
            <div>
              <dt>{t('documents.import.review.reviewedAt')}</dt>
              <dd>
                {/* Part of the review receipt — evidentiary rendering. */}
                {reviewedAt ? (
                  <DateTime className="mono" value={reviewedAt} evidentiary />
                ) : (
                  <span className="muted">{t('documents.import.receipt.notInReceipt')}</span>
                )}
              </dd>
            </div>
            <div>
              <dt>{t('documents.import.review.reviewedBy')}</dt>
              <dd>
                {reviewedBy ?? (
                  <span className="muted">{t('documents.import.receipt.notInReceipt')}</span>
                )}
              </dd>
            </div>
            <div>
              <dt>{t('documents.import.receipt.noteRecorded')}</dt>
              <dd>
                {reviewNote ?? (
                  <span className="muted">{t('documents.import.receipt.noNote')}</span>
                )}
              </dd>
            </div>
            <div>
              <dt>{t('documents.import.review.requiredGuardrails')}</dt>
              <dd>
                <GuardrailList
                  empty={t('documents.import.receipt.noRequiredGuardrails')}
                  guardrails={requiredGuardrails}
                  t={t}
                />
              </dd>
            </div>
            <div>
              <dt>{t('documents.import.review.acknowledgedGuardrails')}</dt>
              <dd>
                <GuardrailList
                  empty={t('documents.import.receipt.noAcknowledgedGuardrails')}
                  guardrails={acknowledgedGuardrails}
                  t={t}
                />
              </dd>
            </div>
          </>
        ) : null}
        <div>
          <dt>{t('documents.import.receipt.field.ocr')}</dt>
          <dd>
            <Badge tone="neutral">{t('common.no')}</Badge>{' '}
            {t('documents.import.receipt.notPerformed')}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.receipt.field.conversion')}</dt>
          <dd>
            <Badge tone="neutral">{t('common.no')}</Badge>{' '}
            {t('documents.import.receipt.notPerformedFem')}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.receipt.field.pdfaReplacement')}</dt>
          <dd>
            <Badge tone="neutral">{t('common.no')}</Badge>{' '}
            {t('documents.import.receipt.notReplaced')}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.receipt.field.signedPdf')}</dt>
          <dd>
            <Badge tone="neutral">{t('common.no')}</Badge>{' '}
            {t('documents.import.receipt.notCreated')}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.receipt.field.legalAcceptance')}</dt>
          <dd>
            <Badge tone="neutral">{t('common.no')}</Badge>{' '}
            {t('documents.import.receipt.notClaimed')}
          </dd>
        </div>
      </dl>
    </div>
  );
}

function ImportedDocumentReviewHistory({
  document,
  t,
}: {
  document: ImportedDocumentView;
  t: TFunction;
}) {
  const history = document.review_history ?? [];

  return (
    <div className="stack--tight" role="group" aria-label={t('documents.import.history.title')}>
      <p className="card__label">{t('documents.import.history.title')}</p>
      {history.length === 0 ? (
        <p className="muted">{t('documents.import.history.empty')}</p>
      ) : (
        <ol className="stack--tight">
          {history.map((entry) => {
            const reviewedAt = documentMetadataText(entry.reviewed_at);
            const reviewedBy = documentMetadataText(entry.reviewed_by);
            const reviewNote = documentMetadataText(entry.review_note);
            const acknowledgedGuardrails = uniqueImportedGuardrails(
              importedGuardrailChecklist(entry.acknowledged_guardrail_ids),
            );

            return (
              <li key={entry.decision_index} className="stack--tight">
                <dl className="deflist deflist--tight">
                  <div>
                    <dt>{t('documents.import.history.decision')}</dt>
                    <dd>
                      <Badge tone={importedReviewStatusTone(entry.review_status)}>
                        {importedReviewStatusLabel(entry.review_status, t)}
                      </Badge>
                    </dd>
                  </div>
                  <div>
                    <dt>{t('documents.import.history.recordedAt')}</dt>
                    <dd>
                      {reviewedAt ? (
                        <DateTime className="mono" value={reviewedAt} evidentiary />
                      ) : (
                        <span className="muted">{t('documents.import.notIndicated')}</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>{t('documents.import.history.recordedBy')}</dt>
                    <dd>
                      {reviewedBy ?? (
                        <span className="muted">{t('documents.import.notIndicated')}</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>{t('documents.import.history.note')}</dt>
                    <dd>
                      {reviewNote ?? (
                        <span className="muted">{t('documents.import.notIndicated')}</span>
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>{t('documents.import.review.acknowledgedGuardrails')}</dt>
                    <dd>
                      <GuardrailList
                        empty={t('documents.import.history.noAcknowledgedGuardrails')}
                        guardrails={acknowledgedGuardrails}
                        t={t}
                      />
                    </dd>
                  </div>
                  <div>
                    <dt>{t('documents.import.history.scope')}</dt>
                    <dd>{t('documents.import.history.scopeBody')}</dd>
                  </div>
                </dl>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
}

function ImportedDocumentReviewDepthSummary({
  document,
  t,
}: {
  document: ImportedDocumentView;
  t: TFunction;
}) {
  const reviewNote = documentMetadataText(document.operator_review_note);
  const originalBytesStatus = documentMetadataText(
    document.preservation_policy?.original_bytes_preservation_status,
  );
  const originalBytesSummary = originalBytesStatus
    ? t('documents.import.depth.bytesPreserved', { status: originalBytesStatus })
    : t('documents.import.depth.bytesNotIndicated');
  const hasReceipt = importedDocumentHasReviewReceipt(document);
  const historyCount = document.review_history?.length ?? 0;

  return (
    <div className="stack--tight" role="group" aria-label={t('documents.import.depth.aria')}>
      <p className="card__label">{t('documents.import.depth.title')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.import.depth.includes')}</dt>
          <dd>
            {t('documents.import.depth.includesValue', {
              bytes: originalBytesSummary,
              receipt: hasReceipt
                ? t('documents.import.depth.recorded')
                : t('documents.import.depth.pending'),
              note: reviewNote
                ? t('documents.import.depth.noteRecorded')
                : t('documents.import.depth.noteNotIndicated'),
              history:
                historyCount > 0
                  ? t('documents.import.depth.decisionsPreserved', {
                      count: String(historyCount),
                    })
                  : t('documents.import.depth.noDecisions'),
            })}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.depth.reviewedDigest')}</dt>
          <dd>
            <Digest value={document.sha256} />
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.depth.derivedStatus')}</dt>
          <dd>
            <Badge tone={importedReviewStatusTone(document.operator_review_status)}>
              {importedReviewStatusLabel(document.operator_review_status, t)}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.depth.operatorNote')}</dt>
          <dd>
            {reviewNote ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
          </dd>
        </div>
        <div>
          <dt>{t('documents.import.depth.excludes')}</dt>
          <dd>{t('documents.import.depth.excludesValue')}</dd>
        </div>
        <div>
          <dt>{t('documents.import.depth.noClaimFlags')}</dt>
          <dd>{t('documents.import.depth.noClaimFlagsValue')}</dd>
        </div>
      </dl>
    </div>
  );
}

function MetadataValue({ value, missing }: { value: unknown; missing: string }) {
  const text = documentMetadataText(value);
  if (!text) return <span className="muted">{missing}</span>;
  return <Truncate text={text} mono />;
}

/**
 * A template reference: the document type's name on the primary line, the id (with its `/vN`)
 * kept underneath because that version is what a sealed document pins. Falls back to today's
 * id-only rendering for a template the catalog does not name.
 */
function TemplateMetadataValue({ templateId, missing }: { templateId: unknown; missing: string }) {
  const text = documentMetadataText(templateId);
  if (!text) return <span className="muted">{missing}</span>;
  if (!hasTemplateName(text)) return <Truncate text={text} mono />;
  return (
    <span className="stack--tight">
      <Truncate text={templateDisplayName(text)} />
      <Truncate className="muted" text={text} mono />
    </span>
  );
}

function pdfAccessibilityStatusLabel(status: string | null, t: TFunction): string {
  switch (status) {
    case 'pdf_accessibility_report_attached':
      return t('documents.accessibility.status.attached');
    case 'pdf_accessibility_report_unavailable':
      return t('documents.accessibility.status.unavailable');
    default:
      return status ?? t('documents.accessibility.notIndicated');
  }
}

function pdfAccessibilityStatusTone(status: string | null): 'neutral' | 'warn' {
  return status === 'pdf_accessibility_report_unavailable' ? 'warn' : 'neutral';
}

function pdfAccessibilityBlockers(
  report: DocumentBundleValidationReport['pdf_accessibility'] | undefined,
  index: DocumentBundlePdfAccessibilityEvidenceIndex | undefined,
): string[] {
  const values = report?.pdf_ua_blockers?.length
    ? report.pdf_ua_blockers
    : (index?.pdf_ua_blockers ?? []);
  return values.flatMap((value) => {
    const text = documentMetadataText(value);
    return text ? [text] : [];
  });
}

function DocumentPdfAccessibilityEvidence({
  validationReport,
  t,
}: {
  validationReport: DocumentBundleValidationReport | undefined;
  t: TFunction;
}) {
  const report = validationReport?.pdf_accessibility;
  const index = validationReport?.evidence_index?.pdf_accessibility;
  if (!report && !index) return null;

  const status =
    documentMetadataText(report?.evidence_status) ?? documentMetadataText(index?.evidence_status);
  const source = documentMetadataText(report?.report_source);
  const version = typeof report?.report_version === 'number' ? String(report.report_version) : null;
  const pdfUaClaimed = report?.pdf_ua_claimed ?? index?.pdf_ua_claimed ?? false;
  const blockers = pdfAccessibilityBlockers(report, index);
  const unavailableReason =
    status === 'pdf_accessibility_report_unavailable'
      ? documentMetadataText(report?.unavailable_reason)
      : null;

  return (
    <div className="stack--tight" role="group" aria-label={t('documents.accessibility.aria')}>
      <p className="card__label">{t('documents.accessibility.title')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.accessibility.status')}</dt>
          <dd>
            <Badge tone={pdfAccessibilityStatusTone(status)}>
              {pdfAccessibilityStatusLabel(status, t)}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>{t('documents.accessibility.source')}</dt>
          <dd>
            {source ? (
              <code className="mono">{source}</code>
            ) : (
              <span className="muted">{t('documents.accessibility.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.accessibility.version')}</dt>
          <dd>
            {version ? (
              <code className="mono">{version}</code>
            ) : (
              <span className="muted">{t('documents.accessibility.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.accessibility.blockers')}</dt>
          <dd>
            {blockers.length ? (
              <div className="stack--tight">
                <span>
                  {t('documents.accessibility.blockers.count', {
                    count: String(blockers.length),
                  })}
                </span>
                <ul className="plain-list">
                  {blockers.map((blocker) => (
                    <li key={blocker}>
                      <code className="mono">{blocker}</code>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              t('documents.accessibility.blockers.none')
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.accessibility.noClaimFlags')}</dt>
          <dd className="row-wrap">
            <code className="mono">pdf_ua_claimed={String(pdfUaClaimed)}</code>
            <code className="mono">dglab_certification_claimed=false</code>
            <code className="mono">legal_validity_claimed=false</code>
          </dd>
        </div>
        {unavailableReason ? (
          <div>
            <dt>{t('documents.accessibility.unavailableReason')}</dt>
            <dd>
              <code className="mono">{unavailableReason}</code>
            </dd>
          </div>
        ) : null}
      </dl>
      <p className="field__hint">{t('documents.accessibility.hint')}</p>
    </div>
  );
}

function ActDocumentMetadata({
  document,
  t,
}: {
  document: {
    id?: unknown;
    template_id?: unknown;
    profile?: unknown;
    created_at?: unknown;
  };
  t: TFunction;
}) {
  const createdAt = documentMetadataText(document.created_at);
  return (
    <div className="stack--tight" role="group" aria-label={t('documents.metadata.aria')}>
      <p className="card__label">{t('documents.metadata.title')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.metadata.document')}</dt>
          <dd>
            <MetadataValue value={document.id} missing={t('documents.metadata.missing')} />
          </dd>
        </div>
        <div>
          <dt>{t('documents.metadata.template')}</dt>
          <dd>
            <TemplateMetadataValue
              templateId={document.template_id}
              missing={t('documents.metadata.missing')}
            />
          </dd>
        </div>
        <div>
          <dt>{t('documents.metadata.profile')}</dt>
          <dd>
            <MetadataValue value={document.profile} missing={t('documents.metadata.missing')} />
          </dd>
        </div>
        <div>
          <dt>{t('documents.metadata.generatedAt')}</dt>
          <dd>
            {/* When the canonical PDF/A was produced — evidentiary. */}
            {createdAt ? (
              <DateTime className="mono" value={createdAt} evidentiary />
            ) : (
              <span className="muted">{t('documents.metadata.missing')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.metadata.legalSource')}</dt>
          <dd className="muted">{t('documents.metadata.legalSourceMissing')}</dd>
        </div>
        <div>
          <dt>{t('documents.metadata.legalThreshold')}</dt>
          <dd className="muted">{t('documents.metadata.legalThresholdMissing')}</dd>
        </div>
      </dl>
      <p className="field__hint">{t('documents.metadata.hint')}</p>
    </div>
  );
}

function GeneratedDispatchStatusSummary({
  status,
  t,
}: {
  status: GeneratedDocumentDispatchEvidenceStatus | null | undefined;
  t: TFunction;
}) {
  const required = status?.required_recipients.length ?? 0;
  const recorded = status?.recorded_recipients.length ?? 0;
  return (
    <div className="stack--tight" role="group" aria-label={t('documents.generated.status.aria')}>
      <p className="card__label">{t('documents.generated.status.title')}</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.generated.status.label')}</dt>
          <dd>
            <Badge tone={generatedDispatchStatusTone(status)}>
              {generatedDispatchStatusLabel(status, t)}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.status.coverage')}</dt>
          <dd>
            {required > 0
              ? t('documents.generated.status.coverageValue', {
                  recorded: String(recorded),
                  required: String(required),
                })
              : t('documents.generated.evidence.notIndicated')}
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.status.evidenceAttached')}</dt>
          <dd>{documentYesNo(Boolean(status?.evidence_attached), t)}</dd>
        </div>
        <div>
          <dt>{t('documents.generated.status.dispatchCompleted')}</dt>
          <dd className="mono">{String(Boolean(status?.dispatch_completed))}</dd>
        </div>
        <div>
          <dt>{t('documents.generated.status.completionBasis')}</dt>
          <dd className="mono">{status?.completion_basis ?? 'none'}</dd>
        </div>
      </dl>
      <InlineWarning tone="info" title={t('documents.generated.noClaim.title')}>
        {t('documents.generated.noClaim.body')}
      </InlineWarning>
    </div>
  );
}

function GeneratedDispatchEvidenceRows({
  evidence,
  importList,
  onSelectImport,
  t,
}: {
  evidence: GeneratedDocumentDispatchEvidenceList | undefined;
  importList: ImportedDocumentView[];
  onSelectImport: (id: string) => void;
  t: TFunction;
}) {
  const rows = evidence?.evidence ?? [];
  if (rows.length === 0) {
    return (
      <EmptyState title={t('documents.generated.evidence.empty.title')}>
        <p>{t('documents.generated.evidence.empty.body')}</p>
      </EmptyState>
    );
  }

  return (
    <ul className="plain-list" aria-label={t('documents.generated.evidence.listAria')}>
      {rows.map((row) => (
        <GeneratedDispatchEvidenceRow
          key={row.idempotency_key}
          row={row}
          importList={importList}
          onSelectImport={onSelectImport}
          t={t}
        />
      ))}
    </ul>
  );
}

function GeneratedDispatchEvidenceRow({
  row,
  importList,
  onSelectImport,
  t,
}: {
  row: GeneratedDocumentDispatchEvidenceRecord;
  importList: ImportedDocumentView[];
  onSelectImport: (id: string) => void;
  t: TFunction;
}) {
  const imported =
    row.imported_document_id != null
      ? importList.find((document) => document.id === row.imported_document_id)
      : undefined;
  return (
    <li className="chainrow">
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('documents.generated.evidence.actor')}</dt>
          <dd>{row.actor}</dd>
        </div>
        <div>
          <dt>{t('documents.generated.evidence.recordedAt')}</dt>
          {/* Both halves of a dispatch receipt: when it was sent, and when we recorded it. */}
          <dd>
            <DateTime className="mono" value={row.recorded_at} evidentiary />
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.dispatchedAt')}</dt>
          <dd>
            <DateTime className="mono" value={row.dispatched_at} evidentiary />
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.channel')}</dt>
          <dd>{dispatchChannelLabel(row.channel, t)}</dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.reference')}</dt>
          <dd>
            {row.reference ?? (
              <span className="muted">{t('documents.generated.evidence.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.evidenceReference')}</dt>
          <dd>
            {row.evidence_reference ?? (
              <span className="muted">{t('documents.generated.evidence.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.importedDocument')}</dt>
          <dd>
            {row.imported_document_id ? (
              imported ? (
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.FileText />}
                  onClick={() => onSelectImport(row.imported_document_id as string)}
                >
                  {importedDisplayName(imported, t)}
                </Button>
              ) : (
                <Truncate text={row.imported_document_id} mono />
              )
            ) : (
              <span className="muted">{t('documents.generated.evidence.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.recipients')}</dt>
          <dd>
            {row.recipients.length > 0
              ? row.recipients.join(', ')
              : t('documents.generated.evidence.notIndicated')}
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.form.operatorNote')}</dt>
          <dd>
            {row.operator_note ?? (
              <span className="muted">{t('documents.generated.evidence.notIndicated')}</span>
            )}
          </dd>
        </div>
        <div>
          <dt>{t('documents.generated.evidence.flags')}</dt>
          <dd>
            {t('documents.generated.evidence.flagsValue', {
              sending: String(row.sending_performed_by_chancela),
              delivery: String(row.delivery_confirmed),
              sufficiency: String(row.legal_sufficiency_claimed),
              notice: String(row.legal_notice_completion_claimed),
              bytes: String(row.bytes_in_payload),
            })}
          </dd>
        </div>
      </dl>
    </li>
  );
}

function GeneratedDispatchEvidenceForm({
  status,
  importList,
  dispatchedAt,
  channel,
  reference,
  evidenceReference,
  importedDocumentId,
  recipients,
  operatorNote,
  isPending,
  error,
  scope,
  onDispatchedAtChange,
  onChannelChange,
  onReferenceChange,
  onEvidenceReferenceChange,
  onImportedDocumentIdChange,
  onRecipientsChange,
  onOperatorNoteChange,
  onSubmit,
}: {
  status: GeneratedDocumentDispatchEvidenceStatus | null | undefined;
  importList: ImportedDocumentView[];
  dispatchedAt: string;
  channel: DispatchChannel | '';
  reference: string;
  evidenceReference: string;
  importedDocumentId: string;
  recipients: string[];
  operatorNote: string;
  isPending: boolean;
  error: unknown;
  scope: ReturnType<typeof scopeBook>;
  onDispatchedAtChange: (value: string) => void;
  onChannelChange: (value: DispatchChannel | '') => void;
  onReferenceChange: (value: string) => void;
  onEvidenceReferenceChange: (value: string) => void;
  onImportedDocumentIdChange: (value: string) => void;
  onRecipientsChange: (value: string[]) => void;
  onOperatorNoteChange: (value: string) => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const controlId = 'generated-dispatch-evidence';
  const requiredRecipients = status?.required_recipients ?? [];
  const hasLocator =
    trimDocumentTextOrNull(reference) != null ||
    trimDocumentTextOrNull(evidenceReference) != null ||
    trimDocumentTextOrNull(importedDocumentId) != null;
  const hasRecipients = requiredRecipients.length === 0 || recipients.length > 0;
  const canSubmit = dispatchedAt.trim().length > 0 && hasLocator && hasRecipients && !isPending;
  const channelOptions = [
    { value: '', label: t('documents.generated.evidence.notIndicated') },
    ...DISPATCH_CHANNELS.map((value) => ({
      value,
      label: dispatchChannelLabel(value, t),
    })),
  ];
  const importOptions = [
    { value: '', label: t('documents.generated.form.noImportedDocument') },
    ...importList.map((document) => ({
      value: document.id,
      label: importedDisplayName(document, t),
    })),
  ];

  return (
    <form
      id="generated-dispatch-evidence"
      className="form"
      tabIndex={-1}
      aria-label={t('documents.generated.form.aria')}
      onSubmit={(event) => {
        event.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <InlineWarning tone="info" title={t('documents.generated.form.noticeTitle')}>
        {t('documents.generated.form.noticeBody')}
      </InlineWarning>
      <Field label={t('documents.generated.form.dispatchedAt')} htmlFor={`${controlId}-at`}>
        <Input
          id={`${controlId}-at`}
          type="datetime-local"
          value={dispatchedAt}
          disabled={isPending}
          onChange={(event) => onDispatchedAtChange(event.target.value)}
        />
      </Field>
      <Field label={t('documents.generated.form.channel')} htmlFor={`${controlId}-channel`}>
        <Select
          id={`${controlId}-channel`}
          value={channel}
          options={channelOptions}
          disabled={isPending}
          onChange={(event) => onChannelChange(event.target.value as DispatchChannel | '')}
        />
      </Field>
      <Field label={t('documents.generated.form.reference')} htmlFor={`${controlId}-reference`}>
        <Input
          id={`${controlId}-reference`}
          value={reference}
          disabled={isPending}
          onChange={(event) => onReferenceChange(event.target.value)}
        />
      </Field>
      <Field
        label={t('documents.generated.form.evidenceReference')}
        htmlFor={`${controlId}-evidence-reference`}
      >
        <Input
          id={`${controlId}-evidence-reference`}
          value={evidenceReference}
          disabled={isPending}
          onChange={(event) => onEvidenceReferenceChange(event.target.value)}
        />
      </Field>
      <Field
        label={t('documents.generated.form.importedDocument')}
        htmlFor={`${controlId}-imported`}
        hint={t('documents.generated.form.locatorHint')}
      >
        <Select
          id={`${controlId}-imported`}
          value={importedDocumentId}
          options={importOptions}
          disabled={isPending}
          onChange={(event) => onImportedDocumentIdChange(event.target.value)}
        />
      </Field>
      <div className="stack--tight">
        <p className="field__label">{t('documents.generated.form.recipients')}</p>
        {requiredRecipients.length > 0 ? (
          requiredRecipients.map((recipient) => (
            <label className="checkline" key={recipient}>
              <input
                type="checkbox"
                checked={recipients.includes(recipient)}
                disabled={isPending}
                onChange={(event) => {
                  onRecipientsChange(
                    event.target.checked
                      ? [...recipients, recipient]
                      : recipients.filter((item) => item !== recipient),
                  );
                }}
              />
              {recipient}
            </label>
          ))
        ) : (
          <p className="field__hint">{t('documents.generated.evidence.notIndicated')}</p>
        )}
      </div>
      <Field
        label={t('documents.generated.form.operatorNote')}
        htmlFor={`${controlId}-note`}
        hint={`${operatorNote.length}/${DISPATCH_EVIDENCE_NOTE_LIMIT}`}
      >
        <TextArea
          id={`${controlId}-note`}
          rows={3}
          maxLength={DISPATCH_EVIDENCE_NOTE_LIMIT}
          value={operatorNote}
          disabled={isPending}
          onChange={(event) => onOperatorNoteChange(event.target.value)}
        />
      </Field>
      {error ? <ErrorNote error={error} /> : null}
      <GateButton
        perm="document.generate"
        scope={scope}
        type="submit"
        variant="secondary"
        icon={<Icon.Pencil />}
        disabled={!canSubmit}
      >
        {isPending
          ? t('documents.generated.form.submitting')
          : t('documents.generated.form.submit')}
      </GateButton>
    </form>
  );
}

function ImportedDocumentDetails({
  document,
  error,
  isLoading,
  t,
}: {
  document: ImportedDocumentView | null;
  error: unknown;
  isLoading: boolean;
  t: TFunction;
}) {
  if (error) return <ErrorNote error={error} />;
  if (isLoading && !document) return <Skeleton height="7rem" />;
  if (!document) return null;

  const filename = documentMetadataText(document.filename);
  const importedAt = documentMetadataText(document.imported_at);
  const declaredType = documentMetadataText(document.declared_content_type);
  const detectedType = documentMetadataText(document.detected_content_type);
  const importedBy = documentMetadataText(document.imported_by);
  const legalNotice = documentMetadataText(document.legal_notice) ?? t('documents.import.notice');
  const reviewNotice =
    documentMetadataText(document.operator_review_notice) ??
    t('documents.import.review.noticeFallback');
  const reviewedAt = documentMetadataText(document.operator_reviewed_at);
  const reviewedBy = documentMetadataText(document.operator_reviewed_by);
  const reviewNote = documentMetadataText(document.operator_review_note);

  return (
    <div className="stack--tight">
      <div className="stack--tight" role="group" aria-label={t('documents.import.metadataAria')}>
        <p className="card__label">{t('documents.import.metadataTitle')}</p>
        <dl className="deflist deflist--tight">
          <div>
            <dt>{t('documents.import.file')}</dt>
            <dd>
              {filename ? (
                <Truncate text={filename} />
              ) : (
                <span className="muted">{t('documents.import.filenameMissing')}</span>
              )}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.identifier')}</dt>
            <dd>
              <Truncate text={document.id} mono />
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.nature')}</dt>
            <dd>
              <Badge tone={document.non_canonical ? 'warn' : 'neutral'}>
                {document.non_canonical
                  ? t('documents.import.nonCanonical')
                  : t('documents.import.imported')}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.size')}</dt>
            <dd>{formatDocumentBytes(document.size_bytes, t)}</dd>
          </div>
          <div>
            <dt>{t('documents.import.declaredType')}</dt>
            <dd>
              {declaredType ?? <span className="muted">{t('documents.import.notDeclared')}</span>}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.detectedType')}</dt>
            <dd>
              {detectedType ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.importedAt')}</dt>
            <dd>
              {/* Import receipt: the moment the file entered the archive — evidentiary. */}
              {importedAt ? (
                <DateTime className="mono" value={importedAt} evidentiary />
              ) : (
                <span className="muted">{t('documents.import.notIndicated')}</span>
              )}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.importedBy')}</dt>
            <dd>
              {importedBy ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.review.operatorReview')}</dt>
            <dd>
              <Badge tone={importedReviewStatusTone(document.operator_review_status)}>
                {importedReviewStatusLabel(document.operator_review_status, t)}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.review.reviewNotice')}</dt>
            <dd>{reviewNotice}</dd>
          </div>
          <div>
            <dt>{t('documents.import.review.reviewedAt')}</dt>
            <dd>
              {reviewedAt ? (
                <DateTime className="mono" value={reviewedAt} evidentiary />
              ) : (
                <span className="muted">{t('documents.import.notIndicated')}</span>
              )}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.review.reviewedBy')}</dt>
            <dd>
              {reviewedBy ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.review.note')}</dt>
            <dd>
              {reviewNote ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
            </dd>
          </div>
          <ImportedDocumentGuardrails document={document} t={t} />
          <div>
            <dt>{t('documents.import.sha256')}</dt>
            <dd>
              <Digest value={document.sha256} />
            </dd>
          </div>
          <div>
            <dt>{t('documents.import.warning')}</dt>
            <dd>{legalNotice}</dd>
          </div>
        </dl>
      </div>
      <CanonicalConversionPreflightEvidence
        preflight={document.canonical_conversion_preflight}
        t={t}
      />
      <ImportedDocumentReviewDepthSummary document={document} t={t} />
      <ImportedDocumentReviewReceipt document={document} t={t} />
      <ImportedDocumentReviewHistory document={document} t={t} />
    </div>
  );
}

function ImportedDocumentGuardrails({
  document,
  t,
}: {
  document: ImportedDocumentView;
  t: TFunction;
}) {
  const policy = document.preservation_policy;
  const canonicalRecordStatus =
    documentMetadataText(document.canonical_record_status) ??
    documentMetadataText(policy?.canonical_record_status);
  const signedArtifactStatus =
    documentMetadataText(document.signed_artifact_status) ??
    documentMetadataText(policy?.signed_artifact_status);
  const checklist = importedGuardrailChecklist(document.review_guardrail_checklist);
  const policyChecklist = importedGuardrailChecklist(policy?.review_guardrail_checklist);
  const guardrails = checklist.length > 0 ? checklist : policyChecklist;
  const canonicalLabel = importedCanonicalRecordStatusLabel(canonicalRecordStatus, t);
  const signedLabel = importedSignedArtifactStatusLabel(signedArtifactStatus, t);

  if (!canonicalLabel && !signedLabel && guardrails.length === 0) return null;

  return (
    <div>
      <dt>{t('documents.import.guardrails.title')}</dt>
      <dd>
        <div className="stack--tight">
          {canonicalLabel ? (
            <p className="row-wrap">
              <Badge tone="warn">{t('documents.import.guardrails.canonical.label')}</Badge>
              <span>{canonicalLabel}</span>
            </p>
          ) : null}
          {signedLabel ? (
            <p className="row-wrap">
              <Badge tone="neutral">{t('documents.import.guardrails.signed.label')}</Badge>
              <span>{signedLabel}</span>
            </p>
          ) : null}
          {guardrails.length > 0 ? (
            <ul className="plain-list">
              {guardrails.map((guardrail) => (
                <li key={guardrail}>{importedGuardrailLabel(guardrail, t)}</li>
              ))}
            </ul>
          ) : null}
        </div>
      </dd>
    </div>
  );
}

function ImportedDocumentReviewForm({
  acknowledged,
  document,
  error,
  isPending,
  note,
  onAcknowledgedChange,
  onNoteChange,
  onStatusChange,
  onSubmit,
  scope,
  status,
}: {
  acknowledged: boolean;
  document: ImportedDocumentView;
  error: unknown;
  isPending: boolean;
  note: string;
  onAcknowledgedChange: (value: boolean) => void;
  onNoteChange: (value: string) => void;
  onStatusChange: (value: ImportedDocumentReviewPatchStatus) => void;
  onSubmit: () => void;
  scope: ReturnType<typeof scopeBook>;
  status: ImportedDocumentReviewPatchStatus;
}) {
  const controlId = `import-review-${documentDownloadSlug(document.id)}`;
  const t = useT();
  const requiredGuardrails = importedRequiredReviewGuardrails(document);
  return (
    <form
      className="form"
      aria-label={t('documents.import.review.formAria')}
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <InlineWarning tone="info" title={t('documents.import.review.conservativeTitle')}>
        {documentMetadataText(document.operator_review_notice) ??
          t('documents.import.review.noticeFallback')}
      </InlineWarning>
      <Field label={t('documents.import.review.statusLabel')} htmlFor={`${controlId}-status`}>
        <Select
          id={`${controlId}-status`}
          value={status}
          options={buildImportedDocumentReviewOptions(t)}
          onChange={(event) =>
            onStatusChange(event.target.value as ImportedDocumentReviewPatchStatus)
          }
        />
      </Field>
      <Field
        label={t('documents.import.review.note')}
        htmlFor={`${controlId}-note`}
        hint={t('documents.import.review.noteHint', {
          count: String(note.length),
          limit: String(IMPORTED_DOCUMENT_REVIEW_NOTE_LIMIT),
        })}
      >
        <TextArea
          id={`${controlId}-note`}
          rows={3}
          maxLength={IMPORTED_DOCUMENT_REVIEW_NOTE_LIMIT}
          value={note}
          onChange={(event) => onNoteChange(event.target.value)}
        />
      </Field>
      <div className="stack--tight">
        <p className="card__label">{t('documents.import.review.guardrailsToAck')}</p>
        <ul className="plain-list">
          {requiredGuardrails.map((guardrail) => (
            <li key={guardrail}>{importedGuardrailLabel(guardrail, t)}</li>
          ))}
        </ul>
        <label className="checkline" htmlFor={`${controlId}-guardrails`}>
          <input
            id={`${controlId}-guardrails`}
            type="checkbox"
            checked={acknowledged}
            disabled={isPending}
            onChange={(event) => onAcknowledgedChange(event.target.checked)}
          />
          {t('documents.import.review.ackLabel')}
        </label>
      </div>
      {error ? <ErrorNote error={error} /> : null}
      <GateButton
        perm="document.generate"
        scope={scope}
        type="submit"
        variant="secondary"
        icon={<Icon.Pencil />}
        disabled={isPending || !acknowledged}
      >
        {isPending ? t('documents.import.review.saving') : t('documents.import.review.save')}
      </GateButton>
    </form>
  );
}

/**
 * Print just the document: toggle `body.printing-doc` so the print-only rules in
 * documents.css isolate the `.doc-preview` subtree, then open the platform print dialog.
 * The class is removed on `afterprint` (and guarded for environments without `print`).
 */
function printDocument() {
  if (typeof window === 'undefined' || typeof window.print !== 'function') return;
  document.body.classList.add('printing-doc');
  const cleanup = () => {
    document.body.classList.remove('printing-doc');
    window.removeEventListener('afterprint', cleanup);
  };
  window.addEventListener('afterprint', cleanup);
  window.print();
}

export function ActDocumentPanel({
  act,
  entityName,
  family,
  target,
}: {
  act: ActView;
  entityName?: string;
  family?: EntityFamily;
  target?: ActDocumentPanelTarget;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
  const handledGeneratedTargetRef = useRef<string | null>(null);
  const handledImportedTargetRef = useRef<string | null>(null);
  const [open, setOpen] = useState(false);
  const [selectedImportId, setSelectedImportId] = useState<string | null>(null);
  const [importError, setImportError] = useState<unknown>(null);
  const [importValidationReport, setImportValidationReport] =
    useState<DocumentImportValidationReport | null>(null);
  const [importValidationPending, setImportValidationPending] = useState(false);
  const [reviewStatus, setReviewStatus] = useState<ImportedDocumentReviewPatchStatus>(
    'reviewed_non_canonical_original_only',
  );
  const [reviewNote, setReviewNote] = useState('');
  const [reviewGuardrailsAcknowledged, setReviewGuardrailsAcknowledged] = useState(false);
  const [selectedGeneratedDocumentId, setSelectedGeneratedDocumentId] = useState<string | null>(
    null,
  );
  const [selectedPostActTemplateId, setSelectedPostActTemplateId] = useState('');
  const [dispatchEvidenceAt, setDispatchEvidenceAt] = useState(localDateTimeInputValue);
  const [dispatchEvidenceChannel, setDispatchEvidenceChannel] = useState<DispatchChannel | ''>('');
  const [dispatchReference, setDispatchReference] = useState('');
  const [dispatchEvidenceReference, setDispatchEvidenceReference] = useState('');
  const [dispatchImportedDocumentId, setDispatchImportedDocumentId] = useState('');
  const [dispatchRecipients, setDispatchRecipients] = useState<string[]>([]);
  const [dispatchOperatorNote, setDispatchOperatorNote] = useState('');

  const signingSnapshotAvailable =
    act.state === 'Signing' || act.state === 'Sealed' || act.state === 'Archived';
  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const reviewScope = scopeBook(act.book_id);
  const preview = useActDocumentPreview(act.id, open);
  const bundle = useActDocumentBundle(act.id, signingSnapshotAvailable);
  const generatedDocuments = useGeneratedDocuments(act.id, !!act.id);
  const convocatoriaTemplates = useTemplates(family, 'Convocatoria', !!family);
  const certidaoTemplates = useTemplates(family, 'Certidao', sealed && !!family);
  const extratoTemplates = useTemplates(family, 'Extrato', sealed && !!family);
  const download = useDownloadActDocument(act.id);
  const workingCopyMarkdownDownload = useDownloadActDocumentWorkingCopy(act.id);
  const workingCopyTextDownload = useDownloadActDocumentWorkingCopy(act.id, 'txt');
  const workingCopyHtmlDownload = useDownloadActDocumentWorkingCopy(act.id, 'html');
  const workingCopyRtfDownload = useDownloadActDocumentWorkingCopy(act.id, 'rtf');
  const workingCopyOdtDownload = useDownloadActDocumentWorkingCopy(act.id, 'odt');
  const officeDownload = useDownloadActDocumentOffice(act.id);
  const reviewImportedDocument = useReviewImportedDocument(act.id);
  const generateActDocument = useGenerateActDocument(act.id);
  const recordGeneratedDispatchEvidence = useRecordGeneratedDocumentDispatchEvidence();
  const importedDocuments = useQuery({
    queryKey: keys.importedDocuments(act.id),
    queryFn: () => listImportedDocumentsForAct(act.id),
  });
  const selectedImportedDocument = useQuery({
    queryKey: keys.importedDocument(selectedImportId ?? ''),
    queryFn: () => api.getImportedDocument(selectedImportId ?? ''),
    enabled: selectedImportId != null,
  });
  const importDocument = useMutation({
    mutationFn: (body: ImportDocumentBody) => api.importDocument(body),
    onSuccess: (document) => {
      queryClient.setQueryData<ImportedDocumentView[]>(keys.importedDocuments(act.id), (current) =>
        mergeImportedDocument(current, document),
      );
      setSelectedImportId(document.id);
      void queryClient.invalidateQueries({ queryKey: keys.importedDocuments(act.id) });
    },
  });
  const importedDownload = useMutation({
    mutationFn: (document: ImportedDocumentView) => api.fetchImportedDocumentBytes(document.id),
  });
  const generatedDownload = useMutation({
    mutationFn: (document: GeneratedDocumentView) => api.fetchGeneratedDocumentPdf(document.id),
  });

  const generatedDocumentTargetId = target?.generatedDocumentId?.trim() || null;
  const generatedDocumentFocusTarget =
    target?.focus === 'dispatch-evidence' ? 'dispatch-evidence' : null;
  const importedDocumentTargetId = target?.importedDocumentId?.trim() || null;
  const importedDocumentFocusTarget = target?.focus === 'import-review' ? 'import-review' : null;
  const importList = useMemo(() => importedDocuments.data ?? [], [importedDocuments.data]);
  const generatedDocumentList = useMemo(
    () => generatedDocuments.data ?? [],
    [generatedDocuments.data],
  );
  const generatedTemplateQueries = sealed
    ? [convocatoriaTemplates, certidaoTemplates, extratoTemplates]
    : [convocatoriaTemplates];
  const generatedTemplateLoading = generatedTemplateQueries.some((query) => query.isLoading);
  const generatedTemplateError =
    generatedTemplateQueries.find((query) => query.error)?.error ?? null;
  const postActTemplates = [
    ...(convocatoriaTemplates.data ?? []),
    ...(sealed ? [...(certidaoTemplates.data ?? []), ...(extratoTemplates.data ?? [])] : []),
  ];
  // Name first so the picker reads as documents rather than slugs; the id stays in the option
  // because two families ship the same document type under different templates.
  const postActTemplateOptions = postActTemplates.map((template) => {
    const name = templateName(template.id);
    return {
      value: template.id,
      // The name already carries the stage ("Certidão de ata", "Convocatória — …"), so repeating
      // the stage label would only pad the option; an unnamed template still needs it.
      label: name
        ? `${name} · ${template.id}`
        : `${lifecycleStageLabel(template.stage, t)} - ${template.id}`,
    };
  });
  const selectedGeneratedDocument =
    generatedDocumentList.find((document) => document.id === selectedGeneratedDocumentId) ?? null;
  const selectedGeneratedDocumentSupportsDispatch =
    selectedGeneratedDocument?.dispatch_evidence_status != null;
  const generatedEvidence = useGeneratedDocumentDispatchEvidence(
    selectedGeneratedDocumentSupportsDispatch ? selectedGeneratedDocument?.id : null,
  );
  const generatedDispatchStatus =
    generatedEvidence.data?.dispatch_evidence_status ??
    selectedGeneratedDocument?.dispatch_evidence_status ??
    null;
  const generatedRequiredRecipients =
    generatedDispatchStatus?.required_recipients ?? EMPTY_GENERATED_RECIPIENTS;
  const generatedRequiredRecipientsSignature = generatedRequiredRecipients.join('\u0000');
  const selectedImportFromList =
    importList.find((document) => document.id === selectedImportId) ?? null;
  const selectedImport = selectedImportedDocument.data ?? selectedImportFromList;
  const selectedImportReviewId = selectedImport?.id;
  const selectedImportReviewStatus = selectedImport?.operator_review_status;
  const selectedImportReviewNote = selectedImport?.operator_review_note;
  const importBusy = importValidationPending || importDocument.isPending;

  useEffect(() => {
    if (!selectedImportReviewId) return;
    setReviewStatus(reviewPatchStatusFromDocument(selectedImportReviewStatus));
    setReviewNote(documentMetadataText(selectedImportReviewNote) ?? '');
    setReviewGuardrailsAcknowledged(false);
  }, [selectedImportReviewId, selectedImportReviewStatus, selectedImportReviewNote]);

  useEffect(() => {
    if (generatedDocumentList.length === 0) {
      setSelectedGeneratedDocumentId(null);
      return;
    }
    if (
      selectedGeneratedDocumentId == null ||
      !generatedDocumentList.some((document) => document.id === selectedGeneratedDocumentId)
    ) {
      setSelectedGeneratedDocumentId(generatedDocumentList[0].id);
    }
  }, [generatedDocumentList, selectedGeneratedDocumentId]);

  useEffect(() => {
    if (postActTemplateOptions.length === 0) {
      setSelectedPostActTemplateId('');
      return;
    }
    if (!postActTemplateOptions.some((option) => option.value === selectedPostActTemplateId)) {
      setSelectedPostActTemplateId(postActTemplateOptions[0].value);
    }
  }, [postActTemplateOptions, selectedPostActTemplateId]);

  useEffect(() => {
    if (generatedDocuments.isLoading || !generatedDocumentTargetId) return;

    const targetKey = `${act.id}:${generatedDocumentTargetId}:${generatedDocumentFocusTarget ?? ''}`;
    if (handledGeneratedTargetRef.current === targetKey) return;

    const target = generatedDocumentList.find(
      (document) => document.id === generatedDocumentTargetId,
    );
    if (!target) return;

    setSelectedGeneratedDocumentId(target.id);
    if (generatedDocumentFocusTarget !== 'dispatch-evidence') {
      handledGeneratedTargetRef.current = targetKey;
      return;
    }

    const focusTarget = () => {
      const control = document.getElementById('generated-dispatch-evidence');
      control?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      control?.focus({ preventScroll: true });
    };

    if (typeof window.requestAnimationFrame === 'function') {
      window.requestAnimationFrame(focusTarget);
    } else {
      window.setTimeout(focusTarget, 0);
    }
    handledGeneratedTargetRef.current = targetKey;
  }, [
    act.id,
    generatedDocuments.isLoading,
    generatedDocumentList,
    generatedDocumentTargetId,
    generatedDocumentFocusTarget,
  ]);

  useEffect(() => {
    if (importedDocuments.isLoading) return;
    if (!importedDocumentTargetId && importedDocumentFocusTarget !== 'import-review') return;

    const targetKey = `${act.id}:${importedDocumentTargetId ?? ''}:${
      importedDocumentFocusTarget ?? ''
    }`;
    if (handledImportedTargetRef.current === targetKey) return;

    const target = importedDocumentTargetId
      ? importList.find((document) => document.id === importedDocumentTargetId)
      : null;
    if (importedDocumentTargetId && !target) return;

    if (target) {
      setSelectedImportId(target.id);
    }

    const focusTarget = () => {
      const control = target
        ? document.getElementById(`import-review-${documentDownloadSlug(target.id)}-status`)
        : null;
      const fallback = document.getElementById('imported-documents');
      const node = control ?? fallback;
      node?.scrollIntoView({ block: 'center', behavior: 'smooth' });
      node?.focus({ preventScroll: true });
    };

    if (typeof window.requestAnimationFrame === 'function') {
      window.requestAnimationFrame(focusTarget);
    } else {
      window.setTimeout(focusTarget, 0);
    }
    handledImportedTargetRef.current = targetKey;
  }, [
    act.id,
    importList,
    importedDocumentFocusTarget,
    importedDocumentTargetId,
    importedDocuments.isLoading,
  ]);

  useEffect(() => {
    setDispatchRecipients(generatedRequiredRecipients);
  }, [
    selectedGeneratedDocument?.id,
    generatedRequiredRecipients,
    generatedRequiredRecipientsSignature,
  ]);

  useEffect(() => {
    setDispatchEvidenceChannel('');
    setDispatchReference('');
    setDispatchEvidenceReference('');
    setDispatchImportedDocumentId('');
    setDispatchOperatorNote('');
  }, [selectedGeneratedDocument?.id]);

  function downloadBaseName() {
    const base = entityName ? `${documentDownloadSlug(entityName)}-` : '';
    const n = act.ata_number != null ? String(act.ata_number) : act.id;
    return `${base}ata-${n}`;
  }

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function onDownload() {
    const filename = `${downloadBaseName()}.pdf`;
    download.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename,
              contentType: 'application/pdf',
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function onDownloadGenerated(document: GeneratedDocumentView) {
    const filename = `${downloadBaseName()}-${generatedDocumentDownloadName(document)}`;
    generatedDownload.mutate(document, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename,
              contentType: 'application/pdf',
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function onDownloadWorkingCopy(format: ActDocumentWorkingCopyFormat, extension: string) {
    const filename = `${downloadBaseName()}-working-copy.${extension}`;
    const mutation = (() => {
      switch (format) {
        case 'txt':
          return workingCopyTextDownload;
        case 'html':
          return workingCopyHtmlDownload;
        case 'rtf':
          return workingCopyRtfDownload;
        case 'odt':
          return workingCopyOdtDownload;
        case 'markdown':
        default:
          return workingCopyMarkdownDownload;
      }
    })();
    mutation.mutate(undefined, {
      onSuccess: async (download) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob: download.blob,
              filename,
              contentType: download.contentType,
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function onDownloadOffice() {
    const filename = `${downloadBaseName()}-office-working-copy.docx`;
    officeDownload.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          showSaveResult(
            await saveBlobAs({
              blob,
              filename,
              contentType:
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  async function onImportFile(file: File) {
    setImportError(null);
    setImportValidationReport(null);
    setImportValidationPending(true);
    try {
      const content_base64 = await readDocumentFileAsBase64(file, t);
      const body: ImportDocumentBody = {
        content_base64,
        content_type: documentMetadataText(file.type),
        filename: documentMetadataText(file.name),
        act_id: act.id,
      };
      const report = await validateImportedDocument(body);
      setImportValidationReport(report);
      if (!report.can_accept_non_canonical_import) {
        toast.error(t('documents.import.toast.validationRejected'));
        return;
      }
      await importDocument.mutateAsync(body);
      toast.success(t('documents.import.toast.success'));
    } catch (e) {
      setImportError(e);
      toast.error(e);
    } finally {
      setImportValidationPending(false);
    }
  }

  async function onDownloadImported(document: ImportedDocumentView) {
    try {
      const blob = await importedDownload.mutateAsync(document);
      showSaveResult(
        await saveBlobAs({
          blob,
          filename: importedDownloadName(document),
          preferBrowserSavePicker: true,
        }),
      );
    } catch (e) {
      toast.error(e);
    }
  }

  function onReviewImportedDocument() {
    if (!selectedImport) return;
    const requiredGuardrails = importedRequiredReviewGuardrails(selectedImport);
    if (!reviewGuardrailsAcknowledged) return;
    const trimmedNote = reviewNote.trim();
    reviewImportedDocument.mutate(
      {
        id: selectedImport.id,
        body: {
          review_status: reviewStatus,
          acknowledged_guardrail_ids: requiredGuardrails,
          review_note: trimmedNote.length > 0 ? trimmedNote : undefined,
        },
      },
      {
        onSuccess: (document) => {
          setSelectedImportId(document.id);
          setReviewGuardrailsAcknowledged(false);
          toast.success(t('documents.import.review.toast.saved'));
        },
        onError: (error) => toast.error(error),
      },
    );
  }

  function onGeneratePostActDocument() {
    if (!selectedPostActTemplateId) return;
    generateActDocument.mutate(selectedPostActTemplateId, {
      onSuccess: (document) => {
        setSelectedGeneratedDocumentId(document.id);
        toast.success(`Documento gerado: ${templateDisplayName(document.template_id)}`);
      },
      onError: (error) => toast.error(error),
    });
  }

  function onRecordGeneratedDispatchEvidence() {
    if (!selectedGeneratedDocument || !selectedGeneratedDocumentSupportsDispatch) return;
    const body: GeneratedDocumentDispatchEvidenceRequest = {
      actor: 'web-operator',
      dispatched_at: localDateTimeToRfc3339(dispatchEvidenceAt),
      channel: dispatchEvidenceChannel || null,
      reference: trimDocumentTextOrNull(dispatchReference),
      recipients: dispatchRecipients,
      evidence_reference: trimDocumentTextOrNull(dispatchEvidenceReference),
      imported_document_id: trimDocumentTextOrNull(dispatchImportedDocumentId),
      operator_note: trimDocumentTextOrNull(dispatchOperatorNote),
    };
    recordGeneratedDispatchEvidence.mutate(
      { documentId: selectedGeneratedDocument.id, body },
      {
        onSuccess: () => {
          setDispatchReference('');
          setDispatchEvidenceReference('');
          setDispatchImportedDocumentId('');
          setDispatchOperatorNote('');
          toast.success(t('documents.generated.form.toast.success'));
        },
        onError: (error) => toast.error(error),
      },
    );
  }

  return (
    <Card title={t('documents.title')}>
      <div className="stack--tight">
        {!signingSnapshotAvailable && family ? (
          <TemplatePicker family={family} stage="Ata" />
        ) : null}

        {/* Frozen Signing snapshot/download, gated on the DOC-03 bundle actually existing. */}
        {signingSnapshotAvailable ? (
          bundle.isLoading ? (
            <Skeleton height="2.4rem" />
          ) : bundle.data ? (
            <div className="stack--tight">
              <div className="rowline">
                <Button
                  type="button"
                  variant="primary"
                  icon={<Icon.FileText />}
                  disabled={download.isPending}
                  onClick={onDownload}
                >
                  {download.isPending ? t('documents.download.pending') : t('documents.download')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  title={t('documents.download.workingCopyHint')}
                  disabled={workingCopyMarkdownDownload.isPending}
                  onClick={() => onDownloadWorkingCopy('markdown', 'md')}
                >
                  {workingCopyMarkdownDownload.isPending
                    ? t('documents.download.pending')
                    : t('documents.download.markdown')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  title={t('documents.download.workingCopyHint')}
                  disabled={workingCopyTextDownload.isPending}
                  onClick={() => onDownloadWorkingCopy('txt', 'txt')}
                >
                  {workingCopyTextDownload.isPending
                    ? t('documents.download.pending')
                    : t('documents.download.txt')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  title={t('documents.download.workingCopyHint')}
                  disabled={workingCopyHtmlDownload.isPending}
                  onClick={() => onDownloadWorkingCopy('html', 'html')}
                >
                  {workingCopyHtmlDownload.isPending
                    ? t('documents.download.pending')
                    : t('documents.download.html')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  title={t('documents.download.workingCopyHint')}
                  disabled={workingCopyRtfDownload.isPending}
                  onClick={() => onDownloadWorkingCopy('rtf', 'rtf')}
                >
                  {workingCopyRtfDownload.isPending
                    ? t('documents.download.pending')
                    : t('documents.download.rtf')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  title={t('documents.download.workingCopyHint')}
                  disabled={workingCopyOdtDownload.isPending}
                  onClick={() => onDownloadWorkingCopy('odt', 'odt')}
                >
                  {workingCopyOdtDownload.isPending
                    ? t('documents.download.pending')
                    : t('documents.download.odt')}
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.FileText />}
                  title={t('documents.download.workingCopyHint')}
                  disabled={officeDownload.isPending}
                  onClick={onDownloadOffice}
                >
                  {officeDownload.isPending
                    ? t('documents.download.pending')
                    : t('documents.download.docx')}
                </Button>
              </div>
              <p className="field__hint">{t('documents.download.workingCopyHint')}</p>
              <ActDocumentMetadata document={bundle.data.document} t={t} />
              <DocumentPdfAccessibilityEvidence
                validationReport={bundle.data.validation_report}
                t={t}
              />
              <p className="doc-integrity">
                <span>{t('documents.digest.label')}</span>
                <Digest value={bundle.data.document.pdf_digest} />
              </p>
            </div>
          ) : isNoDocumentTemplate(bundle.error) || bundle.error ? (
            <InlineWarning tone="info" title={t('documents.download.noneTitle')}>
              {t('documents.download.noneBody')}
            </InlineWarning>
          ) : null
        ) : null}

        {family ||
        generatedDocumentList.length > 0 ||
        generatedDocuments.isLoading ||
        generatedDocuments.error ? (
          <section className="stack--tight" aria-label={t('documents.generated.sectionAria')}>
            {family ? (
              <div className="stack--tight">
                <div className="section-head">
                  <div className="stack--tight">
                    <p className="card__label">{t('uiLiteral.actDocumentPanel.minutasGeradas')}</p>
                    <p className="field__hint">
                      {' '}
                      {t('uiLiteral.actDocumentPanel.gereConvocatoriasEAposOSeloCertidoesE')}{' '}
                    </p>
                  </div>
                </div>
                {generatedTemplateLoading ? (
                  <Skeleton height="2.4rem" />
                ) : generatedTemplateError ? (
                  <ErrorNote error={generatedTemplateError} />
                ) : postActTemplateOptions.length === 0 ? (
                  <p className="muted">{t('documents.template.none')}</p>
                ) : (
                  <div className="row-wrap">
                    <Field label={t('templates.card.id')} htmlFor="post-act-template">
                      <Select
                        id="post-act-template"
                        value={selectedPostActTemplateId}
                        options={postActTemplateOptions}
                        disabled={generateActDocument.isPending}
                        onChange={(event) => setSelectedPostActTemplateId(event.target.value)}
                      />
                    </Field>
                    <GateButton
                      perm="document.generate"
                      scope={reviewScope}
                      type="button"
                      variant="secondary"
                      icon={<Icon.FileText />}
                      disabled={!selectedPostActTemplateId || generateActDocument.isPending}
                      onClick={onGeneratePostActDocument}
                    >
                      {generateActDocument.isPending ? 'A gerar...' : 'Gerar documento'}
                    </GateButton>
                  </div>
                )}
              </div>
            ) : null}

            <div className="section-head">
              <div className="stack--tight">
                <p className="card__label">{t('documents.generated.title')}</p>
                <p className="field__hint">{t('documents.generated.notice')}</p>
              </div>
              <Badge tone="neutral">{t('documents.generated.noClaim.badge')}</Badge>
            </div>

            {generatedDocuments.isLoading ? (
              <Skeleton height="5.5rem" />
            ) : generatedDocuments.error ? (
              <ErrorNote error={generatedDocuments.error} />
            ) : generatedDocumentList.length === 0 ? (
              <EmptyState title={t('documents.generated.empty.title')}>
                <p>{t('documents.generated.empty.body')}</p>
              </EmptyState>
            ) : (
              <ul className="plain-list" aria-label={t('documents.generated.listAria')}>
                {generatedDocumentList.map((document) => {
                  const selected = selectedGeneratedDocument?.id === document.id;
                  const status =
                    selected && generatedDispatchStatus
                      ? generatedDispatchStatus
                      : document.dispatch_evidence_status;
                  return (
                    <li className="chainrow" key={document.id} aria-current={selected || undefined}>
                      <div className="section-head">
                        <div className="stack--tight">
                          <p className="row-wrap">
                            <Badge tone={generatedDispatchStatusTone(status)}>
                              {generatedDispatchStatusLabel(status, t)}
                            </Badge>
                            {/* The raw id stays one row down in the deflist below. */}
                            <Truncate text={templateDisplayName(document.template_id)} />
                          </p>
                          <dl className="deflist deflist--tight">
                            <div>
                              <dt>{t('documents.metadata.document')}</dt>
                              <dd>
                                <Truncate text={document.id} mono />
                              </dd>
                            </div>
                            <div>
                              <dt>{t('documents.metadata.template')}</dt>
                              <dd>
                                <Truncate text={document.template_id} mono />
                              </dd>
                            </div>
                            <div>
                              <dt>{t('documents.metadata.profile')}</dt>
                              <dd>{document.profile}</dd>
                            </div>
                            <div>
                              <dt>{t('documents.metadata.generatedAt')}</dt>
                              <dd>
                                <DateTime
                                  className="mono"
                                  value={document.created_at}
                                  evidentiary
                                />
                              </dd>
                            </div>
                            <div>
                              <dt>{t('documents.digest.label')}</dt>
                              <dd>
                                <Digest value={document.pdf_digest} />
                              </dd>
                            </div>
                            <div>
                              <dt>{t('documents.generated.downloadPath')}</dt>
                              <dd>
                                <Truncate text={document.download} mono />
                              </dd>
                            </div>
                          </dl>
                        </div>
                        <div className="row-wrap">
                          <Button
                            type="button"
                            variant={selected ? 'primary' : 'secondary'}
                            icon={<Icon.FileText />}
                            onClick={() => setSelectedGeneratedDocumentId(document.id)}
                          >
                            {t('documents.generated.viewEvidence')}
                          </Button>
                          <Button
                            type="button"
                            variant="ghost"
                            icon={<Icon.Tray />}
                            disabled={generatedDownload.isPending}
                            onClick={() => onDownloadGenerated(document)}
                          >
                            {t('documents.generated.download')}
                          </Button>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}

            {selectedGeneratedDocument ? (
              <div className="stack--tight">
                {selectedGeneratedDocumentSupportsDispatch ? (
                  <>
                    <GeneratedDispatchStatusSummary status={generatedDispatchStatus} t={t} />
                    {generatedEvidence.isLoading ? (
                      <Skeleton height="5rem" />
                    ) : generatedEvidence.error ? (
                      <ErrorNote error={generatedEvidence.error} />
                    ) : (
                      <GeneratedDispatchEvidenceRows
                        evidence={generatedEvidence.data}
                        importList={importList}
                        onSelectImport={setSelectedImportId}
                        t={t}
                      />
                    )}
                    <GeneratedDispatchEvidenceForm
                      status={generatedDispatchStatus}
                      importList={importList}
                      dispatchedAt={dispatchEvidenceAt}
                      channel={dispatchEvidenceChannel}
                      reference={dispatchReference}
                      evidenceReference={dispatchEvidenceReference}
                      importedDocumentId={dispatchImportedDocumentId}
                      recipients={dispatchRecipients}
                      operatorNote={dispatchOperatorNote}
                      isPending={recordGeneratedDispatchEvidence.isPending}
                      error={recordGeneratedDispatchEvidence.error}
                      scope={reviewScope}
                      onDispatchedAtChange={setDispatchEvidenceAt}
                      onChannelChange={setDispatchEvidenceChannel}
                      onReferenceChange={setDispatchReference}
                      onEvidenceReferenceChange={setDispatchEvidenceReference}
                      onImportedDocumentIdChange={setDispatchImportedDocumentId}
                      onRecipientsChange={setDispatchRecipients}
                      onOperatorNoteChange={setDispatchOperatorNote}
                      onSubmit={onRecordGeneratedDispatchEvidence}
                    />
                  </>
                ) : null}
              </div>
            ) : null}
          </section>
        ) : null}

        <section
          className="stack--tight"
          id="imported-documents"
          tabIndex={-1}
          aria-label={t('documents.import.sectionAria')}
        >
          <div className="section-head">
            <div className="stack--tight">
              <p className="card__label">{t('documents.import.title')}</p>
              <p className="field__hint">{t('documents.import.notice')}</p>
              <p className="field__hint">{t('documents.import.serverValidation')}</p>
            </div>
            <Badge tone="warn">{t('documents.import.nonCanonicalEvidence')}</Badge>
          </div>

          <div className="row-wrap">
            <label className="btn btn--secondary btn--icon file-btn">
              <span className="btn__icon">
                <Icon.Tray />
              </span>
              {importBusy ? t('documents.import.pending') : t('documents.import.choose')}
              <input
                type="file"
                className="sr-only"
                disabled={importBusy}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void onImportFile(file);
                  e.target.value = '';
                }}
              />
            </label>
          </div>

          {importError ? <ErrorNote error={importError} /> : null}
          <DocumentImportValidationEvidence report={importValidationReport} t={t} />

          {importedDocuments.isLoading ? (
            <Skeleton height="4.5rem" />
          ) : importedDocuments.error ? (
            <ErrorNote error={importedDocuments.error} />
          ) : importList.length === 0 ? (
            <EmptyState title={t('documents.import.empty.title')}>
              <p>{t('documents.import.empty.body')}</p>
            </EmptyState>
          ) : (
            <ul className="plain-list" aria-label={t('documents.import.listAria')}>
              {importList.map((document) => {
                const displayName = importedDisplayName(document, t);
                const detectedType = documentMetadataText(document.detected_content_type);
                const importedAt = documentMetadataText(document.imported_at);
                const selected = selectedImportId === document.id;
                return (
                  <li className="chainrow" key={document.id} aria-current={selected || undefined}>
                    <div className="section-head">
                      <div className="stack--tight">
                        <p className="row-wrap">
                          <Badge tone={document.non_canonical ? 'warn' : 'neutral'}>
                            {document.non_canonical
                              ? t('documents.import.nonCanonical')
                              : t('documents.import.imported')}
                          </Badge>
                          <Badge tone={importedReviewStatusTone(document.operator_review_status)}>
                            {importedReviewStatusLabel(document.operator_review_status, t)}
                          </Badge>
                          <Truncate text={displayName} />
                        </p>
                        <p className="chainrow__meta">
                          {formatDocumentBytes(document.size_bytes, t)}
                          {detectedType ? ` · ${detectedType}` : ''}
                          {importedAt ? (
                            <>
                              {' · '}
                              <DateTime value={importedAt} evidentiary />
                            </>
                          ) : null}
                        </p>
                      </div>
                      <div className="row-wrap">
                        <Button
                          type="button"
                          variant={selected ? 'primary' : 'secondary'}
                          icon={<Icon.FileText />}
                          onClick={() => setSelectedImportId(document.id)}
                        >
                          {t('documents.import.viewMetadata')}
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          icon={<Icon.Tray />}
                          disabled={importedDownload.isPending}
                          onClick={() => void onDownloadImported(document)}
                        >
                          {t('documents.import.download')}
                        </Button>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}

          {selectedImportId ? (
            <div className="stack--tight">
              <ImportedDocumentDetails
                document={selectedImport}
                error={selectedImportedDocument.error}
                isLoading={selectedImportedDocument.isLoading}
                t={t}
              />
              {selectedImport ? (
                <ImportedDocumentReviewForm
                  acknowledged={reviewGuardrailsAcknowledged}
                  document={selectedImport}
                  error={reviewImportedDocument.error}
                  isPending={reviewImportedDocument.isPending}
                  note={reviewNote}
                  onAcknowledgedChange={setReviewGuardrailsAcknowledged}
                  onNoteChange={setReviewNote}
                  onStatusChange={setReviewStatus}
                  onSubmit={onReviewImportedDocument}
                  scope={reviewScope}
                  status={reviewStatus}
                />
              ) : null}
            </div>
          ) : null}
        </section>

        {/* Live preview toggle — works pre- and post-seal (renders the current record). */}
        <div className="rowline">
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.FileText />}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? t('documents.preview.hide') : t('documents.preview.show')}
          </Button>
          {open && preview.data ? (
            <Button type="button" variant="ghost" icon={<Icon.Printer />} onClick={printDocument}>
              {t('documents.print')}
            </Button>
          ) : null}
        </div>

        {open ? (
          <div className="stack--tight">
            <p className="field__hint">{t('documents.preview.hint')}</p>
            {preview.isLoading ? (
              <Skeleton height="12rem" />
            ) : isNoDocumentTemplate(preview.error) ? (
              <InlineWarning tone="info" title={t('documents.preview.noTemplate.title')}>
                {t('documents.preview.noTemplate.body')}
              </InlineWarning>
            ) : preview.error ? (
              <ErrorNote error={preview.error} />
            ) : preview.data ? (
              <DocumentPreview doc={preview.data} />
            ) : null}
          </div>
        ) : null}
      </div>
    </Card>
  );
}
