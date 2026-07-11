/**
 * ActDocumentPanel — the document surface mounted on the ata editor (plan t48-e6).
 *
 * Composes the three deliverables into one card on the act screen:
 *   • the template picker (which model applies — informational, pre-seal);
 *   • the live draft preview ("Pré-visualizar") that renders the server `DocumentModel`
 *     so the operator sees the document as they fill the record — including an HONEST
 *     "sem modelo disponível" state when the family has no template (the endpoint 422s);
 *   • the post-seal PDF/A download, gated on the DOC-03 bundle actually existing (so a
 *     sealed act whose family has no template shows an honest "não gerado" note, not a
 *     broken download), with the pdf digest surfaced as an integrity note.
 *
 * Reads render inline errors only; the one mutation here (the download) follows the toast
 * idiom (success + error) per CONVENTIONS §2/§3.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import type {
  ActView,
  DocumentImportValidationFinding,
  DocumentImportValidationReport,
  EntityFamily,
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
  useReviewImportedDocument,
  keys,
} from '../../api/hooks';
import { GateButton, scopeBook } from '../session/permissions';
import { useT, type TFunction } from '../../i18n';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  Badge,
  Button,
  Card,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Select,
  Skeleton,
  TextArea,
  Truncate,
  useToast,
} from '../../ui';
import { DocumentPreview } from './DocumentPreview';
import { TemplatePicker } from './TemplatePicker';
import './documents.css';

/** A 422/404 from the document endpoints is the "family has no template" signal. */
function isNoTemplate(error: unknown): boolean {
  return error instanceof ApiError && (error.status === 422 || error.status === 404);
}

/** Slugify an entity/title fragment for a filesystem-friendly download name. */
function slug(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[̀-ͯ]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

async function listImportedDocumentsForAct(actId: string): Promise<ImportedDocumentView[]> {
  try {
    return await api.listImportedDocuments({ act_id: actId });
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return [];
    throw e;
  }
}

async function validateImportedDocument(
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

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function readFileAsBase64(file: File, t: TFunction): Promise<string> {
  if (typeof FileReader === 'undefined') {
    return file.arrayBuffer().then(arrayBufferToBase64);
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

function metadataText(value: unknown): string | null {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : null;
}

function formatBytes(value: number, t: TFunction): string {
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

function importedDisplayName(document: ImportedDocumentView, t: TFunction): string {
  return metadataText(document.filename) ?? t('documents.import.unnamed');
}

function importedDownloadName(document: ImportedDocumentView): string {
  return metadataText(document.filename) ?? `documento-importado-${slug(document.id)}.bin`;
}

const IMPORTED_DOCUMENT_REVIEW_NOTICE =
  'A revisão regista apenas uma decisão de preservação operacional; não executa OCR, não converte bytes, não substitui o PDF/A canónico e não declara aceitação legal.';
const IMPORTED_DOCUMENT_REVIEW_NOTE_LIMIT = 2000;
const FALLBACK_IMPORTED_DOCUMENT_REVIEW_GUARDRAILS: ImportedDocumentReviewGuardrail[] = [
  'preserved_original_bytes_remain_non_canonical_evidence',
  'canonical_pdfa_record_is_not_replaced',
  'signed_pdf_artifact_is_not_created_or_validated',
  'ocr_or_conversion_output_is_not_promoted_to_canonical_records',
];

const importedDocumentReviewOptions: {
  value: ImportedDocumentReviewPatchStatus;
  label: string;
}[] = [
  {
    value: 'reviewed_non_canonical_original_only',
    label: 'Revisto: original preservado apenas como evidência não canónica',
  },
  {
    value: 'rejected_non_canonical_evidence',
    label: 'Rejeitado como evidência não canónica',
  },
];

function importedReviewStatusLabel(status: unknown): string {
  switch (metadataText(status)) {
    case 'operator_review_required':
      return 'Revisão do operador necessária';
    case 'ocr_review_required':
      return 'Revisão do operador necessária para imagem preservada';
    case 'canonical_conversion_review_required':
      return 'Revisão do operador necessária para ficheiro legado';
    case 'reviewed_non_canonical_original_only':
      return 'Revisto: original preservado apenas como evidência não canónica';
    case 'rejected_non_canonical_evidence':
      return 'Rejeitado como evidência não canónica';
    default:
      return metadataText(status) ?? 'Revisão não indicada';
  }
}

function importedReviewStatusTone(status: unknown): 'neutral' | 'warn' | 'error' | 'ok' {
  switch (metadataText(status)) {
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

function importedCanonicalRecordStatusLabel(status: unknown, t: TFunction): string | null {
  switch (metadataText(status)) {
    case 'not_canonical_record':
      return t('documents.import.guardrails.canonical.notCanonical');
    case null:
      return null;
    default:
      return metadataText(status);
  }
}

function importedSignedArtifactStatusLabel(status: unknown, t: TFunction): string | null {
  switch (metadataText(status)) {
    case 'not_signed_artifact':
      return t('documents.import.guardrails.signed.notSigned');
    case null:
      return null;
    default:
      return metadataText(status);
  }
}

function importedGuardrailChecklist(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const text = metadataText(item);
    return text ? [text] : [];
  });
}

function uniqueImportedGuardrails(guardrails: string[]): ImportedDocumentReviewGuardrail[] {
  return Array.from(new Set(guardrails)) as ImportedDocumentReviewGuardrail[];
}

function importedRequiredReviewGuardrails(
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

function importedGuardrailLabel(guardrail: string, t: TFunction): string {
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

function importedAcknowledgedReviewGuardrails(
  document: ImportedDocumentView,
): ImportedDocumentReviewGuardrail[] {
  return uniqueImportedGuardrails(importedGuardrailChecklist(document.acknowledged_guardrail_ids));
}

function importedDocumentHasReviewReceipt(document: ImportedDocumentView): boolean {
  const status = metadataText(document.operator_review_status);
  if (
    status === 'reviewed_non_canonical_original_only' ||
    status === 'rejected_non_canonical_evidence'
  ) {
    return true;
  }

  return (
    metadataText(document.operator_reviewed_at) != null ||
    metadataText(document.operator_reviewed_by) != null ||
    metadataText(document.operator_review_note) != null ||
    importedAcknowledgedReviewGuardrails(document).length > 0
  );
}

function reviewPatchStatusFromDocument(
  status: ImportedDocumentView['operator_review_status'] | undefined,
): ImportedDocumentReviewPatchStatus {
  return status === 'rejected_non_canonical_evidence'
    ? 'rejected_non_canonical_evidence'
    : 'reviewed_non_canonical_original_only';
}

function mergeImportedDocument(
  current: ImportedDocumentView[] | undefined,
  document: ImportedDocumentView,
): ImportedDocumentView[] {
  const existing = current ?? [];
  return [document, ...existing.filter((item) => item.id !== document.id)];
}

function yesNo(value: boolean, t: TFunction): string {
  return value ? t('common.yes') : t('common.no');
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
                <dd>{yesNo(legacyWord.is_ole_cfb, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.legacyDoc')}</dt>
                <dd>{yesNo(legacyWord.is_legacy_word_doc, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.macrosExecuted')}</dt>
                <dd>{yesNo(legacyWord.macro_execution_performed, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.conversion')}</dt>
                <dd>{yesNo(legacyWord.conversion_performed, t)}</dd>
              </div>
              <div>
                <dt>{t('documents.import.legacyWord.canonicalPdfa')}</dt>
                <dd>{yesNo(legacyWord.canonical_pdfa_generated, t)}</dd>
              </div>
            </dl>
          ) : null}

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
  const reviewedAt = metadataText(document.operator_reviewed_at);
  const reviewedBy = metadataText(document.operator_reviewed_by);
  const reviewNote = metadataText(document.operator_review_note);
  const receiptStatus = hasReceipt
    ? importedReviewStatusLabel(document.operator_review_status)
    : 'Sem recibo de revisão';

  return (
    <div className="stack--tight" role="group" aria-label="Recibo de revisão">
      <p className="card__label">Recibo de revisão</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>Estado do recibo</dt>
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
              <dt>Revisto em</dt>
              <dd>
                {reviewedAt ? (
                  <time className="mono" dateTime={reviewedAt}>
                    {reviewedAt}
                  </time>
                ) : (
                  <span className="muted">Não indicado no recibo</span>
                )}
              </dd>
            </div>
            <div>
              <dt>Revisto por</dt>
              <dd>{reviewedBy ?? <span className="muted">Não indicado no recibo</span>}</dd>
            </div>
            <div>
              <dt>Nota registada</dt>
              <dd>{reviewNote ?? <span className="muted">Sem nota registada</span>}</dd>
            </div>
            <div>
              <dt>Limites exigidos</dt>
              <dd>
                <GuardrailList
                  empty="Sem limites exigidos indicados"
                  guardrails={requiredGuardrails}
                  t={t}
                />
              </dd>
            </div>
            <div>
              <dt>Limites reconhecidos</dt>
              <dd>
                <GuardrailList
                  empty="Sem limites reconhecidos no recibo"
                  guardrails={acknowledgedGuardrails}
                  t={t}
                />
              </dd>
            </div>
          </>
        ) : null}
        <div>
          <dt>OCR</dt>
          <dd>
            <Badge tone="neutral">Não</Badge> Não efetuado por esta revisão.
          </dd>
        </div>
        <div>
          <dt>Conversão</dt>
          <dd>
            <Badge tone="neutral">Não</Badge> Não efetuada por esta revisão.
          </dd>
        </div>
        <div>
          <dt>Substituição do PDF/A canónico</dt>
          <dd>
            <Badge tone="neutral">Não</Badge> Não substituído por este documento.
          </dd>
        </div>
        <div>
          <dt>PDF assinado</dt>
          <dd>
            <Badge tone="neutral">Não</Badge> Não criado nem validado por esta revisão.
          </dd>
        </div>
        <div>
          <dt>Aceitação legal</dt>
          <dd>
            <Badge tone="neutral">Não</Badge> Não declarada por esta revisão.
          </dd>
        </div>
      </dl>
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
  const reviewNote = metadataText(document.operator_review_note);
  const originalBytesStatus = metadataText(
    document.preservation_policy?.original_bytes_preservation_status,
  );
  const originalBytesSummary = originalBytesStatus
    ? `Bytes preservados (${originalBytesStatus})`
    : 'Preservação dos bytes originais não indicada nos metadados carregados';
  const hasReceipt = importedDocumentHasReviewReceipt(document);

  return (
    <div
      className="stack--tight"
      role="group"
      aria-label="Resumo de profundidade da revisão importada"
    >
      <p className="card__label">Resumo de profundidade da revisão</p>
      <dl className="deflist deflist--tight">
        <div>
          <dt>Inclui</dt>
          <dd>
            {originalBytesSummary}, digest SHA-256, estado de revisão{' '}
            {hasReceipt ? 'registado' : 'pendente'} e nota do operador{' '}
            {reviewNote ? 'registada' : 'não indicada'}.
          </dd>
        </div>
        <div>
          <dt>Digest revisto</dt>
          <dd>
            <Digest value={document.sha256} />
          </dd>
        </div>
        <div>
          <dt>Estado derivado</dt>
          <dd>
            <Badge tone={importedReviewStatusTone(document.operator_review_status)}>
              {importedReviewStatusLabel(document.operator_review_status)}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>Nota do operador</dt>
          <dd>
            {reviewNote ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
          </dd>
        </div>
        <div>
          <dt>Exclui</dt>
          <dd>
            OCR, conversão, substituição de PDF/A, PDF assinado, validação de assinatura, selo,
            PDF/UA e aceitação legal.
          </dd>
        </div>
        <div>
          <dt>Flags sem reivindicação</dt>
          <dd>
            OCR: não · conversão: não · PDF/A substituído: não · PDF assinado: não · assinatura: não
            · selo: não · PDF/UA: não · aceitação legal: não.
          </dd>
        </div>
      </dl>
    </div>
  );
}

function MetadataValue({ value, missing }: { value: unknown; missing: string }) {
  const text = metadataText(value);
  if (!text) return <span className="muted">{missing}</span>;
  return <Truncate text={text} mono />;
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
  const createdAt = metadataText(document.created_at);
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
            <MetadataValue value={document.template_id} missing={t('documents.metadata.missing')} />
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
            {createdAt ? (
              <time className="mono" dateTime={createdAt}>
                {createdAt}
              </time>
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

  const filename = metadataText(document.filename);
  const importedAt = metadataText(document.imported_at);
  const declaredType = metadataText(document.declared_content_type);
  const detectedType = metadataText(document.detected_content_type);
  const importedBy = metadataText(document.imported_by);
  const legalNotice = metadataText(document.legal_notice) ?? t('documents.import.notice');
  const reviewNotice =
    metadataText(document.operator_review_notice) ?? IMPORTED_DOCUMENT_REVIEW_NOTICE;
  const reviewedAt = metadataText(document.operator_reviewed_at);
  const reviewedBy = metadataText(document.operator_reviewed_by);
  const reviewNote = metadataText(document.operator_review_note);

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
            <dd>{formatBytes(document.size_bytes, t)}</dd>
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
              {importedAt ? (
                <time className="mono" dateTime={importedAt}>
                  {importedAt}
                </time>
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
            <dt>Revisão do operador</dt>
            <dd>
              <Badge tone={importedReviewStatusTone(document.operator_review_status)}>
                {importedReviewStatusLabel(document.operator_review_status)}
              </Badge>
            </dd>
          </div>
          <div>
            <dt>Aviso de revisão</dt>
            <dd>{reviewNotice}</dd>
          </div>
          <div>
            <dt>Revisto em</dt>
            <dd>
              {reviewedAt ? (
                <time className="mono" dateTime={reviewedAt}>
                  {reviewedAt}
                </time>
              ) : (
                <span className="muted">{t('documents.import.notIndicated')}</span>
              )}
            </dd>
          </div>
          <div>
            <dt>Revisto por</dt>
            <dd>
              {reviewedBy ?? <span className="muted">{t('documents.import.notIndicated')}</span>}
            </dd>
          </div>
          <div>
            <dt>Nota da revisão</dt>
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
      <ImportedDocumentReviewDepthSummary document={document} t={t} />
      <ImportedDocumentReviewReceipt document={document} t={t} />
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
    metadataText(document.canonical_record_status) ?? metadataText(policy?.canonical_record_status);
  const signedArtifactStatus =
    metadataText(document.signed_artifact_status) ?? metadataText(policy?.signed_artifact_status);
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
  const controlId = `import-review-${slug(document.id)}`;
  const t = useT();
  const requiredGuardrails = importedRequiredReviewGuardrails(document);
  return (
    <form
      className="form"
      aria-label="Revisão operacional do documento importado"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      <InlineWarning tone="info" title="Revisão conservadora">
        {metadataText(document.operator_review_notice) ?? IMPORTED_DOCUMENT_REVIEW_NOTICE}
      </InlineWarning>
      <Field label="Estado de revisão" htmlFor={`${controlId}-status`}>
        <Select
          id={`${controlId}-status`}
          value={status}
          options={importedDocumentReviewOptions}
          onChange={(event) =>
            onStatusChange(event.target.value as ImportedDocumentReviewPatchStatus)
          }
        />
      </Field>
      <Field
        label="Nota da revisão"
        htmlFor={`${controlId}-note`}
        hint={`${note.length}/${IMPORTED_DOCUMENT_REVIEW_NOTE_LIMIT} caracteres. Registe apenas a decisão operacional; não declare OCR, conversão ou aceitação legal.`}
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
        <p className="card__label">Limites a reconhecer</p>
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
          Confirmo que revi estes limites e que a decisão não promove o documento importado a
          registo canónico, PDF/A substituto, PDF assinado ou aceitação legal.
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
        {isPending ? 'A guardar revisão' : 'Guardar revisão'}
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
}: {
  act: ActView;
  entityName?: string;
  family?: EntityFamily;
}) {
  const t = useT();
  const toast = useToast();
  const queryClient = useQueryClient();
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

  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const reviewScope = scopeBook(act.book_id);
  const preview = useActDocumentPreview(act.id, open);
  const bundle = useActDocumentBundle(act.id, sealed);
  const download = useDownloadActDocument(act.id);
  const workingCopyMarkdownDownload = useDownloadActDocumentWorkingCopy(act.id);
  const workingCopyTextDownload = useDownloadActDocumentWorkingCopy(act.id, 'txt');
  const workingCopyHtmlDownload = useDownloadActDocumentWorkingCopy(act.id, 'html');
  const workingCopyRtfDownload = useDownloadActDocumentWorkingCopy(act.id, 'rtf');
  const workingCopyOdtDownload = useDownloadActDocumentWorkingCopy(act.id, 'odt');
  const officeDownload = useDownloadActDocumentOffice(act.id);
  const reviewImportedDocument = useReviewImportedDocument(act.id);
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

  const importList = importedDocuments.data ?? [];
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
    setReviewNote(metadataText(selectedImportReviewNote) ?? '');
    setReviewGuardrailsAcknowledged(false);
  }, [selectedImportReviewId, selectedImportReviewStatus, selectedImportReviewNote]);

  function downloadBaseName() {
    const base = entityName ? `${slug(entityName)}-` : '';
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
      const content_base64 = await readFileAsBase64(file, t);
      const body: ImportDocumentBody = {
        content_base64,
        content_type: metadataText(file.type),
        filename: metadataText(file.name),
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
          toast.success('Revisão do documento importado guardada.');
        },
        onError: (error) => toast.error(error),
      },
    );
  }

  return (
    <Card title={t('documents.title')}>
      <div className="stack--tight">
        {!sealed && family ? <TemplatePicker family={family} stage="Ata" /> : null}

        {/* Post-seal download, gated on the DOC-03 bundle actually existing. */}
        {sealed ? (
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
              <p className="doc-integrity">
                <span>{t('documents.digest.label')}</span>
                <Digest value={bundle.data.document.pdf_digest} />
              </p>
            </div>
          ) : isNoTemplate(bundle.error) || bundle.error ? (
            <InlineWarning tone="info" title={t('documents.download.noneTitle')}>
              {t('documents.download.noneBody')}
            </InlineWarning>
          ) : null
        ) : null}

        <section className="stack--tight" aria-label={t('documents.import.sectionAria')}>
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
                const detectedType = metadataText(document.detected_content_type);
                const importedAt = metadataText(document.imported_at);
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
                            {importedReviewStatusLabel(document.operator_review_status)}
                          </Badge>
                          <Truncate text={displayName} />
                        </p>
                        <p className="chainrow__meta">
                          {formatBytes(document.size_bytes, t)}
                          {detectedType ? ` · ${detectedType}` : ''}
                          {importedAt ? (
                            <>
                              {' · '}
                              <time dateTime={importedAt}>{importedAt}</time>
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
            ) : isNoTemplate(preview.error) ? (
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
