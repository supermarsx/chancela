import { useState } from 'react';
import type { PdfSignatureValidationResponse } from '../../api/types';
import { useValidatePdfSignature } from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage } from '../../desktop/saveFile';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  InlineWarning,
  SkeletonRegion,
  SkeletonTable,
  useToast,
} from '../../ui';
import {
  formatPdfValidatorBytes,
  pdfValidationStatusLabel,
  pdfValidationStatusTone,
} from './pdfValidatorFormat';
import { PdfValidationResultTable } from './PdfValidationResultTable';

export {
  formatPdfValidatorBytes,
  pdfValidationEvidenceTone,
  pdfValidationFindingTone,
  pdfValidationStatusLabel,
  pdfValidationStatusTone,
  pdfValidatorBoolText,
} from './pdfValidatorFormat';

export function pdfValidatorArrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function pdfValidatorHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function pdfValidatorSha256Hex(buffer: ArrayBuffer): Promise<string | null> {
  if (!globalThis.crypto?.subtle) return null;
  return pdfValidatorHex(await globalThis.crypto.subtle.digest('SHA-256', buffer));
}

export function readPdfValidatorFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(reader.result);
        return;
      }
      reject(new Error('file read did not return bytes'));
    };
    reader.onerror = () => reject(reader.error ?? new Error('file read failed'));
    reader.readAsArrayBuffer(file);
  });
}

export function pdfValidationReportJson(report: PdfSignatureValidationResponse): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export function pdfValidationReportFilename(report: PdfSignatureValidationResponse): string {
  const base = (report.filename ?? 'pdf')
    .replace(/\.pdf$/i, '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
  return `${base || 'pdf'}-validation-report.json`;
}

const arrayBufferToBase64 = pdfValidatorArrayBufferToBase64;
const sha256Hex = pdfValidatorSha256Hex;
const readFileAsArrayBuffer = readPdfValidatorFileAsArrayBuffer;
const formatBytes = formatPdfValidatorBytes;
const statusTone = pdfValidationStatusTone;
const statusLabel = pdfValidationStatusLabel;
const reportJson = pdfValidationReportJson;
const reportFilename = pdfValidationReportFilename;

function ValidationReportActions({ report }: { report: PdfSignatureValidationResponse }) {
  const t = useT();
  const toast = useToast();
  const [saving, setSaving] = useState(false);

  async function copyReport() {
    if (!navigator.clipboard) {
      toast.error(t('data.status.copyUnsupported'));
      return;
    }
    try {
      await navigator.clipboard.writeText(reportJson(report));
      toast.success(t('common.copied'));
    } catch (error) {
      toast.error(error instanceof Error ? error : t('pdfValidator.report.copyFailed'));
    }
  }

  async function downloadReport() {
    setSaving(true);
    try {
      const blob = new Blob([reportJson(report)], { type: 'application/json;charset=utf-8' });
      const result = await saveBlobAs({
        blob,
        filename: reportFilename(report),
        contentType: 'application/json;charset=utf-8',
        filters: [{ name: 'JSON', extensions: ['json'] }],
        preferBrowserSavePicker: true,
      });
      if (result.kind === 'cancelled') {
        toast.info(saveBlobResultMessage(result));
        return;
      }
      toast.success(saveBlobResultMessage(result));
    } catch (error) {
      toast.error(error);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="pdf-validator-report-actions">
      <p className="pdf-validator-status">{t('pdfValidator.report.status')}</p>
      <div className="pdf-validator-action-buttons">
        <IconButton
          icon={<Icon.Copy />}
          label={t('pdfValidator.report.copyJson')}
          variant="secondary"
          onClick={() => void copyReport()}
        />
        <IconButton
          icon={<Icon.Save />}
          label={saving ? t('common.saving') : t('pdfValidator.report.saveJson')}
          variant="secondary"
          disabled={saving}
          onClick={() => void downloadReport()}
        />
      </div>
    </div>
  );
}

function ValidationReport({ report }: { report: PdfSignatureValidationResponse }) {
  const t = useT();
  const mismatch =
    (report.declared_sha256 && report.declared_sha256 !== report.sha256) ||
    (report.declared_size_bytes !== null && report.declared_size_bytes !== report.size_bytes);

  return (
    <div className="pdf-validator-report">
      <div className="pdf-validator-summary">
        <div>
          <p className="field__label">{t('pdfValidator.result.title')}</p>
          <h3>{report.filename ?? t('pdfValidator.file.unnamed')}</h3>
          <p className="muted">{report.legal_notice}</p>
        </div>
        <Badge tone={statusTone(report.status)}>{statusLabel(report.status, t)}</Badge>
      </div>
      <ValidationReportActions report={report} />

      {mismatch ? (
        <InlineWarning tone="error" title={t('pdfValidator.mismatch.title')}>
          {t('pdfValidator.mismatch.body')}
        </InlineWarning>
      ) : null}

      {/* Every field the old key/value cards carried now lives as a row of this table,
          including the per-signature and per-DocTimeStamp blocks. */}
      <PdfValidationResultTable report={report} />
    </div>
  );
}


export function PdfSignatureValidatorPanel() {
  const t = useT();
  const validate = useValidatePdfSignature();
  const [file, setFile] = useState<File | null>(null);
  const [readError, setReadError] = useState<Error | null>(null);

  async function submit() {
    if (!file) return;
    setReadError(null);
    try {
      const buffer = await readFileAsArrayBuffer(file);
      const declaredSha256 = await sha256Hex(buffer);
      validate.mutate({
        content_base64: arrayBufferToBase64(buffer),
        filename: file.name,
        declared_sha256: declaredSha256,
        declared_size_bytes: file.size,
      });
    } catch (e) {
      setReadError(e instanceof Error ? e : new Error(String(e)));
    }
  }

  return (
    <Card
      title={t('pdfValidator.title')}
      actions={
        <Button
          type="button"
          variant="primary"
          icon={<Icon.FileText />}
          disabled={!file || validate.isPending}
          onClick={() => void submit()}
        >
          {validate.isPending
            ? t('pdfValidator.action.pending')
            : t('pdfValidator.action.validate')}
        </Button>
      }
    >
      <div className="pdf-validator stack">
        <InlineWarning tone="info" title={t('pdfValidator.notice.title')}>
          {t('pdfValidator.notice.body')}
        </InlineWarning>

        <div className="pdf-validator-upload">
          <Field
            label={t('pdfValidator.file.label')}
            htmlFor="pdf-signature-validator-file"
            hint={
              file
                ? t('pdfValidator.file.selected', { name: file.name })
                : t('pdfValidator.file.hint')
            }
          >
            <input
              id="pdf-signature-validator-file"
              className="control"
              type="file"
              accept="application/pdf,.pdf"
              onChange={(e) => {
                setFile(e.currentTarget.files?.[0] ?? null);
                validate.reset();
                setReadError(null);
              }}
            />
          </Field>
          {file ? (
            <div className="pdf-validator-file">
              <Badge tone="neutral">PDF</Badge>
              <span>{file.name}</span>
              <span className="muted">{formatBytes(file.size, t)}</span>
            </div>
          ) : null}
        </div>

        {readError ? <ErrorNote error={readError} /> : null}
        {validate.error ? (
          <InlineWarning tone="error" title={t('pdfValidator.failClosed.title')}>
            <p>{t('pdfValidator.failClosed.body')}</p>
            <ErrorNote error={validate.error} />
          </InlineWarning>
        ) : null}
        {validate.isPending ? (
          <SkeletonRegion label={t('pdfValidator.action.pending')}>
            <SkeletonTable cols={3} rows={6} />
          </SkeletonRegion>
        ) : validate.data ? (
          <ValidationReport report={validate.data} />
        ) : null}
      </div>
    </Card>
  );
}
