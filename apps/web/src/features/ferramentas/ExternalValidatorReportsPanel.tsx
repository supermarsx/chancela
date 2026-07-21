import { useState, type ReactNode } from 'react';
import type {
  ExternalValidatorRawReportSummary,
  ExternalValidatorReportSummary,
  ExternalValidatorReportUploadBody,
} from '../../api/types';
import { useExternalValidatorReports, useUploadExternalValidatorReport } from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage } from '../../desktop/saveFile';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Card,
  Digest,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  InlineWarning,
  SkeletonRegion,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { GateButton } from '../session/permissions';

const RAW_REPORT_MAX_BYTES = 2 * 1024 * 1024;
const RAW_REPORT_ACCEPT =
  'application/json,.json,application/pdf,.pdf,application/xml,text/xml,.xml,text/plain,.txt,application/octet-stream';
const RAW_REPORT_CONTENT_TYPES = new Set([
  'application/json',
  'application/pdf',
  'application/xml',
  'text/xml',
  'text/plain',
  'application/octet-stream',
]);

interface RawReportSelection {
  fileName: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  contentBase64: string;
  sourceFilename: string | null;
}

export function readExternalValidatorFileAsText(file: File): Promise<string> {
  if (typeof file.text === 'function') return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error ?? new Error('file read failed'));
    reader.readAsText(file);
  });
}

export function externalValidatorArrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function externalValidatorHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function externalValidatorSha256Hex(buffer: ArrayBuffer): Promise<string | null> {
  if (!globalThis.crypto?.subtle) return null;
  return externalValidatorHex(await globalThis.crypto.subtle.digest('SHA-256', buffer));
}

export function readExternalValidatorFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
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

export function formatExternalValidatorBytes(value: number, t: TFunction): string {
  if (!Number.isFinite(value) || value < 0) return t('pdfValidator.size.unknown');
  if (value < 1024) return `${value} bytes`;
  const units = ['KB', 'MB', 'GB'];
  let amount = value;
  let unit = 'bytes';
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  return `${amount.toFixed(amount < 10 ? 1 : 0)} ${unit}`;
}

function textValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

export function normalizeRawReportContentType(value: string | undefined): string | null {
  const mediaType = (value ?? '').split(';')[0].trim().toLowerCase();
  return RAW_REPORT_CONTENT_TYPES.has(mediaType) ? mediaType : null;
}

export function rawReportContentType(file: File): string {
  const declared = normalizeRawReportContentType(file.type);
  if (declared) return declared;
  const name = file.name.toLowerCase();
  if (name.endsWith('.json')) return 'application/json';
  if (name.endsWith('.pdf')) return 'application/pdf';
  if (name.endsWith('.xml')) return 'application/xml';
  if (name.endsWith('.txt')) return 'text/plain';
  return 'application/octet-stream';
}

export function safeSourceFilename(value: string): string | null {
  if (!value || value.length > 255 || value.includes('/') || value.includes('\\')) return null;
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (character !== ' ' && (code < 0x21 || code > 0x7e)) return null;
  }
  return value;
}

const readFileAsText = readExternalValidatorFileAsText;
const arrayBufferToBase64 = externalValidatorArrayBufferToBase64;
const sha256Hex = externalValidatorSha256Hex;
const readFileAsArrayBuffer = readExternalValidatorFileAsArrayBuffer;
const formatBytes = formatExternalValidatorBytes;

function reportCaseId(report: ExternalValidatorReportSummary): string | null {
  return textValue(report.case_id);
}

function reportValidatorFamily(report: ExternalValidatorReportSummary): string | null {
  return textValue(report.validator_family);
}

function reportArchivePath(report: ExternalValidatorReportSummary): string | null {
  return (
    textValue(report.path) ??
    textValue(report.archive_path) ??
    textValue(report.suggested_archive_path) ??
    textValue(report.suggested_path)
  );
}

function reportDigest(report: ExternalValidatorReportSummary): string | null {
  return textValue(report.sha256) ?? textValue(report.digest);
}

function safeFilenameSegment(value: string | null): string {
  const normalized = (value ?? 'external-validator-report')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
  return normalized || 'external-validator-report';
}

function metadataSummaryJson(report: ExternalValidatorReportSummary): string {
  return `${JSON.stringify(
    {
      summary_kind: 'external_validator_report_metadata_summary',
      scope: 'external_validator_report_metadata_only',
      raw_report_included: false,
      generated_at: new Date().toISOString(),
      report,
    },
    null,
    2,
  )}\n`;
}

function metadataSummaryFilename(report: ExternalValidatorReportSummary): string {
  const base = reportCaseId(report) ?? reportArchivePath(report) ?? reportValidatorFamily(report);
  return `${safeFilenameSegment(base)}-external-validator-metadata-summary.json`;
}

function displayText(value: string | null): ReactNode {
  return value ? <code className="mono">{value}</code> : '—';
}

function buildUploadRequest(
  rawText: string,
  rawReport: RawReportSelection | null,
): string | ExternalValidatorReportUploadBody {
  if (!rawReport) return rawText;
  const parsed = JSON.parse(rawText) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new SyntaxError('external-validator metadata must be a JSON object');
  }
  return {
    ...(parsed as Record<string, unknown>),
    raw_report: {
      content_base64: rawReport.contentBase64,
      content_type: rawReport.contentType,
      sha256: rawReport.sha256,
      size_bytes: rawReport.sizeBytes,
      ...(rawReport.sourceFilename ? { source_filename: rawReport.sourceFilename } : {}),
    },
  };
}

function RawReportLocalSummary({ report }: { report: RawReportSelection }) {
  const t = useT();
  return (
    <div className="pdf-validator-report">
      <p className="field__label">{t('externalValidatorReports.rawFile.summaryTitle')}</p>
      <dl className="pdf-validator-kv">
        <div>
          <dt>{t('externalValidatorReports.rawFile.filename')}</dt>
          <dd>{displayText(report.fileName)}</dd>
        </div>
        <div>
          <dt>{t('externalValidatorReports.table.contentType')}</dt>
          <dd>{displayText(report.contentType)}</dd>
        </div>
        <div>
          <dt>{t('pdfValidator.field.size')}</dt>
          <dd>{formatBytes(report.sizeBytes, t)}</dd>
        </div>
        <div>
          <dt>{t('pdfValidator.field.sha256')}</dt>
          <dd>
            <Digest value={report.sha256} copyable={false} />
          </dd>
        </div>
        <div>
          <dt>{t('externalValidatorReports.rawFile.provenance')}</dt>
          <dd>{t('externalValidatorReports.rawFile.provenance.local')}</dd>
        </div>
      </dl>
    </div>
  );
}

function RawReportBackendSummary({ rawReport }: { rawReport: ExternalValidatorRawReportSummary }) {
  const t = useT();
  const path = textValue(rawReport.path) ?? textValue(rawReport.suggested_path);
  return (
    <div className="pdf-validator-report">
      <p className="field__label">{t('externalValidatorReports.rawReport.summaryTitle')}</p>
      <dl className="pdf-validator-kv">
        <div>
          <dt>{t('externalValidatorReports.rawFile.provenance')}</dt>
          <dd>
            <Badge
              tone={rawReport.preservation_status === 'raw_report_attached' ? 'ok' : 'neutral'}
            >
              {rawReport.preservation_status}
            </Badge>
          </dd>
        </div>
        <div>
          <dt>{t('externalValidatorReports.rawFile.filename')}</dt>
          <dd>{displayText(textValue(rawReport.source_filename))}</dd>
        </div>
        <div>
          <dt>{t('externalValidatorReports.table.contentType')}</dt>
          <dd>{displayText(textValue(rawReport.content_type))}</dd>
        </div>
        <div>
          <dt>{t('pdfValidator.field.size')}</dt>
          <dd>{formatBytes(rawReport.size_bytes, t)}</dd>
        </div>
        <div>
          <dt>{t('pdfValidator.field.sha256')}</dt>
          <dd>
            <Digest value={rawReport.sha256} copyable={false} />
          </dd>
        </div>
        <div>
          <dt>{t('externalValidatorReports.table.archivePath')}</dt>
          <dd>{displayText(path)}</dd>
        </div>
      </dl>
      <p className="muted">{t('externalValidatorReports.notice.noClaims')}</p>
    </div>
  );
}

function StorageSummary({
  storage,
  status,
  count,
  malformed,
  duplicates,
}: {
  storage: string;
  status: string;
  count: number;
  malformed: number;
  duplicates: number;
}) {
  const t = useT();
  return (
    <dl className="pdf-validator-kv">
      <div>
        <dt>{t('externalValidatorReports.summary.storage')}</dt>
        <dd>{storage}</dd>
      </div>
      <div>
        <dt>{t('externalValidatorReports.summary.status')}</dt>
        <dd>
          <Badge tone={status === 'ok' ? 'ok' : 'neutral'}>{status}</Badge>
        </dd>
      </div>
      <div>
        <dt>{t('externalValidatorReports.summary.count')}</dt>
        <dd>{count}</dd>
      </div>
      <div>
        <dt>{t('externalValidatorReports.summary.malformed')}</dt>
        <dd>{malformed}</dd>
      </div>
      <div>
        <dt>{t('externalValidatorReports.summary.duplicates')}</dt>
        <dd>{duplicates}</dd>
      </div>
    </dl>
  );
}

function SummaryDownloadButton({ report }: { report: ExternalValidatorReportSummary }) {
  const t = useT();
  const toast = useToast();
  const [saving, setSaving] = useState(false);

  async function downloadSummary() {
    setSaving(true);
    try {
      const blob = new Blob([metadataSummaryJson(report)], {
        type: 'application/json;charset=utf-8',
      });
      const result = await saveBlobAs({
        blob,
        filename: metadataSummaryFilename(report),
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
    <IconButton
      icon={<Icon.Save />}
      label={saving ? t('common.saving') : t('externalValidatorReports.downloadSummary')}
      variant="secondary"
      placement="left"
      disabled={saving}
      onClick={() => void downloadSummary()}
    />
  );
}

function ReportsTable({ reports }: { reports: ExternalValidatorReportSummary[] }) {
  const t = useT();
  return (
    <Table
      head={
        <tr>
          <th>{t('externalValidatorReports.table.caseId')}</th>
          <th>{t('externalValidatorReports.table.validatorFamily')}</th>
          <th>{t('externalValidatorReports.table.archivePath')}</th>
          <th>{t('externalValidatorReports.table.contentType')}</th>
          <th>{t('externalValidatorReports.table.digest')}</th>
          <th>{t('externalValidatorReports.rawReport.table')}</th>
          <th>{t('externalValidatorReports.table.actions')}</th>
        </tr>
      }
    >
      {reports.map((report, index) => {
        const digest = reportDigest(report);
        const key = [reportCaseId(report), reportArchivePath(report), digest, String(index)]
          .filter(Boolean)
          .join(':');
        return (
          <tr key={key}>
            <td>{displayText(reportCaseId(report))}</td>
            <td>{displayText(reportValidatorFamily(report))}</td>
            <td>{displayText(reportArchivePath(report))}</td>
            <td>{displayText(textValue(report.content_type))}</td>
            <td>{digest ? <Digest value={digest} copyable={false} /> : '—'}</td>
            <td>
              {report.raw_report ? (
                <RawReportBackendSummary rawReport={report.raw_report} />
              ) : (
                <span className="muted">{t('externalValidatorReports.rawReport.none')}</span>
              )}
            </td>
            <td className="pdf-validator-actions-cell">
              <span className="muted">{t('externalValidatorReports.table.metadataOnly')}</span>
              <SummaryDownloadButton report={report} />
            </td>
          </tr>
        );
      })}
    </Table>
  );
}

export function ExternalValidatorReportsPanel() {
  const t = useT();
  const toast = useToast();
  const reports = useExternalValidatorReports();
  const upload = useUploadExternalValidatorReport();
  const [file, setFile] = useState<File | null>(null);
  const [rawText, setRawText] = useState<string | null>(null);
  const [rawReportFile, setRawReportFile] = useState<File | null>(null);
  const [rawReport, setRawReport] = useState<RawReportSelection | null>(null);
  const [clientError, setClientError] = useState<string | null>(null);
  const [rawReportError, setRawReportError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);
  const [readingRawReport, setReadingRawReport] = useState(false);

  async function selectFile(next: File | null) {
    setFile(next);
    setRawText(null);
    setClientError(null);
    upload.reset();
    if (!next) return;

    setReading(true);
    try {
      const text = await readFileAsText(next);
      JSON.parse(text);
      setRawText(text);
    } catch (error) {
      setRawText(null);
      setClientError(
        error instanceof SyntaxError
          ? t('externalValidatorReports.file.invalidJson')
          : t('externalValidatorReports.file.readError'),
      );
    } finally {
      setReading(false);
    }
  }

  async function selectRawReportFile(next: File | null) {
    setRawReportFile(next);
    setRawReport(null);
    setRawReportError(null);
    upload.reset();
    if (!next) return;
    if (next.size <= 0) {
      setRawReportError(t('externalValidatorReports.rawFile.empty'));
      return;
    }
    if (next.size > RAW_REPORT_MAX_BYTES) {
      setRawReportError(
        t('externalValidatorReports.rawFile.tooLarge', {
          max: formatBytes(RAW_REPORT_MAX_BYTES, t),
        }),
      );
      return;
    }

    setReadingRawReport(true);
    try {
      const buffer = await readFileAsArrayBuffer(next);
      const digest = await sha256Hex(buffer);
      if (!digest) {
        setRawReportError(t('externalValidatorReports.rawFile.digestUnavailable'));
        return;
      }
      setRawReport({
        fileName: next.name,
        contentType: rawReportContentType(next),
        sizeBytes: next.size,
        sha256: digest,
        contentBase64: arrayBufferToBase64(buffer),
        sourceFilename: safeSourceFilename(next.name),
      });
    } catch {
      setRawReportError(t('externalValidatorReports.rawFile.readError'));
    } finally {
      setReadingRawReport(false);
    }
  }

  function submitUpload() {
    if (
      !rawText ||
      clientError ||
      rawReportError ||
      reading ||
      readingRawReport ||
      upload.isPending ||
      (rawReportFile && !rawReport)
    ) {
      return;
    }
    try {
      const body = buildUploadRequest(rawText, rawReport);
      upload.mutate(body, {
        onSuccess: () => toast.success(t('externalValidatorReports.upload.success')),
      });
    } catch {
      setClientError(t('externalValidatorReports.file.invalidJson'));
    }
  }

  const data = reports.data;
  const selectedHint = file
    ? t('externalValidatorReports.file.selected', {
        name: file.name,
        size: formatBytes(file.size, t),
      })
    : t('externalValidatorReports.file.hint');
  const rawReportHint = rawReportFile
    ? t('externalValidatorReports.rawFile.selected', {
        name: rawReportFile.name,
        size: formatBytes(rawReportFile.size, t),
      })
    : t('externalValidatorReports.rawFile.hint', {
        max: formatBytes(RAW_REPORT_MAX_BYTES, t),
      });
  const canUpload =
    !!rawText &&
    !clientError &&
    !rawReportError &&
    !reading &&
    !readingRawReport &&
    !upload.isPending &&
    (!rawReportFile || !!rawReport);

  return (
    <Card
      title={t('externalValidatorReports.title')}
      actions={
        <GateButton
          type="button"
          perm="settings.manage"
          variant="primary"
          icon={<Icon.Tray />}
          disabled={!canUpload}
          onClick={submitUpload}
        >
          {upload.isPending
            ? t('externalValidatorReports.action.pending')
            : rawReport
              ? t('externalValidatorReports.action.uploadWithRaw')
              : t('externalValidatorReports.action.upload')}
        </GateButton>
      }
    >
      <div className="pdf-validator stack">
        <InlineWarning tone="info" title={t('externalValidatorReports.notice.title')}>
          <p>{t('externalValidatorReports.notice.body')}</p>
          <p>{t('externalValidatorReports.notice.noClaims')}</p>
        </InlineWarning>

        <div className="pdf-validator-upload">
          <Field
            label={t('externalValidatorReports.file.label')}
            htmlFor="external-validator-report-file"
            hint={selectedHint}
            error={clientError}
          >
            <input
              id="external-validator-report-file"
              className="control"
              type="file"
              accept="application/json,.json"
              onChange={(e) => void selectFile(e.currentTarget.files?.[0] ?? null)}
            />
          </Field>
          {file ? (
            <div className="pdf-validator-file">
              <Badge tone="neutral">JSON</Badge>
              <span>{file.name}</span>
              <span className="muted">{formatBytes(file.size, t)}</span>
            </div>
          ) : null}
        </div>

        <div className="pdf-validator-upload">
          <Field
            label={t('externalValidatorReports.rawFile.label')}
            htmlFor="external-validator-raw-report-file"
            hint={rawReportHint}
            error={rawReportError}
          >
            <input
              id="external-validator-raw-report-file"
              className="control"
              type="file"
              accept={RAW_REPORT_ACCEPT}
              onChange={(e) => void selectRawReportFile(e.currentTarget.files?.[0] ?? null)}
            />
          </Field>
          {rawReport ? <RawReportLocalSummary report={rawReport} /> : null}
          {readingRawReport ? (
            <p className="muted">{t('externalValidatorReports.rawFile.reading')}</p>
          ) : null}
        </div>

        {upload.error ? <ErrorNote error={upload.error} /> : null}
        {/* Seven columns: case, family, path, content type, digest, raw report, actions. */}
        {reports.isLoading ? (
          <SkeletonRegion label={t('externalValidatorReports.loading')}>
            <SkeletonTable cols={7} />
          </SkeletonRegion>
        ) : null}
        {reports.error ? <ErrorNote error={reports.error} /> : null}
        {data ? (
          <>
            <p className="pdf-validator-status" aria-live="polite">
              {t('externalValidatorReports.status', {
                count: data.count,
                malformed: data.malformed_count,
                duplicates: data.duplicate_suggested_path_count,
              })}
            </p>
            <StorageSummary
              storage={data.storage}
              status={data.status}
              count={data.count}
              malformed={data.malformed_count}
              duplicates={data.duplicate_suggested_path_count}
            />
          </>
        ) : null}
        {data && data.reports.length === 0 ? (
          <EmptyState title={t('externalValidatorReports.empty.title')}>
            <p>{t('externalValidatorReports.empty.body')}</p>
          </EmptyState>
        ) : null}
        {data && data.reports.length > 0 ? <ReportsTable reports={data.reports} /> : null}
      </div>
    </Card>
  );
}
