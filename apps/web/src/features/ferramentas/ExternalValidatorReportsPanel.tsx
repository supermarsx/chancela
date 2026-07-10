import { useState, type ReactNode } from 'react';
import type { ExternalValidatorReportSummary } from '../../api/types';
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
  Loading,
  Table,
  useToast,
} from '../../ui';
import { GateButton } from '../session/permissions';

function readFileAsText(file: File): Promise<string> {
  if (typeof file.text === 'function') return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ''));
    reader.onerror = () => reject(reader.error ?? new Error('file read failed'));
    reader.readAsText(file);
  });
}

function formatBytes(value: number, t: TFunction): string {
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
  const [clientError, setClientError] = useState<string | null>(null);
  const [reading, setReading] = useState(false);

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

  function submitUpload() {
    if (!rawText || clientError || reading || upload.isPending) return;
    try {
      JSON.parse(rawText);
    } catch {
      setClientError(t('externalValidatorReports.file.invalidJson'));
      return;
    }
    upload.mutate(rawText, {
      onSuccess: () => toast.success(t('externalValidatorReports.upload.success')),
    });
  }

  const data = reports.data;
  const selectedHint = file
    ? t('externalValidatorReports.file.selected', {
        name: file.name,
        size: formatBytes(file.size, t),
      })
    : t('externalValidatorReports.file.hint');

  return (
    <Card
      title={t('externalValidatorReports.title')}
      actions={
        <GateButton
          type="button"
          perm="settings.manage"
          variant="primary"
          icon={<Icon.Tray />}
          disabled={!file || !rawText || !!clientError || reading || upload.isPending}
          onClick={submitUpload}
        >
          {upload.isPending
            ? t('externalValidatorReports.action.pending')
            : t('externalValidatorReports.action.upload')}
        </GateButton>
      }
    >
      <div className="pdf-validator stack">
        <InlineWarning tone="info" title={t('externalValidatorReports.notice.title')}>
          {t('externalValidatorReports.notice.body')}
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

        {upload.error ? <ErrorNote error={upload.error} /> : null}
        {reports.isLoading ? <Loading label={t('externalValidatorReports.loading')} /> : null}
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
