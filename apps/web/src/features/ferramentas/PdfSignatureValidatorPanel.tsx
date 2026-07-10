import { useState } from 'react';
import type { ReactNode } from 'react';
import type {
  DocTimeStampValidationReport,
  PdfSignatureValidationFinding,
  PdfSignatureValidationResponse,
  PdfValidationStatus,
} from '../../api/types';
import { useValidatePdfSignature } from '../../api/hooks';
import { saveBlobAs, saveBlobResultMessage } from '../../desktop/saveFile';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  Digest,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  useToast,
} from '../../ui';

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function sha256Hex(buffer: ArrayBuffer): Promise<string | null> {
  if (!globalThis.crypto?.subtle) return null;
  return hex(await globalThis.crypto.subtle.digest('SHA-256', buffer));
}

function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
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

function boolText(value: boolean, t: TFunction): string {
  return value ? t('common.yes') : t('common.no');
}

function statusTone(status: PdfValidationStatus): 'neutral' | 'ok' | 'warn' | 'error' {
  if (status === 'valid') return 'ok';
  if (status === 'invalid') return 'error';
  if (status === 'indeterminate') return 'warn';
  return 'neutral';
}

function statusLabel(status: PdfValidationStatus, t: TFunction): string {
  if (status === 'valid') return t('pdfValidator.status.valid');
  if (status === 'invalid') return t('pdfValidator.status.invalid');
  if (status === 'indeterminate') return t('pdfValidator.status.indeterminate');
  return t('pdfValidator.status.unsigned');
}

function findingTone(severity: string): 'neutral' | 'warn' | 'error' {
  if (severity === 'error') return 'error';
  if (severity === 'warning') return 'warn';
  return 'neutral';
}

function reportJson(report: PdfSignatureValidationResponse): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

function reportFilename(report: PdfSignatureValidationResponse): string {
  const base = (report.filename ?? 'pdf')
    .replace(/\.pdf$/i, '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
  return `${base || 'pdf'}-validation-report.json`;
}

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
    <div className="form__actions">
      <Button
        type="button"
        variant="secondary"
        icon={<Icon.Copy />}
        onClick={() => void copyReport()}
      >
        {t('pdfValidator.report.copyJson')}
      </Button>
      <Button
        type="button"
        variant="secondary"
        icon={<Icon.Save />}
        disabled={saving}
        onClick={() => void downloadReport()}
      >
        {saving ? t('common.saving') : t('pdfValidator.report.saveJson')}
      </Button>
    </div>
  );
}

function FindingList({ findings }: { findings: PdfSignatureValidationFinding[] }) {
  const t = useT();
  if (!findings.length) return <p className="muted">{t('pdfValidator.findings.none')}</p>;
  return (
    <ul className="pdf-validator-findings">
      {findings.map((finding) => (
        <li key={`${finding.severity}-${finding.code}-${finding.message}`}>
          <Badge tone={findingTone(finding.severity)}>{finding.severity}</Badge>
          <div>
            <code className="mono">{finding.code}</code>
            <p>{finding.message}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}

function KeyValueGrid({ rows }: { rows: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="pdf-validator-kv">
      {rows.map((row) => (
        <div key={row.label}>
          <dt>{row.label}</dt>
          <dd>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function EvidenceDetails({ report }: { report: PdfSignatureValidationResponse }) {
  const t = useT();
  const sig = report.signature;
  const byteRange = sig.byte_range;
  const cades = sig.cades;
  const dss = sig.dss;
  const docTs = sig.doc_timestamp;

  return (
    <div className="pdf-validator-details">
      <details open>
        <summary>{t('pdfValidator.section.structure')}</summary>
        <KeyValueGrid
          rows={[
            { label: t('pdfValidator.field.isPdf'), value: boolText(report.structure.is_pdf, t) },
            { label: t('pdfValidator.field.version'), value: report.structure.version ?? '—' },
            {
              label: t('pdfValidator.field.headerOffset'),
              value: report.structure.header_offset ?? '—',
            },
            {
              label: t('pdfValidator.field.eof'),
              value: boolText(report.structure.has_eof_marker, t),
            },
            {
              label: t('pdfValidator.field.startxref'),
              value: boolText(report.structure.has_startxref, t),
            },
          ]}
        />
      </details>

      <details open>
        <summary>{t('pdfValidator.section.signature')}</summary>
        <KeyValueGrid
          rows={[
            {
              label: t('pdfValidator.field.validationPerformed'),
              value: boolText(sig.validation_performed, t),
            },
            { label: t('pdfValidator.field.pades'), value: sig.pades_profile ?? '—' },
            {
              label: t('pdfValidator.field.signatureMarkers'),
              value: sig.signature_marker_count,
            },
            {
              label: t('pdfValidator.field.byteRangeMarkers'),
              value: sig.byte_range_marker_count,
            },
            {
              label: t('pdfValidator.field.contentsMarker'),
              value: boolText(sig.has_contents_marker, t),
            },
            {
              label: t('pdfValidator.field.signatureTimestamp'),
              value: boolText(sig.timestamp.signature_timestamp_present, t),
            },
          ]}
        />
        {sig.validation_error ? <p className="field__error">{sig.validation_error}</p> : null}
        {byteRange ? (
          <KeyValueGrid
            rows={[
              {
                label: t('pdfValidator.field.byteRange'),
                value: <code className="mono">{byteRange.byte_range.join(', ')}</code>,
              },
              {
                label: t('pdfValidator.field.coverage'),
                value: t('pdfValidator.value.coverage', {
                  covered: byteRange.covered_len,
                  total: byteRange.total_len,
                }),
              },
              {
                label: t('pdfValidator.field.laterUpdates'),
                value: boolText(byteRange.has_later_incremental_updates, t),
              },
              {
                label: t('pdfValidator.field.signedRevisionDigest'),
                value: byteRange.digest_sha256 ? <Digest value={byteRange.digest_sha256} /> : '—',
              },
            ]}
          />
        ) : null}
        {cades ? (
          <KeyValueGrid
            rows={[
              { label: t('pdfValidator.field.cades'), value: cades.status },
              {
                label: t('pdfValidator.field.signingCertificate'),
                value: boolText(cades.signing_certificate_v2_present, t),
              },
              {
                label: t('pdfValidator.field.signerSubject'),
                value: cades.signer_cert_subject ?? '—',
              },
              {
                label: t('pdfValidator.field.signerCertDigest'),
                value: <Digest value={cades.signer_cert_sha256} />,
              },
              { label: t('pdfValidator.field.signingTime'), value: cades.signing_time ?? '—' },
            ]}
          />
        ) : null}
      </details>

      <details>
        <summary>{t('pdfValidator.section.dss')}</summary>
        <KeyValueGrid
          rows={[
            { label: t('pdfValidator.field.dssPresent'), value: boolText(dss.present, t) },
            { label: t('pdfValidator.field.vri'), value: dss.vri_count },
            { label: t('pdfValidator.field.vriTu'), value: dss.vri_tu_count },
            { label: t('pdfValidator.field.certificates'), value: dss.certificate_count },
            { label: t('pdfValidator.field.ocsp'), value: dss.ocsp_count },
            { label: t('pdfValidator.field.crl'), value: dss.crl_count },
            {
              label: t('pdfValidator.field.revocationEvidence'),
              value: boolText(dss.revocation_evidence_present, t),
            },
          ]}
        />
      </details>

      <details>
        <summary>{t('pdfValidator.section.docTimestamp')}</summary>
        <KeyValueGrid
          rows={[
            { label: t('pdfValidator.field.present'), value: boolText(docTs.present, t) },
            { label: t('pdfValidator.field.count'), value: docTs.count },
            { label: t('pdfValidator.field.tokens'), value: docTs.token_count },
            {
              label: t('pdfValidator.field.imprints'),
              value: boolText(docTs.all_imprints_valid, t),
            },
          ]}
        />
        {docTs.validations.length ? (
          <ul className="pdf-validator-timestamps">
            {docTs.validations.map((validation: DocTimeStampValidationReport) => (
              <li key={`${validation.index}-${validation.object_id}`}>
                <span>
                  <Badge tone={validation.status === 'valid' ? 'ok' : 'warn'}>
                    {validation.status}
                  </Badge>
                  <code className="mono">{validation.object_id}</code>
                </span>
                <span className="muted">
                  {validation.failure_reason ?? validation.token_hash_algorithm ?? '—'}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
      </details>

      <details open>
        <summary>{t('pdfValidator.section.trust')}</summary>
        <KeyValueGrid
          rows={[
            { label: t('pdfValidator.field.trust'), value: report.trust.status },
            {
              label: t('pdfValidator.field.liveTsl'),
              value: boolText(report.trust.live_trusted_list_validation_performed, t),
            },
            {
              label: t('pdfValidator.field.ama'),
              value: boolText(report.trust.ama_integration_performed, t),
            },
            { label: t('pdfValidator.field.revocation'), value: report.revocation.status },
            {
              label: t('pdfValidator.field.liveFetch'),
              value: boolText(report.revocation.live_fetch_performed, t),
            },
            {
              label: t('pdfValidator.field.embeddedRevocation'),
              value: boolText(report.revocation.embedded_revocation_evidence_present, t),
            },
            { label: t('pdfValidator.field.qualification'), value: report.qualification.status },
            {
              label: t('pdfValidator.field.legalValidity'),
              value: boolText(report.qualification.legal_validity_claimed, t),
            },
          ]}
        />
        <p className="muted">{report.trust.message}</p>
        <p className="muted">{report.revocation.message}</p>
        <p className="muted">{report.qualification.message}</p>
      </details>
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

      <KeyValueGrid
        rows={[
          { label: t('pdfValidator.field.size'), value: formatBytes(report.size_bytes, t) },
          { label: t('pdfValidator.field.sha256'), value: <Digest value={report.sha256} /> },
          {
            label: t('pdfValidator.field.declaredSize'),
            value:
              report.declared_size_bytes === null
                ? '—'
                : formatBytes(report.declared_size_bytes, t),
          },
          {
            label: t('pdfValidator.field.declaredSha256'),
            value: report.declared_sha256 ? <Digest value={report.declared_sha256} /> : '—',
          },
        ]}
      />

      <EvidenceDetails report={report} />

      <details open>
        <summary>{t('pdfValidator.section.findings')}</summary>
        <FindingList findings={report.findings} />
      </details>
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
        {validate.data ? <ValidationReport report={validate.data} /> : null}
      </div>
    </Card>
  );
}
