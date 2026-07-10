import { useState } from 'react';
import type { ReactNode } from 'react';
import type {
  DocTimeStampValidationReport,
  LocalTechnicalRenewalPlanReport,
  PdfSignatureValidationFinding,
  PdfSignatureValidationResponse,
  PdfValidationStatus,
  SignatureLocalRenewalPlanReport,
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
  IconButton,
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

function evidenceTone(status: string): 'neutral' | 'ok' | 'warn' | 'error' {
  const normalized = status.toLowerCase();
  if (normalized === 'valid' || normalized === 'available') return 'ok';
  if (normalized.includes('invalid') || normalized.includes('failed')) return 'error';
  if (normalized.includes('indeterminate') || normalized.includes('unavailable')) return 'warn';
  if (normalized.includes('unsupported') || normalized.includes('gap')) return 'warn';
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

function TextList({ values, emptyLabel }: { values: string[]; emptyLabel: string }) {
  if (!values.length) return <span className="muted">{emptyLabel}</span>;
  return (
    <span className="pdf-validator-chipline">
      {values.map((value, index) => (
        <code className="mono pdf-validator-chip" key={`${value}-${index}`}>
          {value}
        </code>
      ))}
    </span>
  );
}

function DigestList({ values, emptyLabel }: { values: string[]; emptyLabel: string }) {
  if (!values.length) return <span className="muted">{emptyLabel}</span>;
  return (
    <ul className="pdf-validator-digests">
      {values.map((value, index) => (
        <li key={`${value}-${index}`}>
          <Digest value={value} />
        </li>
      ))}
    </ul>
  );
}

function RenewalPlanGrid({ plan }: { plan: LocalTechnicalRenewalPlanReport }) {
  const t = useT();
  return (
    <>
      <KeyValueGrid
        rows={[
          {
            label: t('pdfValidator.field.renewalPlan'),
            value: <Badge tone={evidenceTone(plan.status)}>{plan.status}</Badge>,
          },
          { label: t('pdfValidator.field.statusScope'), value: plan.scope },
          {
            label: t('pdfValidator.field.signatureTimestamp'),
            value: boolText(plan.signature_timestamp_present, t),
          },
          {
            label: t('pdfValidator.field.revocationEvidence'),
            value: boolText(plan.dss_revocation_evidence_present, t),
          },
          {
            label: t('pdfValidator.field.dssValidationTime'),
            value: boolText(plan.dss_validation_time_present, t),
          },
          {
            label: t('pdfValidator.section.docTimestamp'),
            value: boolText(plan.doc_timestamp_present, t),
          },
          {
            label: t('pdfValidator.field.docTimestampImprints'),
            value: boolText(plan.doc_timestamp_imprints_valid, t),
          },
          {
            label: t('pdfValidator.field.missingInputs'),
            value: (
              <TextList values={plan.missing_inputs} emptyLabel={t('pdfValidator.value.none')} />
            ),
          },
          { label: t('pdfValidator.field.nextAction'), value: plan.next_action },
          {
            label: t('pdfValidator.field.evidenceGaps'),
            value: boolText(plan.has_local_evidence_gap, t),
          },
          {
            label: t('pdfValidator.field.allPlanningInputs'),
            value: boolText(plan.all_local_planning_inputs_present, t),
          },
          {
            label: t('pdfValidator.field.productionProfileClaimed'),
            value: boolText(plan.production_long_term_profile_claimed, t),
          },
          {
            label: t('pdfValidator.field.legalLtvClaimed'),
            value: boolText(plan.legal_ltv_claimed, t),
          },
        ]}
      />
      <p className="muted">{plan.notice}</p>
    </>
  );
}

function SignatureRenewalList({ signatures }: { signatures: SignatureLocalRenewalPlanReport[] }) {
  const t = useT();
  if (!signatures.length) {
    return <p className="muted">{t('pdfValidator.signatures.none')}</p>;
  }
  return (
    <ul className="pdf-validator-signatures">
      {signatures.map((signature) => {
        const plan = signature.local_technical_renewal_plan;
        return (
          <li key={`${signature.index}-${signature.object_id}`}>
            <div className="pdf-validator-evidence-head">
              <span>
                <Badge tone={evidenceTone(plan.status)}>
                  {t('pdfValidator.signature.item', { index: signature.index })}
                </Badge>
                <code className="mono">{signature.object_id}</code>
              </span>
              <span className="muted">{plan.status}</span>
            </div>
            <KeyValueGrid
              rows={[
                {
                  label: t('pdfValidator.field.signedRevision'),
                  value: signature.signed_revision_len,
                },
                {
                  label: t('pdfValidator.field.vriKey'),
                  value: <Digest value={signature.vri_key_sha256} />,
                },
                {
                  label: t('pdfValidator.field.dssVri'),
                  value: boolText(signature.dss_vri_present, t),
                },
                {
                  label: t('pdfValidator.field.dssVriValidationTime'),
                  value: boolText(signature.dss_vri_validation_time_present, t),
                },
                {
                  label: t('pdfValidator.field.missingInputs'),
                  value: (
                    <TextList
                      values={plan.missing_inputs}
                      emptyLabel={t('pdfValidator.value.none')}
                    />
                  ),
                },
                { label: t('pdfValidator.field.nextAction'), value: plan.next_action },
                {
                  label: t('pdfValidator.field.legalLtvClaimed'),
                  value: boolText(plan.legal_ltv_claimed, t),
                },
              ]}
            />
          </li>
        );
      })}
    </ul>
  );
}

function EvidenceDetails({ report }: { report: PdfSignatureValidationResponse }) {
  const t = useT();
  const sig = report.signature;
  const byteRange = sig.byte_range;
  const cades = sig.cades;
  const dss = sig.dss;
  const docTs = sig.doc_timestamp;
  const renewalPlan = sig.local_technical_renewal_plan;
  const multiRenewalPlan = sig.multi_signature_local_renewal_plan;

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
                label: t('pdfValidator.field.signedRevision'),
                value: byteRange.signed_revision_len,
              },
              {
                label: t('pdfValidator.field.excludedBytes'),
                value: byteRange.excluded_len ?? '—',
              },
              {
                label: t('pdfValidator.field.coversWholeFile'),
                value: boolText(byteRange.covers_whole_file_except_contents, t),
              },
              {
                label: t('pdfValidator.field.coversSignedRevision'),
                value: boolText(byteRange.covers_signed_revision_except_contents, t),
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
            {
              label: t('pdfValidator.field.vriTuKeys'),
              value: (
                <TextList values={dss.vri_tu_keys} emptyLabel={t('pdfValidator.value.none')} />
              ),
            },
            { label: t('pdfValidator.field.certificates'), value: dss.certificate_count },
            { label: t('pdfValidator.field.ocsp'), value: dss.ocsp_count },
            { label: t('pdfValidator.field.crl'), value: dss.crl_count },
            {
              label: t('pdfValidator.field.revocationEvidence'),
              value: boolText(dss.revocation_evidence_present, t),
            },
            { label: t('pdfValidator.field.statusScope'), value: dss.status_scope },
            {
              label: t('pdfValidator.field.certificateHashes'),
              value: (
                <DigestList
                  values={dss.certificate_sha256}
                  emptyLabel={t('pdfValidator.value.none')}
                />
              ),
            },
            {
              label: t('pdfValidator.field.ocspHashes'),
              value: (
                <DigestList values={dss.ocsp_sha256} emptyLabel={t('pdfValidator.value.none')} />
              ),
            },
            {
              label: t('pdfValidator.field.crlHashes'),
              value: (
                <DigestList values={dss.crl_sha256} emptyLabel={t('pdfValidator.value.none')} />
              ),
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
            { label: t('pdfValidator.field.statusScope'), value: docTs.status_scope },
            {
              label: t('pdfValidator.field.tokenHashes'),
              value: (
                <DigestList values={docTs.token_sha256} emptyLabel={t('pdfValidator.value.none')} />
              ),
            },
          ]}
        />
        {docTs.validations.length ? (
          <ul className="pdf-validator-timestamps">
            {docTs.validations.map((validation: DocTimeStampValidationReport) => (
              <li key={`${validation.index}-${validation.object_id}`}>
                <div className="pdf-validator-evidence-head">
                  <span>
                    <Badge tone={validation.status === 'valid' ? 'ok' : 'warn'}>
                      {validation.status}
                    </Badge>
                    <code className="mono">{validation.object_id}</code>
                  </span>
                  <span className="muted">
                    {validation.failure_reason ?? validation.token_hash_algorithm ?? '—'}
                  </span>
                </div>
                <KeyValueGrid
                  rows={[
                    {
                      label: t('pdfValidator.field.byteRange'),
                      value: validation.byte_range ? (
                        <code className="mono">{validation.byte_range.join(', ')}</code>
                      ) : (
                        '—'
                      ),
                    },
                    {
                      label: t('pdfValidator.field.documentDigest'),
                      value: validation.document_digest_sha256 ? (
                        <Digest value={validation.document_digest_sha256} />
                      ) : (
                        '—'
                      ),
                    },
                    {
                      label: t('pdfValidator.field.tokenImprint'),
                      value: validation.token_imprint_sha256 ? (
                        <Digest value={validation.token_imprint_sha256} />
                      ) : (
                        '—'
                      ),
                    },
                    {
                      label: t('pdfValidator.field.hashAlgorithm'),
                      value: validation.token_hash_algorithm ?? '—',
                    },
                    {
                      label: t('pdfValidator.field.failureReason'),
                      value: validation.failure_reason ?? '—',
                    },
                  ]}
                />
              </li>
            ))}
          </ul>
        ) : null}
      </details>

      <details open>
        <summary>{t('pdfValidator.section.signatures')}</summary>
        <KeyValueGrid
          rows={[
            {
              label: t('pdfValidator.field.renewalPlan'),
              value: <Badge tone={evidenceTone(renewalPlan.status)}>{renewalPlan.status}</Badge>,
            },
            {
              label: t('pdfValidator.field.multiSignaturePlan'),
              value: (
                <Badge tone={evidenceTone(multiRenewalPlan.status)}>
                  {multiRenewalPlan.status}
                </Badge>
              ),
            },
            {
              label: t('pdfValidator.field.signatureCount'),
              value: multiRenewalPlan.signature_count,
            },
            {
              label: t('pdfValidator.field.signaturesWithGaps'),
              value: (
                <TextList
                  values={multiRenewalPlan.signatures_with_local_evidence_gaps.map(String)}
                  emptyLabel={t('pdfValidator.value.none')}
                />
              ),
            },
            { label: t('pdfValidator.field.nextAction'), value: multiRenewalPlan.next_action },
            {
              label: t('pdfValidator.field.evidenceGaps'),
              value: boolText(multiRenewalPlan.has_local_evidence_gap, t),
            },
            {
              label: t('pdfValidator.field.allPlanningInputs'),
              value: boolText(multiRenewalPlan.all_local_planning_inputs_present, t),
            },
            { label: t('pdfValidator.field.statusScope'), value: multiRenewalPlan.scope },
            {
              label: t('pdfValidator.field.productionProfileClaimed'),
              value: boolText(multiRenewalPlan.production_long_term_profile_claimed, t),
            },
            {
              label: t('pdfValidator.field.legalLtvClaimed'),
              value: boolText(multiRenewalPlan.legal_ltv_claimed, t),
            },
          ]}
        />
        <p className="muted">{multiRenewalPlan.notice}</p>
        <details>
          <summary>{t('pdfValidator.section.renewalPlan')}</summary>
          <RenewalPlanGrid plan={renewalPlan} />
        </details>
        <SignatureRenewalList signatures={multiRenewalPlan.signatures} />
      </details>

      <details open>
        <summary>{t('pdfValidator.section.trust')}</summary>
        <KeyValueGrid
          rows={[
            { label: t('pdfValidator.field.trust'), value: report.trust.status },
            {
              label: t('pdfValidator.field.trustPerformed'),
              value: boolText(report.trust.performed, t),
            },
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
              label: t('pdfValidator.field.revocationFreshness'),
              value: boolText(report.revocation.freshness_validation_performed, t),
            },
            {
              label: t('pdfValidator.field.embeddedRevocation'),
              value: boolText(report.revocation.embedded_revocation_evidence_present, t),
            },
            { label: t('pdfValidator.field.qualification'), value: report.qualification.status },
            {
              label: t('pdfValidator.field.qualifiedStatusClaimed'),
              value: boolText(report.qualification.qualified_status_claimed, t),
            },
            {
              label: t('pdfValidator.field.legalValidity'),
              value: boolText(report.qualification.legal_validity_claimed, t),
            },
            {
              label: t('pdfValidator.field.legalEffectAssessed'),
              value: boolText(report.qualification.legal_effect_assessed, t),
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
