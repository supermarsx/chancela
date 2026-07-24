/**
 * The PDF/PAdES validation report as a single verdict table.
 *
 * The report used to render as a grid of key/value boxes inside eight collapsible
 * sections — roughly a hundred little cards, none of them aligned, so an operator could
 * not scan "what failed and why" without opening every section and reading each box.
 *
 * Row model: **one row per check, grouped by a full-width group header row.** The report
 * is a tree (document → section → check; and for the LTV plan, document → signature →
 * check), and the flattening is what made the cards chaotic. A row per *signature* was
 * the alternative, but almost all of this report is document-level — structure, byte
 * range, CAdES, DSS, trust — so a signature-keyed table would have hidden the bulk of it
 * back inside expanders. Instead the hierarchy survives as grouping: each section, and
 * each individual signature and DocTimeStamp, is its own labelled group of rows, and the
 * verdict for every check lines up in one scannable column.
 *
 * Verdicts are never colour-only: each cell carries a text label ("Conforme" / "Falha" /
 * "Inconclusivo" / "Informativo") next to the icon, so the result survives greyscale
 * printing and colour-blind reading. `info` is a deliberate fourth state — a measured
 * fact such as a version string, a digest or a marker count is not a pass, and painting
 * it green would overstate what the validator checked. Likewise the "legal validity" and
 * "qualified status" fields are informational: this tool reports local technical
 * evidence, and a `false` there is the intended answer, not a failure.
 *
 * Explanatory detail is not dropped for tightness: the failure reason, the notice text
 * and the scope of each plan render as a secondary line under the check name, which is
 * the field an operator most needs — for a validator, *why* something failed matters
 * more than the fact that it did.
 */
import type { ReactNode } from 'react';
import type {
  DocTimeStampValidationReport,
  LocalTechnicalRenewalPlanReport,
  PdfSignatureValidationResponse,
} from '../../api/types';
import { useT, type TFunction } from '../../i18n';
import { Digest, Icon, Table } from '../../ui';
import {
  formatPdfValidatorBytes,
  pdfValidationEvidenceTone,
  pdfValidatorBoolText,
} from './PdfSignatureValidatorPanel';

export type ValidationVerdict = 'pass' | 'fail' | 'inconclusive' | 'info';

export interface ValidationCheckRow {
  key: string;
  label: string;
  verdict: ValidationVerdict;
  evidence: ReactNode;
  /** The reason / scope / notice line, rendered under the check name. */
  note?: ReactNode;
}

export interface ValidationCheckGroup {
  key: string;
  title: string;
  /** Group-level explanatory copy (plan notices, trust/revocation/qualification messages). */
  note?: string;
  rows: ValidationCheckRow[];
}

/** A boolean the specification requires to be true: false is a real non-conformity. */
function conformance(value: boolean): ValidationVerdict {
  return value ? 'pass' : 'fail';
}

/**
 * A boolean that records whether evidence exists. Absent evidence is not a failure —
 * a B-B signature legitimately carries no timestamp — so it reads as inconclusive.
 */
function presence(value: boolean): ValidationVerdict {
  return value ? 'pass' : 'inconclusive';
}

/** Map a backend status string onto a verdict, reusing the panel's tone vocabulary. */
export function statusVerdict(status: string): ValidationVerdict {
  const tone = pdfValidationEvidenceTone(status);
  if (tone === 'ok') return 'pass';
  if (tone === 'error') return 'fail';
  if (tone === 'warn') return 'inconclusive';
  return 'info';
}

export function validationVerdictLabel(verdict: ValidationVerdict, t: TFunction): string {
  if (verdict === 'pass') return t('pdfValidator.verdict.pass');
  if (verdict === 'fail') return t('pdfValidator.verdict.fail');
  if (verdict === 'inconclusive') return t('pdfValidator.verdict.inconclusive');
  return t('pdfValidator.verdict.info');
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

const DASH = '—';

/** The shared rows of a local technical renewal plan, document-level or per signature. */
function renewalPlanRows(
  prefix: string,
  plan: LocalTechnicalRenewalPlanReport,
  t: TFunction,
): ValidationCheckRow[] {
  return [
    {
      key: `${prefix}-timestamp`,
      label: t('pdfValidator.field.signatureTimestamp'),
      verdict: presence(plan.signature_timestamp_present),
      evidence: pdfValidatorBoolText(plan.signature_timestamp_present, t),
    },
    {
      key: `${prefix}-revocation`,
      label: t('pdfValidator.field.revocationEvidence'),
      verdict: presence(plan.dss_revocation_evidence_present),
      evidence: pdfValidatorBoolText(plan.dss_revocation_evidence_present, t),
    },
    {
      key: `${prefix}-dss-time`,
      label: t('pdfValidator.field.dssValidationTime'),
      verdict: presence(plan.dss_validation_time_present),
      evidence: pdfValidatorBoolText(plan.dss_validation_time_present, t),
    },
    {
      key: `${prefix}-doc-ts`,
      label: t('pdfValidator.section.docTimestamp'),
      verdict: presence(plan.doc_timestamp_present),
      evidence: pdfValidatorBoolText(plan.doc_timestamp_present, t),
    },
    {
      key: `${prefix}-doc-ts-imprints`,
      label: t('pdfValidator.field.docTimestampImprints'),
      verdict: plan.doc_timestamp_present
        ? conformance(plan.doc_timestamp_imprints_valid)
        : 'inconclusive',
      evidence: pdfValidatorBoolText(plan.doc_timestamp_imprints_valid, t),
    },
    {
      key: `${prefix}-missing`,
      label: t('pdfValidator.field.missingInputs'),
      verdict: plan.missing_inputs.length ? 'inconclusive' : 'pass',
      evidence: <TextList values={plan.missing_inputs} emptyLabel={t('pdfValidator.value.none')} />,
    },
    {
      key: `${prefix}-next`,
      label: t('pdfValidator.field.nextAction'),
      verdict: 'info',
      evidence: <code className="mono">{plan.next_action}</code>,
    },
    {
      key: `${prefix}-gap`,
      label: t('pdfValidator.field.evidenceGaps'),
      verdict: plan.has_local_evidence_gap ? 'inconclusive' : 'pass',
      evidence: pdfValidatorBoolText(plan.has_local_evidence_gap, t),
    },
    {
      key: `${prefix}-inputs`,
      label: t('pdfValidator.field.allPlanningInputs'),
      verdict: presence(plan.all_local_planning_inputs_present),
      evidence: pdfValidatorBoolText(plan.all_local_planning_inputs_present, t),
    },
    // Claim fields are informational by design: this tool asserts local technical
    // evidence only, so `false` is the intended answer and must not read as a failure.
    {
      key: `${prefix}-profile`,
      label: t('pdfValidator.field.productionProfileClaimed'),
      verdict: 'info',
      evidence: pdfValidatorBoolText(plan.production_long_term_profile_claimed, t),
    },
    {
      key: `${prefix}-ltv`,
      label: t('pdfValidator.field.legalLtvClaimed'),
      verdict: 'info',
      evidence: pdfValidatorBoolText(plan.legal_ltv_claimed, t),
    },
  ];
}

function docTimestampGroup(
  validation: DocTimeStampValidationReport,
  t: TFunction,
): ValidationCheckGroup {
  const prefix = `docts-${validation.index}-${validation.object_id}`;
  return {
    key: prefix,
    title: `${t('pdfValidator.section.docTimestamp')} ${validation.index} · ${validation.object_id}`,
    rows: [
      {
        key: `${prefix}-status`,
        label: t('pdfValidator.section.docTimestamp'),
        verdict: statusVerdict(validation.status),
        evidence: <code className="mono">{validation.status}</code>,
        note: validation.failure_reason,
      },
      {
        key: `${prefix}-byte-range`,
        label: t('pdfValidator.field.byteRange'),
        verdict: 'info',
        evidence: validation.byte_range ? (
          <code className="mono">{validation.byte_range.join(', ')}</code>
        ) : (
          DASH
        ),
      },
      {
        key: `${prefix}-doc-digest`,
        label: t('pdfValidator.field.documentDigest'),
        verdict: 'info',
        evidence: validation.document_digest_sha256 ? (
          <Digest value={validation.document_digest_sha256} />
        ) : (
          DASH
        ),
      },
      {
        key: `${prefix}-imprint`,
        label: t('pdfValidator.field.tokenImprint'),
        verdict: 'info',
        evidence: validation.token_imprint_sha256 ? (
          <Digest value={validation.token_imprint_sha256} />
        ) : (
          DASH
        ),
      },
      {
        key: `${prefix}-algorithm`,
        label: t('pdfValidator.field.hashAlgorithm'),
        verdict: 'info',
        evidence: validation.token_hash_algorithm ?? DASH,
      },
      {
        key: `${prefix}-reason`,
        label: t('pdfValidator.field.failureReason'),
        verdict: validation.failure_reason ? 'fail' : 'info',
        evidence: validation.failure_reason ?? DASH,
      },
    ],
  };
}

/**
 * Flatten the report into ordered groups of checks. Exported so a test can assert the
 * row set without going through the DOM, and so the ordering stays reviewable in one place.
 */
export function buildValidationGroups(
  report: PdfSignatureValidationResponse,
  t: TFunction,
): ValidationCheckGroup[] {
  const sig = report.signature;
  const { byte_range: byteRange, cades, dss, doc_timestamp: docTs } = sig;
  const plan = sig.local_technical_renewal_plan;
  const multiPlan = sig.multi_signature_local_renewal_plan;
  const declaredMatches =
    (report.declared_sha256 === null || report.declared_sha256 === report.sha256) &&
    (report.declared_size_bytes === null || report.declared_size_bytes === report.size_bytes);
  const declaredPresent = report.declared_sha256 !== null || report.declared_size_bytes !== null;

  const groups: ValidationCheckGroup[] = [
    {
      key: 'file',
      title: t('pdfValidator.section.file'),
      rows: [
        {
          key: 'file-size',
          label: t('pdfValidator.field.size'),
          verdict: 'info',
          evidence: formatPdfValidatorBytes(report.size_bytes, t),
        },
        {
          key: 'file-sha256',
          label: t('pdfValidator.field.sha256'),
          verdict: 'info',
          evidence: <Digest value={report.sha256} />,
        },
        {
          key: 'file-declared-size',
          label: t('pdfValidator.field.declaredSize'),
          verdict: 'info',
          evidence:
            report.declared_size_bytes === null
              ? DASH
              : formatPdfValidatorBytes(report.declared_size_bytes, t),
        },
        {
          key: 'file-declared-sha256',
          label: t('pdfValidator.field.declaredSha256'),
          verdict: 'info',
          evidence: report.declared_sha256 ? <Digest value={report.declared_sha256} /> : DASH,
        },
        {
          key: 'file-integrity',
          label: t('pdfValidator.field.integrity'),
          verdict: declaredPresent ? conformance(declaredMatches) : 'inconclusive',
          evidence: pdfValidatorBoolText(declaredMatches, t),
          note: declaredMatches ? undefined : t('pdfValidator.mismatch.body'),
        },
      ],
    },
    {
      key: 'structure',
      title: t('pdfValidator.section.structure'),
      rows: [
        {
          key: 'structure-is-pdf',
          label: t('pdfValidator.field.isPdf'),
          verdict: conformance(report.structure.is_pdf),
          evidence: pdfValidatorBoolText(report.structure.is_pdf, t),
        },
        {
          key: 'structure-version',
          label: t('pdfValidator.field.version'),
          verdict: 'info',
          evidence: report.structure.version ?? DASH,
        },
        {
          key: 'structure-header-offset',
          label: t('pdfValidator.field.headerOffset'),
          verdict: 'info',
          evidence: report.structure.header_offset ?? DASH,
        },
        {
          key: 'structure-eof',
          label: t('pdfValidator.field.eof'),
          verdict: conformance(report.structure.has_eof_marker),
          evidence: pdfValidatorBoolText(report.structure.has_eof_marker, t),
        },
        {
          key: 'structure-startxref',
          label: t('pdfValidator.field.startxref'),
          verdict: conformance(report.structure.has_startxref),
          evidence: pdfValidatorBoolText(report.structure.has_startxref, t),
        },
      ],
    },
    {
      key: 'signature',
      title: t('pdfValidator.section.signature'),
      rows: [
        {
          key: 'signature-performed',
          label: t('pdfValidator.field.validationPerformed'),
          verdict: presence(sig.validation_performed),
          evidence: pdfValidatorBoolText(sig.validation_performed, t),
          // The parser's own error is the single most useful line in the report when it
          // is set, so it rides with the check rather than hiding in a collapsed section.
          note: sig.validation_error,
        },
        {
          key: 'signature-pades',
          label: t('pdfValidator.field.pades'),
          verdict: 'info',
          evidence: sig.pades_profile ?? DASH,
        },
        {
          key: 'signature-markers',
          label: t('pdfValidator.field.signatureMarkers'),
          verdict: 'info',
          evidence: sig.signature_marker_count,
        },
        {
          key: 'signature-byte-range-markers',
          label: t('pdfValidator.field.byteRangeMarkers'),
          verdict: 'info',
          evidence: sig.byte_range_marker_count,
        },
        {
          key: 'signature-contents',
          label: t('pdfValidator.field.contentsMarker'),
          verdict: conformance(sig.has_contents_marker),
          evidence: pdfValidatorBoolText(sig.has_contents_marker, t),
        },
        {
          key: 'signature-timestamp',
          label: t('pdfValidator.field.signatureTimestamp'),
          verdict: presence(sig.timestamp.signature_timestamp_present),
          evidence: pdfValidatorBoolText(sig.timestamp.signature_timestamp_present, t),
          note: sig.timestamp.status_scope,
        },
      ],
    },
  ];

  if (byteRange) {
    groups.push({
      key: 'byte-range',
      title: t('pdfValidator.field.byteRange'),
      rows: [
        {
          key: 'byte-range-value',
          label: t('pdfValidator.field.byteRange'),
          verdict: 'info',
          evidence: <code className="mono">{byteRange.byte_range.join(', ')}</code>,
        },
        {
          key: 'byte-range-coverage',
          label: t('pdfValidator.field.coverage'),
          verdict: 'info',
          evidence: t('pdfValidator.value.coverage', {
            covered: byteRange.covered_len,
            total: byteRange.total_len,
          }),
        },
        {
          key: 'byte-range-later-updates',
          label: t('pdfValidator.field.laterUpdates'),
          // Incremental updates after a signature are legal in PAdES: reporting them as a
          // failure would cry wolf on every correctly counter-signed document.
          verdict: 'info',
          evidence: pdfValidatorBoolText(byteRange.has_later_incremental_updates, t),
        },
        {
          key: 'byte-range-signed-revision',
          label: t('pdfValidator.field.signedRevision'),
          verdict: 'info',
          evidence: byteRange.signed_revision_len,
        },
        {
          key: 'byte-range-excluded',
          label: t('pdfValidator.field.excludedBytes'),
          verdict: 'info',
          evidence: byteRange.excluded_len ?? DASH,
        },
        {
          key: 'byte-range-covers-file',
          label: t('pdfValidator.field.coversWholeFile'),
          verdict: conformance(byteRange.covers_whole_file_except_contents),
          evidence: pdfValidatorBoolText(byteRange.covers_whole_file_except_contents, t),
        },
        {
          key: 'byte-range-covers-revision',
          label: t('pdfValidator.field.coversSignedRevision'),
          verdict: conformance(byteRange.covers_signed_revision_except_contents),
          evidence: pdfValidatorBoolText(byteRange.covers_signed_revision_except_contents, t),
        },
        {
          key: 'byte-range-digest',
          label: t('pdfValidator.field.signedRevisionDigest'),
          verdict: 'info',
          evidence: byteRange.digest_sha256 ? <Digest value={byteRange.digest_sha256} /> : DASH,
        },
      ],
    });
  }

  if (cades) {
    groups.push({
      key: 'cades',
      title: t('pdfValidator.field.cades'),
      rows: [
        {
          key: 'cades-status',
          label: t('pdfValidator.field.cades'),
          verdict: statusVerdict(cades.status),
          evidence: <code className="mono">{cades.status}</code>,
        },
        {
          key: 'cades-signing-certificate',
          label: t('pdfValidator.field.signingCertificate'),
          verdict: conformance(cades.signing_certificate_v2_present),
          evidence: pdfValidatorBoolText(cades.signing_certificate_v2_present, t),
        },
        {
          key: 'cades-subject',
          label: t('pdfValidator.field.signerSubject'),
          verdict: 'info',
          evidence: cades.signer_cert_subject ?? DASH,
        },
        {
          key: 'cades-cert-digest',
          label: t('pdfValidator.field.signerCertDigest'),
          verdict: 'info',
          evidence: <Digest value={cades.signer_cert_sha256} />,
        },
        {
          key: 'cades-signing-time',
          label: t('pdfValidator.field.signingTime'),
          verdict: 'info',
          evidence: cades.signing_time ?? DASH,
        },
      ],
    });
  }

  groups.push({
    key: 'dss',
    title: t('pdfValidator.section.dss'),
    rows: [
      {
        key: 'dss-present',
        label: t('pdfValidator.field.dssPresent'),
        verdict: presence(dss.present),
        evidence: pdfValidatorBoolText(dss.present, t),
        note: dss.status_scope,
      },
      {
        key: 'dss-vri',
        label: t('pdfValidator.field.vri'),
        verdict: 'info',
        evidence: dss.vri_count,
      },
      {
        key: 'dss-vri-tu',
        label: t('pdfValidator.field.vriTu'),
        verdict: 'info',
        evidence: dss.vri_tu_count,
      },
      {
        key: 'dss-vri-tu-keys',
        label: t('pdfValidator.field.vriTuKeys'),
        verdict: 'info',
        evidence: <TextList values={dss.vri_tu_keys} emptyLabel={t('pdfValidator.value.none')} />,
      },
      {
        key: 'dss-certificates',
        label: t('pdfValidator.field.certificates'),
        verdict: 'info',
        evidence: dss.certificate_count,
      },
      {
        key: 'dss-ocsp',
        label: t('pdfValidator.field.ocsp'),
        verdict: 'info',
        evidence: dss.ocsp_count,
      },
      {
        key: 'dss-crl',
        label: t('pdfValidator.field.crl'),
        verdict: 'info',
        evidence: dss.crl_count,
      },
      {
        key: 'dss-revocation',
        label: t('pdfValidator.field.revocationEvidence'),
        verdict: presence(dss.revocation_evidence_present),
        evidence: pdfValidatorBoolText(dss.revocation_evidence_present, t),
      },
      {
        key: 'dss-scope',
        label: t('pdfValidator.field.statusScope'),
        verdict: 'info',
        evidence: <code className="mono">{dss.status_scope}</code>,
      },
      {
        key: 'dss-certificate-hashes',
        label: t('pdfValidator.field.certificateHashes'),
        verdict: 'info',
        evidence: (
          <DigestList values={dss.certificate_sha256} emptyLabel={t('pdfValidator.value.none')} />
        ),
      },
      {
        key: 'dss-ocsp-hashes',
        label: t('pdfValidator.field.ocspHashes'),
        verdict: 'info',
        evidence: <DigestList values={dss.ocsp_sha256} emptyLabel={t('pdfValidator.value.none')} />,
      },
      {
        key: 'dss-crl-hashes',
        label: t('pdfValidator.field.crlHashes'),
        verdict: 'info',
        evidence: <DigestList values={dss.crl_sha256} emptyLabel={t('pdfValidator.value.none')} />,
      },
    ],
  });

  groups.push({
    key: 'doc-timestamp',
    title: t('pdfValidator.section.docTimestamp'),
    rows: [
      {
        key: 'doc-timestamp-present',
        label: t('pdfValidator.field.present'),
        verdict: presence(docTs.present),
        evidence: pdfValidatorBoolText(docTs.present, t),
      },
      {
        key: 'doc-timestamp-count',
        label: t('pdfValidator.field.count'),
        verdict: 'info',
        evidence: docTs.count,
      },
      {
        key: 'doc-timestamp-tokens',
        label: t('pdfValidator.field.tokens'),
        verdict: 'info',
        evidence: docTs.token_count,
      },
      {
        key: 'doc-timestamp-imprints',
        label: t('pdfValidator.field.imprints'),
        verdict: docTs.present ? conformance(docTs.all_imprints_valid) : 'inconclusive',
        evidence: pdfValidatorBoolText(docTs.all_imprints_valid, t),
      },
      {
        key: 'doc-timestamp-scope',
        label: t('pdfValidator.field.statusScope'),
        verdict: 'info',
        evidence: <code className="mono">{docTs.status_scope}</code>,
      },
      {
        key: 'doc-timestamp-hashes',
        label: t('pdfValidator.field.tokenHashes'),
        verdict: 'info',
        evidence: (
          <DigestList values={docTs.token_sha256} emptyLabel={t('pdfValidator.value.none')} />
        ),
      },
    ],
  });

  for (const validation of docTs.validations) {
    groups.push(docTimestampGroup(validation, t));
  }

  groups.push({
    key: 'renewal-plan',
    title: t('pdfValidator.section.renewalPlan'),
    note: plan.notice,
    rows: [
      {
        key: 'renewal-plan-status',
        label: t('pdfValidator.field.renewalPlan'),
        verdict: statusVerdict(plan.status),
        evidence: <code className="mono">{plan.status}</code>,
        note: plan.scope,
      },
      ...renewalPlanRows('renewal-plan', plan, t),
    ],
  });

  groups.push({
    key: 'multi-plan',
    title: t('pdfValidator.section.signatures'),
    note: multiPlan.notice,
    rows: [
      {
        key: 'multi-plan-status',
        label: t('pdfValidator.field.multiSignaturePlan'),
        verdict: statusVerdict(multiPlan.status),
        evidence: <code className="mono">{multiPlan.status}</code>,
        note: multiPlan.scope,
      },
      {
        key: 'multi-plan-count',
        label: t('pdfValidator.field.signatureCount'),
        verdict: 'info',
        evidence: multiPlan.signature_count,
      },
      {
        key: 'multi-plan-gaps',
        label: t('pdfValidator.field.signaturesWithGaps'),
        verdict: multiPlan.signatures_with_local_evidence_gaps.length ? 'inconclusive' : 'pass',
        evidence: (
          <TextList
            values={multiPlan.signatures_with_local_evidence_gaps.map(String)}
            emptyLabel={t('pdfValidator.value.none')}
          />
        ),
      },
      {
        key: 'multi-plan-next',
        label: t('pdfValidator.field.nextAction'),
        verdict: 'info',
        evidence: <code className="mono">{multiPlan.next_action}</code>,
      },
      {
        key: 'multi-plan-gap',
        label: t('pdfValidator.field.evidenceGaps'),
        verdict: multiPlan.has_local_evidence_gap ? 'inconclusive' : 'pass',
        evidence: pdfValidatorBoolText(multiPlan.has_local_evidence_gap, t),
      },
      {
        key: 'multi-plan-inputs',
        label: t('pdfValidator.field.allPlanningInputs'),
        verdict: presence(multiPlan.all_local_planning_inputs_present),
        evidence: pdfValidatorBoolText(multiPlan.all_local_planning_inputs_present, t),
      },
      {
        key: 'multi-plan-profile',
        label: t('pdfValidator.field.productionProfileClaimed'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(multiPlan.production_long_term_profile_claimed, t),
      },
      {
        key: 'multi-plan-ltv',
        label: t('pdfValidator.field.legalLtvClaimed'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(multiPlan.legal_ltv_claimed, t),
      },
    ],
  });

  // One group per signature: this is the part of the report that really is per-signature,
  // and keeping each in its own labelled block is what stops a multi-signature document
  // from collapsing into an unattributable list of checks.
  for (const signature of multiPlan.signatures) {
    const signaturePlan = signature.local_technical_renewal_plan;
    const prefix = `signature-${signature.index}-${signature.object_id}`;
    groups.push({
      key: prefix,
      title: `${t('pdfValidator.signature.item', { index: signature.index })} · ${signature.object_id}`,
      note: signaturePlan.notice,
      rows: [
        {
          key: `${prefix}-status`,
          label: t('pdfValidator.field.renewalPlan'),
          verdict: statusVerdict(signaturePlan.status),
          evidence: <code className="mono">{signaturePlan.status}</code>,
          note: signaturePlan.scope,
        },
        {
          key: `${prefix}-revision`,
          label: t('pdfValidator.field.signedRevision'),
          verdict: 'info',
          evidence: signature.signed_revision_len,
        },
        {
          key: `${prefix}-vri-key`,
          label: t('pdfValidator.field.vriKey'),
          verdict: 'info',
          evidence: <Digest value={signature.vri_key_sha256} />,
        },
        {
          key: `${prefix}-dss-vri`,
          label: t('pdfValidator.field.dssVri'),
          verdict: presence(signature.dss_vri_present),
          evidence: pdfValidatorBoolText(signature.dss_vri_present, t),
        },
        {
          key: `${prefix}-dss-vri-time`,
          label: t('pdfValidator.field.dssVriValidationTime'),
          verdict: presence(signature.dss_vri_validation_time_present),
          evidence: pdfValidatorBoolText(signature.dss_vri_validation_time_present, t),
        },
        // Exactly the plan fields the per-signature card carried. The full renewal-plan
        // input list stays at document level: repeating all eleven rows per signature
        // would restore the noise the cards were criticised for.
        {
          key: `${prefix}-missing`,
          label: t('pdfValidator.field.missingInputs'),
          verdict: signaturePlan.missing_inputs.length ? 'inconclusive' : 'pass',
          evidence: (
            <TextList
              values={signaturePlan.missing_inputs}
              emptyLabel={t('pdfValidator.value.none')}
            />
          ),
        },
        {
          key: `${prefix}-next`,
          label: t('pdfValidator.field.nextAction'),
          verdict: 'info',
          evidence: <code className="mono">{signaturePlan.next_action}</code>,
        },
        {
          key: `${prefix}-ltv`,
          label: t('pdfValidator.field.legalLtvClaimed'),
          verdict: 'info',
          evidence: pdfValidatorBoolText(signaturePlan.legal_ltv_claimed, t),
        },
      ],
    });
  }

  groups.push({
    key: 'trust',
    title: t('pdfValidator.section.trust'),
    rows: [
      {
        key: 'trust-status',
        label: t('pdfValidator.field.trust'),
        verdict: statusVerdict(report.trust.status),
        evidence: <code className="mono">{report.trust.status}</code>,
        note: report.trust.message,
      },
      {
        key: 'trust-performed',
        label: t('pdfValidator.field.trustPerformed'),
        verdict: presence(report.trust.performed),
        evidence: pdfValidatorBoolText(report.trust.performed, t),
      },
      // Live TSL and AMA lookups are deliberately out of scope for the local validator,
      // so their `false` is a statement of scope, not a failed check.
      {
        key: 'trust-live-tsl',
        label: t('pdfValidator.field.liveTsl'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.trust.live_trusted_list_validation_performed, t),
      },
      {
        key: 'trust-ama',
        label: t('pdfValidator.field.ama'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.trust.ama_integration_performed, t),
      },
      {
        key: 'revocation-status',
        label: t('pdfValidator.field.revocation'),
        verdict: statusVerdict(report.revocation.status),
        evidence: <code className="mono">{report.revocation.status}</code>,
        note: report.revocation.message,
      },
      {
        key: 'revocation-live-fetch',
        label: t('pdfValidator.field.liveFetch'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.revocation.live_fetch_performed, t),
      },
      {
        key: 'revocation-freshness',
        label: t('pdfValidator.field.revocationFreshness'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.revocation.freshness_validation_performed, t),
      },
      {
        key: 'revocation-embedded',
        label: t('pdfValidator.field.embeddedRevocation'),
        verdict: presence(report.revocation.embedded_revocation_evidence_present),
        evidence: pdfValidatorBoolText(report.revocation.embedded_revocation_evidence_present, t),
      },
      {
        key: 'qualification-status',
        label: t('pdfValidator.field.qualification'),
        verdict: statusVerdict(report.qualification.status),
        evidence: <code className="mono">{report.qualification.status}</code>,
        note: report.qualification.message,
      },
      {
        key: 'qualification-claimed',
        label: t('pdfValidator.field.qualifiedStatusClaimed'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.qualification.qualified_status_claimed, t),
      },
      {
        key: 'qualification-legal-validity',
        label: t('pdfValidator.field.legalValidity'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.qualification.legal_validity_claimed, t),
      },
      {
        key: 'qualification-legal-effect',
        label: t('pdfValidator.field.legalEffectAssessed'),
        verdict: 'info',
        evidence: pdfValidatorBoolText(report.qualification.legal_effect_assessed, t),
      },
    ],
  });

  groups.push({
    key: 'findings',
    title: t('pdfValidator.section.findings'),
    rows: report.findings.length
      ? report.findings.map((finding, index) => ({
          key: `finding-${index}-${finding.code}`,
          label: finding.code,
          verdict:
            finding.severity === 'error'
              ? ('fail' as const)
              : finding.severity === 'warning'
                ? ('inconclusive' as const)
                : ('info' as const),
          evidence: finding.message,
          note: finding.severity,
        }))
      : [
          {
            key: 'findings-none',
            label: t('pdfValidator.section.findings'),
            verdict: 'pass' as const,
            evidence: t('pdfValidator.findings.none'),
          },
        ],
  });

  return groups;
}

function VerdictCell({ verdict }: { verdict: ValidationVerdict }) {
  const t = useT();
  return (
    <td className="pdf-validator-verdict" data-verdict={verdict}>
      <span className="pdf-validator-verdict__pill">
        {verdict === 'info' ? null : (
          <span className="pdf-validator-verdict__mark" aria-hidden="true">
            {verdict === 'pass' ? (
              <Icon.Check />
            ) : verdict === 'fail' ? (
              <Icon.Close />
            ) : (
              <Icon.Info />
            )}
          </span>
        )}
        {/* The label is the verdict: colour and icon only reinforce it, so the table
            still reads correctly in greyscale and for colour-blind operators. */}
        <span className="pdf-validator-verdict__label">{validationVerdictLabel(verdict, t)}</span>
      </span>
    </td>
  );
}

export function PdfValidationResultTable({ report }: { report: PdfSignatureValidationResponse }) {
  const t = useT();
  const groups = buildValidationGroups(report, t);

  return (
    <div className="pdf-validator-table">
      <Table
        caption={t('pdfValidator.table.caption')}
        head={
          <tr>
            <th scope="col" data-validator-column="Check">
              {t('pdfValidator.table.check')}
            </th>
            <th scope="col" data-validator-column="Verdict">
              {t('pdfValidator.table.verdict')}
            </th>
            <th scope="col" data-validator-column="Evidence">
              {t('pdfValidator.table.evidence')}
            </th>
          </tr>
        }
      >
        {groups.flatMap((group) => [
          <tr key={group.key} className="pdf-validator-table__group">
            <th scope="colgroup" colSpan={3}>
              <span className="pdf-validator-table__group-title">{group.title}</span>
              {group.note ? (
                <span className="pdf-validator-table__group-note">{group.note}</span>
              ) : null}
            </th>
          </tr>,
          ...group.rows.map((row) => (
            <tr key={row.key} data-validator-row={row.key}>
              <th scope="row" className="pdf-validator-table__check">
                <span className="pdf-validator-table__check-label">{row.label}</span>
                {row.note ? (
                  <span className="pdf-validator-table__check-note">{row.note}</span>
                ) : null}
              </th>
              <VerdictCell verdict={row.verdict} />
              <td className="pdf-validator-table__evidence">{row.evidence}</td>
            </tr>
          )),
        ])}
      </Table>
    </div>
  );
}
