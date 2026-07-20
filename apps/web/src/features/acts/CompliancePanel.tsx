/**
 * Live compliance panel (UX-43). Renders the result of `GET /v1/acts/:id/compliance`:
 * each issue shown with its rule id and the legal-basis message the rule pack emits,
 * severity-coded. `seal_allowed` (errors == 0 && state == Signing) is the single gate
 * the SealAction reads. Refetched by the query cache whenever the act is saved or
 * advanced, so it stays in step with edits.
 */
import type { MouseEvent } from 'react';
import { Link } from 'react-router-dom';
import type { ComplianceReport } from '../../api/types';
import { entityFamilyLabels, severityLabels } from '../../api/labels';
import { openExternal } from '../../desktop/openExternal';
import { t as translateNow, useT } from '../../i18n';
import { Badge, EmptyState, InlineWarning } from '../../ui';

type MetadataRecord = Record<string, unknown>;

interface SourceReference {
  label: string;
  href: string | null;
  linkKind: 'external' | 'internal' | null;
  verification: 'Verified' | 'Pending' | null;
}

type ConveningAdvisoryView = NonNullable<ComplianceReport['convening_advisories']>[number];

const CONVENING_NOTICE_NO_CLAIMS =
  'Aviso consultivo local sobre metadados registados; não afirma suficiência jurídica, entrega externa válida nem conclusão do workflow.';

const SOURCE_CONTAINER_KEYS = [
  'source',
  'sources',
  'source_ref',
  'source_refs',
  'source_reference',
  'source_references',
  'legal_source',
  'legal_sources',
  'legal_reference',
  'legal_references',
  'legal_basis',
  'law_ref',
  'law_refs',
  'reference',
  'references',
  'citation',
  'citations',
] as const;

const URL_KEYS = [
  'url',
  'href',
  'link',
  'source_url',
  'official_url',
  'law_url',
  'canonical_url',
  'source',
] as const;

const LABEL_KEYS = [
  'label',
  'title',
  'citation',
  'reference',
  'legal_reference',
  'article_ref',
  'provision',
  'anchor',
] as const;

const AUTHORITY_KEYS = ['authority', 'diploma', 'legal_source', 'source', 'source_label'] as const;
const ARTICLE_KEYS = ['article', 'article_label', 'article_ref', 'provision'] as const;

function asRecord(value: unknown): MetadataRecord | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as MetadataRecord)
    : null;
}

function asNonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function httpHref(value: string): string | null {
  try {
    const url = new URL(value);
    return url.protocol === 'http:' || url.protocol === 'https:' ? value : null;
  } catch {
    return null;
  }
}

function corpusHref(sourceId: string, article: string | null): string {
  const params = new URLSearchParams({ tool: 'legislacao', diploma: sourceId });
  if (article) params.set('artigo', article);
  return `/ferramentas?${params.toString()}`;
}

function firstString(record: MetadataRecord, keys: readonly string[]): string | null {
  for (const key of keys) {
    const value = asNonEmptyString(record[key]);
    if (value) return value;
  }
  return null;
}

function stringParts(record: MetadataRecord, keys: readonly string[]): string[] {
  const out: string[] = [];
  for (const key of keys) {
    const value = asNonEmptyString(record[key]);
    if (value && !out.includes(value)) out.push(value);
  }
  return out;
}

function parseSourceRecord(
  record: MetadataRecord,
  options: { corpusDeepLink?: boolean } = {},
): SourceReference | null {
  const urlText = firstString(record, URL_KEYS);
  const href = urlText ? httpHref(urlText) : null;
  const sourceId = options.corpusDeepLink ? asNonEmptyString(record.source_id) : null;
  const article = sourceId ? asNonEmptyString(record.article) : null;
  const internalHref = sourceId ? corpusHref(sourceId, article) : null;
  const structuredLabel = stringParts(record, AUTHORITY_KEYS)
    .concat(stringParts(record, ARTICLE_KEYS))
    .join(', ');
  const label = firstString(record, LABEL_KEYS) ?? (structuredLabel || urlText);

  if (!label && !urlText) return null;
  const visible = label || urlText || '';
  const pending =
    record.verification === 'Pending' ||
    record.source_complete === false ||
    record.complete === false;
  const verified =
    record.verification === 'Verified' &&
    record.source_complete !== false &&
    record.complete !== false;
  const pendingSuffix = pending ? ' · fonte pendente' : '';
  const unsafeUrl = urlText && !href && !visible.includes(urlText) ? ` (${urlText})` : '';
  return {
    label: `${visible}${pendingSuffix}${unsafeUrl}`,
    href: internalHref ?? href,
    linkKind: internalHref ? 'internal' : href ? 'external' : null,
    verification: pending ? 'Pending' : verified ? 'Verified' : null,
  };
}

function parseSourceValue(
  value: unknown,
  options: { corpusDeepLink?: boolean } = {},
): SourceReference[] {
  const text = asNonEmptyString(value);
  if (text) {
    const href = httpHref(text);
    return [{ label: text, href, linkKind: href ? 'external' : null, verification: null }];
  }

  if (Array.isArray(value)) return value.flatMap((item) => parseSourceValue(item, options));

  const record = asRecord(value);
  if (!record) return [];

  const parsed = parseSourceRecord(record, options);
  return parsed ? [parsed] : [];
}

function sourceReferences(value: unknown): SourceReference[] {
  const record = asRecord(value);
  if (!record) return [];

  const refs: SourceReference[] = [];
  const direct = parseSourceRecord(record);
  if (direct) refs.push(direct);

  for (const key of SOURCE_CONTAINER_KEYS) {
    refs.push(...parseSourceValue(record[key], { corpusDeepLink: key === 'legal_basis' }));
  }

  const seen = new Set<string>();
  return refs.filter((ref) => {
    const key = `${ref.href ?? ''}\u0000${ref.label}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function SourceReferences({ references }: { references: SourceReference[] }) {
  const t = useT();
  if (references.length === 0) return null;
  const sourceLabel = t('legislacao.corpus.article.source');

  return (
    <div className="row-wrap muted" aria-label={sourceLabel} style={{ marginTop: '0.35rem' }}>
      <span>{sourceLabel}</span>
      {references.map((ref, i) => {
        const href = ref.href;
        return (
          <span key={`${href ?? ''}-${ref.label}-${i}`} className="source-reference">
            {href ? (
              ref.linkKind === 'internal' ? (
                <Link
                  className="mono truncate"
                  to={href}
                  title={ref.label}
                  aria-label={`${t('common.open')}: ${ref.label}`}
                  style={{ maxWidth: 'min(100%, 28rem)' }}
                >
                  {ref.label}
                </Link>
              ) : (
                <a
                  className="mono truncate"
                  href={href}
                  target="_blank"
                  rel="noreferrer noopener"
                  title={ref.label}
                  aria-label={`${t('common.open')}: ${ref.label}`}
                  style={{ maxWidth: 'min(100%, 28rem)' }}
                  onClick={(e: MouseEvent<HTMLAnchorElement>) => {
                    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
                    e.preventDefault();
                    void openExternal(href);
                  }}
                >
                  {ref.label}
                </a>
              )
            ) : (
              <span
                className="mono truncate"
                title={ref.label}
                aria-label={`${sourceLabel}: ${ref.label}`}
                style={{ maxWidth: 'min(100%, 28rem)' }}
              >
                {ref.label}
              </span>
            )}
            {ref.verification ? (
              <Badge tone={ref.verification === 'Verified' ? 'ok' : 'warn'}>
                {ref.verification === 'Verified'
                  ? t('legislacao.corpus.badge.verified')
                  : t('legislacao.corpus.badge.pending')}
              </Badge>
            ) : null}
          </span>
        );
      })}
    </div>
  );
}

function writtenResolutionStatusLabel(
  t: ReturnType<typeof useT>,
  status: string | null | undefined,
): string {
  switch (status) {
    case 'bound_present':
      return t('compliance.writtenResolution.status.boundPresent');
    case 'referenced_only':
      return t('compliance.writtenResolution.status.referencedOnly');
    case 'missing':
      return t('compliance.writtenResolution.status.missing');
    case 'not_applicable':
      return t('compliance.writtenResolution.status.notApplicable');
    case 'reviewed':
      return t('compliance.writtenResolution.status.reviewed');
    case 'needs_follow_up':
      return t('compliance.writtenResolution.status.needsFollowUp');
    default:
      return status?.trim() || t('compliance.writtenResolution.status.notRecorded');
  }
}

function WrittenResolutionEvidenceReview({
  status,
}: {
  status: ComplianceReport['written_resolution_evidence_status'];
}) {
  const t = useT();
  if (!status || status.status === 'not_applicable') return null;
  const hasReviewReceipt = status.review_receipts > 0;

  return (
    <section
      className="written-resolution-review"
      aria-label={t('compliance.writtenResolution.review.label')}
    >
      <div className="row-wrap">
        <span className="card__label">{t('compliance.writtenResolution.review.label')}</span>
        <Badge tone={hasReviewReceipt ? 'ok' : 'warn'}>
          {hasReviewReceipt
            ? t('compliance.writtenResolution.review.receiptRecorded')
            : t('compliance.writtenResolution.review.receiptMissing')}
        </Badge>
        <Badge
          tone={status.bound_count > 0 ? 'ok' : status.referenced_only_count > 0 ? 'warn' : 'error'}
        >
          {writtenResolutionStatusLabel(t, status.status)}
        </Badge>
        {status.latest_review_status ? (
          <Badge tone={status.latest_review_status === 'reviewed' ? 'ok' : 'warn'}>
            {writtenResolutionStatusLabel(t, status.latest_review_status)}
          </Badge>
        ) : null}
      </div>
      <dl className="deflist deflist--tight">
        <div>
          <dt>{t('compliance.writtenResolution.review.reviewReceipts')}</dt>
          <dd>{status.review_receipts}</dd>
        </div>
        <div>
          <dt>{t('compliance.writtenResolution.review.reviewedLocators')}</dt>
          <dd>{status.reviewed_evidence_locators}</dd>
        </div>
        <div>
          <dt>{t('compliance.writtenResolution.review.reviewedDigests')}</dt>
          <dd>{status.reviewed_evidence_digests}</dd>
        </div>
        <div>
          <dt>{t('compliance.writtenResolution.review.boundEvidence')}</dt>
          <dd>{status.bound_count}</dd>
        </div>
      </dl>
      <p className="muted">{t('compliance.writtenResolution.review.boundary')}</p>
    </section>
  );
}

function conveningAdvisoryNextRecord(advisory: ConveningAdvisoryView): string {
  if (advisory.code === 'convening.statute_notice.missing_actual' || advisory.actual_days == null) {
    return 'Confirme a data da reunião e registe data/meio de expedição, antecedência efetiva e prova conservada.';
  }

  return 'Reveja a antecedência registada face ao limiar estatutário local e associe a prova de expedição conservada.';
}

function ConveningAdvisoryGuidance({ advisory }: { advisory: ConveningAdvisoryView }) {
  return (
    <dl
      className="deflist deflist--tight"
      aria-label={translateNow('uiLiteral.compliancePanel.orientacaoLocalDaConvocatoria')}
    >
      <div>
        <dt>{translateNow('uiLiteral.compliancePanel.proximoRegistoLocal')}</dt>
        <dd>{conveningAdvisoryNextRecord(advisory)}</dd>
      </div>
      <div>
        <dt>{translateNow('uiLiteral.compliancePanel.limitesDoAviso')}</dt>
        <dd>{CONVENING_NOTICE_NO_CLAIMS}</dd>
      </div>
    </dl>
  );
}

export function CompliancePanel({ report }: { report: ComplianceReport }) {
  const t = useT();
  const conveningAdvisories = report.convening_advisories ?? [];
  const warningCount = report.warnings + conveningAdvisories.length;
  const clean = report.issues.length === 0 && conveningAdvisories.length === 0;

  return (
    <div className="stack--tight">
      <div className="row-wrap">
        <span className="card__label">{t('compliance.rules', { rulePack: report.rule_pack })}</span>
        <Badge tone="neutral">
          {t('compliance.family', { family: entityFamilyLabels[report.family] })}
        </Badge>
        {report.statute_overlay ? (
          <Badge tone="accent">{t('compliance.statuteOverlay')}</Badge>
        ) : null}
        {report.errors > 0 ? (
          <Badge tone="error">
            {report.errors === 1
              ? t('compliance.errors.one', { count: report.errors })
              : t('compliance.errors.other', { count: report.errors })}
          </Badge>
        ) : null}
        {warningCount > 0 ? (
          <Badge tone="warn">
            {warningCount === 1
              ? t('compliance.warnings.one', { count: warningCount })
              : t('compliance.warnings.other', { count: warningCount })}
          </Badge>
        ) : null}
        {clean ? <Badge tone="ok">{t('compliance.conforme')}</Badge> : null}
      </div>

      <WrittenResolutionEvidenceReview status={report.written_resolution_evidence_status} />

      {clean ? (
        <EmptyState title={t('compliance.noIssues')} />
      ) : (
        <ul className="issues">
          {report.issues.map((issue, i) => (
            <li
              key={`${issue.rule_id}-${i}`}
              className={`issue issue--${issue.severity.toLowerCase()}`}
            >
              <div className="issue__head">
                <Badge tone={issue.severity === 'Error' ? 'error' : 'warn'}>
                  {severityLabels[issue.severity]}
                </Badge>
                <code className="mono">{issue.rule_id}</code>
              </div>
              <p className="issue__message">{issue.message}</p>
              <SourceReferences references={sourceReferences(issue)} />
            </li>
          ))}
          {conveningAdvisories.map((advisory, i) => (
            <li
              key={`${advisory.code}-${i}`}
              className={`issue issue--${advisory.severity.toLowerCase()}`}
            >
              <div className="issue__head">
                <Badge tone={advisory.severity === 'Error' ? 'error' : 'warn'}>
                  {severityLabels[advisory.severity]}
                </Badge>
                <code className="mono">{advisory.code}</code>
                <code className="mono">{advisory.threshold_id}</code>
              </div>
              <p className="issue__message">{advisory.message}</p>
              <ConveningAdvisoryGuidance advisory={advisory} />
              <SourceReferences references={sourceReferences(advisory)} />
            </li>
          ))}
        </ul>
      )}

      {!clean && report.errors > 0 ? (
        <InlineWarning tone="info">{t('compliance.sealBlocked')}</InlineWarning>
      ) : null}
    </div>
  );
}
