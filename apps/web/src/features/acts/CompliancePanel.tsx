/**
 * Live compliance panel (UX-43). Renders the result of `GET /v1/acts/:id/compliance`:
 * each issue shown with its rule id and the legal-basis message the rule pack emits,
 * severity-coded. `seal_allowed` (errors == 0 && state == Signing) is the single gate
 * the SealAction reads. Refetched by the query cache whenever the act is saved or
 * advanced, so it stays in step with edits.
 */
import type { ComplianceReport } from '../../api/types';
import { severityLabels } from '../../api/labels';
import { useT } from '../../i18n';
import { Badge, EmptyState, InlineWarning } from '../../ui';

export function CompliancePanel({ report }: { report: ComplianceReport }) {
  const t = useT();
  const clean = report.issues.length === 0;

  return (
    <div className="stack--tight">
      <div className="row-wrap">
        <span className="card__label">{t('compliance.rules', { rulePack: report.rule_pack })}</span>
        {report.errors > 0 ? (
          <Badge tone="error">
            {report.errors === 1
              ? t('compliance.errors.one', { count: report.errors })
              : t('compliance.errors.other', { count: report.errors })}
          </Badge>
        ) : null}
        {report.warnings > 0 ? (
          <Badge tone="warn">
            {report.warnings === 1
              ? t('compliance.warnings.one', { count: report.warnings })
              : t('compliance.warnings.other', { count: report.warnings })}
          </Badge>
        ) : null}
        {clean ? <Badge tone="ok">{t('compliance.conforme')}</Badge> : null}
      </div>

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
