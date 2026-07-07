/**
 * Painel — the WFL-40 dashboard subset (plan t5 §2.7). Counts, the chain-valid
 * indicator, an unresolved-compliance callout, and the last ledger events. Everything
 * is derived from `GET /v1/dashboard`, which the seal/mutation hooks invalidate, so
 * the numbers stay live.
 */
import { Link } from 'react-router-dom';
import { useDashboard } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Badge,
  Card,
  ErrorNote,
  InlineWarning,
  PageHeader,
  SkeletonCards,
  SkeletonTable,
} from '../../ui';
import { LedgerTable } from '../ledger/LedgerTable';

function Metric({ label, value, note }: { label: string; value: number | string; note?: string }) {
  return (
    <li className="card">
      <p className="card__label">{label}</p>
      <p className="card__metric">{value}</p>
      {note ? <p className="card__note">{note}</p> : null}
    </li>
  );
}

export function DashboardPage() {
  const t = useT();
  const { data, isLoading, error } = useDashboard();

  if (isLoading) {
    return (
      <div className="stack">
        <PageHeader title={t('dashboard.title')} />
        <SkeletonCards />
        <Card title={t('dashboard.recentEvents.title')}>
          <SkeletonTable cols={5} />
        </Card>
      </div>
    );
  }
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;

  return (
    <div className="stack">
      <PageHeader title={t('dashboard.title')} />

      <ul className="cards">
        <Metric label={t('dashboard.metric.entities')} value={data.entities} />
        <Metric
          label={t('dashboard.metric.booksOpen')}
          value={data.books_open}
          note={t('dashboard.metric.booksOpen.note', { total: data.books_total })}
        />
        <Metric
          label={t('dashboard.metric.actsDraft')}
          value={data.acts_draft}
          note={t('dashboard.metric.actsDraft.note', { total: data.acts_total })}
        />
        <Metric
          label={t('dashboard.metric.awaitingSignature')}
          value={data.acts_awaiting_signature}
          note={t('dashboard.metric.awaitingSignature.note')}
        />
        <Metric
          label={t('dashboard.metric.actsSealed')}
          value={data.acts_sealed}
          note={t('dashboard.metric.actsSealed.note')}
        />
        <Metric
          label={t('dashboard.metric.ledger')}
          value={data.ledger_length}
          note={
            data.ledger_valid
              ? t('dashboard.metric.ledger.note.valid')
              : t('dashboard.metric.ledger.note.invalid')
          }
        />
      </ul>

      <div className="row-wrap">
        <div className="chain-status">
          <span className="card__label">{t('dashboard.integrity.label')}</span>{' '}
          {data.ledger_valid ? (
            <Badge tone="ok">{t('dashboard.chain.verified')}</Badge>
          ) : (
            <Badge tone="error">{t('dashboard.chain.compromised')}</Badge>
          )}
        </div>
      </div>

      {data.unresolved_compliance > 0 ? (
        <InlineWarning tone="warn" title={t('dashboard.compliance.title')}>
          {data.unresolved_compliance === 1
            ? t('dashboard.compliance.body.one', { count: data.unresolved_compliance })
            : t('dashboard.compliance.body.other', { count: data.unresolved_compliance })}
        </InlineWarning>
      ) : null}

      <Card
        title={t('dashboard.recentEvents.title')}
        actions={<Link to="/arquivo">{t('dashboard.viewFullArchive')}</Link>}
      >
        <LedgerTable events={data.recent_events} />
      </Card>
    </div>
  );
}
