/**
 * Arquivo — the append-only ledger with its verify status. The chain-valid badge
 * comes from `GET /v1/ledger/verify`; the table from `GET /v1/ledger/events`. A
 * scope filter narrows to a single entity/book/act subtree (substring match, §2.6).
 */
import { useState } from 'react';
import { useLedger, useLedgerVerify } from '../../api/hooks';
import { useT } from '../../i18n';
import { Badge, Card, ErrorNote, Field, Input, PageHeader, SkeletonTable } from '../../ui';
import { LedgerTable } from './LedgerTable';

export function LedgerPage() {
  const t = useT();
  const [scope, setScope] = useState('');
  const verify = useLedgerVerify();
  const events = useLedger(scope ? { scope } : {});

  return (
    <div className="stack">
      <PageHeader title={t('ledger.page.title')} />

      <div className="row-wrap">
        <div className="chain-status">
          <span className="card__label">{t('ledger.integrity.label')}</span>{' '}
          {verify.isLoading ? (
            <Badge tone="neutral">{t('ledger.verify.checking')}</Badge>
          ) : verify.data?.valid ? (
            <Badge tone="ok">{t('ledger.chain.verified', { count: verify.data.length })}</Badge>
          ) : (
            <Badge tone="error">{t('ledger.chain.compromised')}</Badge>
          )}
        </div>
      </div>

      <Card
        title={t('ledger.events.title')}
        actions={
          <div className="filter">
            <Field label={t('ledger.scope.label')} htmlFor="ledger-scope">
              <Input
                id="ledger-scope"
                placeholder={t('ledger.scope.placeholder')}
                value={scope}
                onChange={(e) => setScope(e.target.value)}
              />
            </Field>
          </div>
        }
      >
        {events.isLoading ? (
          <SkeletonTable cols={6} />
        ) : events.error ? (
          <ErrorNote error={events.error} />
        ) : (
          <LedgerTable events={events.data ?? []} />
        )}
      </Card>
    </div>
  );
}
