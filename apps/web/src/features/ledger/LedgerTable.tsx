/**
 * Shared render of ledger events (used by the dashboard's recent list and the
 * Arquivo page). Hashes are hex strings, shown through the abbreviated `Digest`
 * component (first/last eight, full value on hover, click-to-copy) so the table stays
 * legible without hiding the evidence.
 */
import type { LedgerEventView } from '../../api/types';
import { useT, useLocale } from '../../i18n';
import { Badge, Digest, EmptyState, Table } from '../../ui';

function formatTimestamp(rfc3339: string, locale: string): string {
  const d = new Date(rfc3339);
  return Number.isNaN(d.getTime()) ? rfc3339 : d.toLocaleString(locale);
}

export function LedgerTable({ events }: { events: LedgerEventView[] }) {
  const t = useT();
  const locale = useLocale();
  if (events.length === 0) {
    return <EmptyState title={t('ledger.empty')} />;
  }
  return (
    <Table
      head={
        <tr>
          <th>{t('ledger.th.seq')}</th>
          <th>{t('ledger.th.event')}</th>
          <th>{t('ledger.th.scope')}</th>
          <th>{t('ledger.th.actor')}</th>
          <th>{t('ledger.th.date')}</th>
          <th>{t('ledger.th.hash')}</th>
        </tr>
      }
    >
      {events.map((e) => (
        <tr key={e.id}>
          <td>{e.seq}</td>
          <td>
            <Badge tone="accent">{e.kind}</Badge>
          </td>
          <td>
            <code className="mono">{e.scope}</code>
          </td>
          <td>
            {e.actor === 'api' ? (
              <span className="muted" title={t('ledger.actor.systemTooltip')}>
                {e.actor}
              </span>
            ) : (
              e.actor
            )}
          </td>
          <td>{formatTimestamp(e.timestamp, locale)}</td>
          <td>
            <Digest value={e.hash} />
          </td>
        </tr>
      ))}
    </Table>
  );
}
