/**
 * Shared render of ledger events (used by the dashboard's recent list and the
 * Arquivo page). Hashes are hex strings, shown through the abbreviated `Digest`
 * component (first/last eight, full value on hover, click-to-copy) so the table stays
 * legible without hiding the evidence.
 */
import { ledgerEventKindLabel } from '../../api/labels';
import type { LedgerEventView } from '../../api/types';
import { useT } from '../../i18n';
import { Badge, DateTime, Digest, EmptyState, Table, TooltipText } from '../../ui';
import { LedgerScopeCell, useLedgerScopeNames } from './LedgerScopeCell';

function shortChain(chain: string): string {
  const [kind, id] = chain.split(':', 2);
  if (!id) return chain;
  return `${kind}:${id.slice(0, 8)}`;
}

export function LedgerTable({
  events,
  showChains = false,
}: {
  events: LedgerEventView[];
  showChains?: boolean;
}) {
  const t = useT();
  // One pair of list queries for the whole table — never one per row. Both are shared query keys
  // and both are skipped when the viewer holds no such permission, so an unauthorized visit costs
  // nothing and every scope simply keeps its id.
  const scopeNames = useLedgerScopeNames();
  // Shared by the dashboard and the Arquivo page, so a single malformed row from either
  // payload must not take the surrounding page down with the error boundary: drop it and
  // render the rest of the chain.
  const rows = events.filter((event): event is LedgerEventView => Boolean(event));
  if (rows.length === 0) {
    return <EmptyState title={t('ledger.empty')} />;
  }
  return (
    <Table
      head={
        <tr>
          <th>{t('ledger.th.seq')}</th>
          <th>{t('ledger.th.event')}</th>
          <th>{t('ledger.th.scope')}</th>
          {showChains ? <th>{t('ledger.th.chains')}</th> : null}
          <th>{t('ledger.th.actor')}</th>
          <th>{t('ledger.th.date')}</th>
          <th>{t('ledger.th.hash')}</th>
        </tr>
      }
    >
      {rows.map((e) => (
        <tr key={e.id}>
          <td>{e.seq}</td>
          <td>
            <Badge tone="accent">
              {/* The dotted wire id stays reachable — it is the filter/export value, and the
                  friendly label replaces it on screen, so it lives ONLY in the bubble (hence
                  focusable by default). */}
              <TooltipText label={e.kind}>{ledgerEventKindLabel(e.kind)}</TooltipText>
            </Badge>
          </td>
          <td>
            {/* The raw scope was a bare id — `0a20de34-…` told a reader nothing. It now reads as
                `Tipo — Nome`, resolved only against records this viewer may already read, with
                the exact scope string one focus away for an auditor. */}
            <LedgerScopeCell scope={e.scope} names={scopeNames} />
          </td>
          {showChains ? (
            <td>
              <span className="ledger-chain-list">
                {(e.chains ?? []).map((chain) => (
                  <Badge key={chain} tone="neutral">
                    {/* The full chain hash exists only here — the cell shows an abbreviation. */}
                    <TooltipText label={chain}>{shortChain(chain)}</TooltipText>
                  </Badge>
                ))}
              </span>
            </td>
          ) : null}
          <td>
            {e.actor === 'api' ? (
              <TooltipText className="muted" label={t('ledger.actor.systemTooltip')}>
                {e.actor}
              </TooltipText>
            ) : (
              e.actor
            )}
          </td>
          {/* The ledger is the evidentiary record: seconds and the zone abbreviation, with
              the core's unrounded instant kept in the `datetime` attribute for a verifier. */}
          <td>
            <DateTime value={e.timestamp} evidentiary />
          </td>
          <td>
            <Digest value={e.hash} />
          </td>
        </tr>
      ))}
    </Table>
  );
}
