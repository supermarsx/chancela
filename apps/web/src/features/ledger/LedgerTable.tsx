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
import { chainSummaryLabel, LedgerScopeCell, useLedgerScopeNames } from './LedgerScopeCell';

export function LedgerTable({
  events,
  showChains = false,
  compact = false,
  rowCount,
}: {
  events: LedgerEventView[];
  showChains?: boolean;
  /**
   * The Arquivo reading mode: hundreds of rows scanned in one sitting, so the row is tightened
   * to the floor the digest copy control sets (see `.ledger-table` in `theme.css`). The
   * dashboard's short recent-events list keeps the app-wide table rhythm.
   */
  compact?: boolean;
  /** `aria-rowcount`; `-1` while the server holds rows this table has not fetched. */
  rowCount?: number;
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
      className={compact ? 'ledger-table' : undefined}
      rowCount={rowCount}
      head={
        <tr aria-rowindex={rowCount === undefined ? undefined : 1}>
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
      {/* `aria-rowindex` is 1-based over the whole table, header included, so the first event
          is row 2. It is what lets a screen reader say "row 137" while the total is still
          unknown — without it a lazily-extending table renumbers itself on every load. */}
      {rows.map((e, index) => (
        <tr key={e.id} aria-rowindex={rowCount === undefined ? undefined : index + 2}>
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
              {/* Mirrors the Âmbito column: friendly, `·`-separated names in normal case rather
                  than the raw `company:{uuid}` / `book:{uuid}` tokens (which, as uppercase pills,
                  read as one unbroken blob). Each membership keeps its exact chain id one focus
                  away in the tooltip — it is the value the `?chain=` filter and every export use. */}
              <span className="ledger-chain-list">
                {(e.chains ?? []).map((chain, index) => (
                  <span key={chain}>
                    {index > 0 ? <span className="muted"> · </span> : null}
                    <TooltipText label={chain}>
                      {chainSummaryLabel(chain, scopeNames, t)}
                    </TooltipText>
                  </span>
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
