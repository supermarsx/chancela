import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import { getByRevealedText, renderWithProviders } from '../../test/utils';
import type { LedgerEventView } from '../../api/types';
import { LedgerTable } from './LedgerTable';

function makeEvent(seq: number, patch: Partial<LedgerEventView> = {}): LedgerEventView {
  return {
    id: `event-${seq}`,
    seq,
    actor: 'amelia.marques',
    justification: null,
    timestamp: '2026-07-07T10:20:30Z',
    scope: `act:${seq}`,
    kind: `event.${seq}`,
    payload_digest: 'aa'.repeat(32),
    prev_hash: '00'.repeat(32),
    hash: String(seq % 10).repeat(64),
    chains: ['global', 'book:book-123456789'],
    attestation: null,
    ...patch,
  };
}

afterEach(() => {
  cleanup();
});

describe('LedgerTable', () => {
  it('renders the well-formed rows when the payload carries a malformed one', () => {
    const events = [makeEvent(1), undefined, makeEvent(2)] as unknown as LedgerEventView[];

    renderWithProviders(<LedgerTable events={events} />);

    expect(screen.getByText('event.1')).toBeTruthy();
    expect(screen.getByText('event.2')).toBeTruthy();
    expect(screen.getAllByRole('row').length).toBe(3); // header + the two usable events
  });

  it('labels a known event kind and keeps the wire identifier one hover away', () => {
    renderWithProviders(<LedgerTable events={[makeEvent(1, { kind: 'act.sealed' })]} />);

    // The cell reads as copy; the dotted id — the Arquivo filter value — is still announced,
    // now through the tooltip description rather than a native title.
    expect(getByRevealedText('act.sealed').textContent).toBe('Ata selada');
  });

  it('renders an unmapped kind as its raw identifier instead of blank', () => {
    renderWithProviders(<LedgerTable events={[makeEvent(2, { kind: 'act.teleported' })]} />);

    // Nothing to reveal when the label already IS the visible id: it renders once, plainly,
    // with no bubble and no redundant description for a screen reader to repeat.
    const matches = screen.getAllByText('act.teleported');
    expect(matches).toHaveLength(1);
    expect(matches[0].getAttribute('aria-describedby')).toBeNull();
  });

  it('falls back to the empty state when every row is malformed', () => {
    const events = [undefined, null] as unknown as LedgerEventView[];

    renderWithProviders(<LedgerTable events={events} />);

    expect(screen.getByText('Sem eventos')).toBeTruthy();
  });

  it('leaves the table plain when no row count is given', () => {
    // The dashboard's recent-events list renders every row it has, so `aria-rowcount` would be
    // noise; and it keeps the app-wide table rhythm rather than the Arquivo's compact one.
    const { container } = renderWithProviders(<LedgerTable events={[makeEvent(1)]} />);

    const table = screen.getByRole('table');
    expect(table.getAttribute('aria-rowcount')).toBeNull();
    expect(screen.getAllByRole('row')[1].getAttribute('aria-rowindex')).toBeNull();
    expect(container.querySelector('.ledger-table')).toBeNull();
  });

  it('reports an unknown total rather than the loaded count while rows remain unfetched', () => {
    // The load-bearing assertion of the whole lazy surface: -1 is the ARIA value for "the total
    // is not known". Passing `rows.length` here instead would tell a screen-reader user the
    // audit log ENDS where the fetching happened to stop — on an evidentiary record that is a
    // lie, not a rounding error.
    const { container } = renderWithProviders(
      <LedgerTable events={[makeEvent(1), makeEvent(2)]} compact rowCount={-1} />,
    );

    expect(screen.getByRole('table').getAttribute('aria-rowcount')).toBe('-1');
    // Header is row 1, so the events are 2 and 3 — stable numbering as the table extends.
    const rows = screen.getAllByRole('row');
    expect(rows.map((r) => r.getAttribute('aria-rowindex'))).toEqual(['1', '2', '3']);
    expect(container.querySelector('.ledger-table')).toBeTruthy();
  });

  it('states the real total once the server reports no more rows', () => {
    renderWithProviders(<LedgerTable events={[makeEvent(1), makeEvent(2)]} compact rowCount={3} />);

    expect(screen.getByRole('table').getAttribute('aria-rowcount')).toBe('3');
  });

  it('renders an event whose payload omits the chain list', () => {
    const events = [makeEvent(3, { chains: undefined as unknown as string[] })];

    renderWithProviders(<LedgerTable events={events} showChains />);

    expect(screen.getByText('event.3')).toBeTruthy();
  });
});
