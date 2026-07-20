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

  it('renders an event whose payload omits the chain list', () => {
    const events = [makeEvent(3, { chains: undefined as unknown as string[] })];

    renderWithProviders(<LedgerTable events={events} showChains />);

    expect(screen.getByText('event.3')).toBeTruthy();
  });
});
