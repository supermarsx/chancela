import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, screen } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
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
