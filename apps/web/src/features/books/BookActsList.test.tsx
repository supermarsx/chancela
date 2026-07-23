import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { Wrapper } from '../../test/utils';
import type { ActView } from '../../api/types';
import { BookActsList } from './BookActsList';

function makeAct(overrides: Partial<ActView> & Pick<ActView, 'id' | 'title'>): ActView {
  return {
    book_id: 'book-1',
    channel: 'Physical',
    meeting_date: '2026-06-30',
    meeting_time: null,
    place: 'Lisboa',
    mesa: { presidente: 'Ana', secretarios: [] },
    agenda: [],
    attendance_reference: null,
    members_present: null,
    members_represented: null,
    referenced_documents: [],
    deliberations: '',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [],
    state: 'Draft',
    ata_number: null,
    payload_digest: null,
    seal_event_seq: null,
    seal_metadata: null,
    retifies: null,
    ...overrides,
  };
}

/** The ata-number cell text of every data row, top to bottom. */
function rowNumbers(): string[] {
  const table = screen.getByRole('table');
  return within(table)
    .getAllByRole('row')
    .slice(1) // drop the header row
    .map((row) => within(row).getAllByRole('cell')[0]?.textContent?.trim() ?? '');
}

afterEach(cleanup);

describe('BookActsList', () => {
  const acts: ActView[] = [
    makeAct({ id: 'a1', title: 'Primeira ata', ata_number: 1, state: 'Sealed' }),
    makeAct({ id: 'a3', title: 'Terceira ata', ata_number: 3, state: 'Sealed' }),
    makeAct({ id: 'a2', title: 'Segunda ata', ata_number: 2, state: 'Sealed' }),
    makeAct({ id: 'd1', title: 'Rascunho em curso', ata_number: null, state: 'Draft' }),
  ];

  it('orders most-recent-first: drafts first, then numbered descending', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} />
      </Wrapper>,
    );
    expect(rowNumbers()).toEqual(['—', '3', '2', '1']);
  });

  it('searches across number, title, channel and state', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} />
      </Wrapper>,
    );
    const search = screen.getByRole('searchbox');
    fireEvent.change(search, { target: { value: 'segunda' } });
    expect(screen.getByText('Segunda ata')).toBeTruthy();
    expect(screen.queryByText('Terceira ata')).toBeNull();
    expect(rowNumbers()).toEqual(['2']);
  });

  it('filters by state, and shows the filtered-empty note when nothing matches', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} />
      </Wrapper>,
    );
    const stateSelect = screen.getByLabelText('Estado');
    fireEvent.change(stateSelect, { target: { value: 'Draft' } });
    expect(rowNumbers()).toEqual(['—']);
    expect(screen.getByText('Rascunho em curso')).toBeTruthy();

    fireEvent.change(stateSelect, { target: { value: 'Archived' } });
    // No archived atas -> the filtered-empty state replaces the table.
    expect(screen.queryByRole('table')).toBeNull();
    expect(screen.getByText('Sem resultados')).toBeTruthy();
  });

  it('links each row to its act via an accessible open action', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} />
      </Wrapper>,
    );
    const open = screen.getAllByRole('link', { name: 'Abrir' });
    expect(open).toHaveLength(acts.length);
    expect(open[0].getAttribute('href')).toBe('/acts/d1');
  });
});
