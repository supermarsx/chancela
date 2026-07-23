import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { Wrapper } from '../../test/utils';
import type { ActView } from '../../api/types';
import { BookActsList } from './BookActsList';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

const OPENING = {
  bookId: 'book-1',
  title: 'Termo de abertura',
  state: 'Sealed' as const,
  instrumentDate: '2026-01-01',
  legacy: false,
  documentAvailable: true,
  availableSignatures: 1,
  requiredSignatures: 1,
};

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

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  saveFileMock.saveBlobAs.mockReset();
});

describe('BookActsList', () => {
  const acts: ActView[] = [
    makeAct({ id: 'a1', title: 'Primeira ata', ata_number: 1, state: 'Sealed' }),
    makeAct({ id: 'a3', title: 'Terceira ata', ata_number: 3, state: 'Sealed' }),
    makeAct({ id: 'a2', title: 'Segunda ata', ata_number: 2, state: 'Sealed' }),
    makeAct({ id: 'd1', title: 'Rascunho em curso', ata_number: null, state: 'Draft' }),
  ];

  it('orders most-recent-first, with the sealed genesis record after the atas', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} opening={OPENING} />
      </Wrapper>,
    );
    expect(rowNumbers()).toEqual(['—', '3', '2', '1', '—']);
    const openingRecord = screen.getAllByRole('row').at(-1);
    expect(openingRecord?.getAttribute('data-record-type')).toBe('TermoAbertura');
    expect(
      within(openingRecord!)
        .getByRole('link', { name: 'Abrir: Termo de abertura' })
        .getAttribute('href'),
    ).toBe('/books/book-1/opening');
    expect(within(openingRecord!).getAllByRole('cell')[2]?.textContent).toBe('—');
    expect(within(openingRecord!).getByText('1 de janeiro de 2026')).toBeTruthy();
    expect(
      within(openingRecord!).getByText(/1\/1 assinaturas PAdES exigidas disponíveis/),
    ).toBeTruthy();
  });

  it('keeps an active Draft opening term before the ata chronology', () => {
    render(
      <Wrapper>
        <BookActsList
          acts={acts}
          opening={{
            ...OPENING,
            state: 'Draft',
            documentAvailable: false,
            availableSignatures: 0,
          }}
        />
      </Wrapper>,
    );

    const firstRecord = screen.getAllByRole('row')[1];
    expect(firstRecord?.getAttribute('data-record-type')).toBe('TermoAbertura');
  });

  it('searches across number, title, channel and state', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} opening={OPENING} />
      </Wrapper>,
    );
    const search = screen.getByRole('searchbox');
    fireEvent.change(search, { target: { value: 'segunda' } });
    expect(screen.getByText('Segunda ata')).toBeTruthy();
    expect(screen.queryByText('Terceira ata')).toBeNull();
    expect(rowNumbers()).toEqual(['2']);
  });

  it('searches the opening record by its instrument date', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} opening={OPENING} />
      </Wrapper>,
    );

    fireEvent.change(screen.getByRole('searchbox'), { target: { value: '2026-01-01' } });

    expect(screen.getByText('Termo de abertura')).toBeTruthy();
    expect(rowNumbers()).toEqual(['—']);
  });

  it('labels and saves the base PDF as unsigned', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'ignored.pdf',
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(() =>
        Promise.resolve(
          new Response('%PDF-1.7', {
            headers: { 'Content-Type': 'application/pdf' },
          }),
        ),
      ),
    );
    render(
      <Wrapper>
        <BookActsList acts={acts} opening={OPENING} />
      </Wrapper>,
    );

    fireEvent.click(screen.getByRole('button', { name: 'Descarregar PDF base sem assinaturas' }));

    await waitFor(() =>
      expect(saveFileMock.saveBlobAs).toHaveBeenCalledWith(
        expect.objectContaining({
          filename: 'termo-de-abertura-book-1-base-sem-assinaturas.pdf',
        }),
      ),
    );
  });

  it('filters by state, and shows the filtered-empty note when nothing matches', () => {
    render(
      <Wrapper>
        <BookActsList acts={acts} opening={OPENING} />
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
        <BookActsList acts={acts} opening={OPENING} />
      </Wrapper>,
    );
    const open = screen.getAllByRole('link', { name: 'Abrir' });
    expect(open).toHaveLength(acts.length);
    expect(open[0].getAttribute('href')).toBe('/acts/d1');
  });
});
