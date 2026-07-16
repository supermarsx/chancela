import { describe, expect, it } from 'vitest';
import type {
  BookState,
  BookView,
  Entity,
  EntityRegistrySummary,
  LedgerEventView,
} from '../../api/types';
import {
  activityCategory,
  activityLabel,
  activityTone,
  bookDateSummary,
  bookStateCounts,
  bookStateCountsFromSummary,
  bookStateSummary,
  bookStateTone,
  caeDetails,
  caeLabel,
  dateRank,
  emptyBookStateCounts,
  entityMatchesActivityFilter,
  entityMatchesActivityKindFilter,
  entityMatchesBookFilter,
  entityMatchesBookKindFilter,
  entityMatchesLastBookFilter,
  entityMatchesRegistryFreshnessFilter,
  entityMatchesRegistryImportFilter,
  entityMatchesValidationFilter,
  formatActivityDate,
  formatActivityTimestamp,
  formatDateValue,
  indexBooksByEntity,
  registryFreshnessLabel,
  registryFreshnessTone,
  selectLastBook,
  totalBooksFromCounts,
} from './EntitiesPage';

function book(overrides: Partial<BookView> = {}): BookView {
  return {
    id: 'book-1',
    entity_id: 'entity-1',
    kind: 'AssembleiaGeral',
    state: 'Created',
    purpose: null,
    numbering_scheme: null,
    opening_date: null,
    closing_date: null,
    closing_reason: null,
    last_ata_number: 0,
    predecessor: null,
    required_signatories_abertura: null,
    required_signatories_encerramento: null,
    ...overrides,
  };
}

function registry(overrides: Partial<EntityRegistrySummary> = {}): EntityRegistrySummary {
  return {
    imported: true,
    matricula: null,
    data_constituicao: null,
    capital: null,
    cae: [],
    retrieved_at: '2026-07-16T10:00:00Z',
    valid_until: null,
    expired: null,
    last_registry_change: null,
    ...overrides,
  };
}

const entity = {
  nipc_validated: true,
} as Entity;
const activity = { kind: 'book.opened' } as LedgerEventView;

describe('entity list view-model helpers', () => {
  it('selects the most recent book with deterministic date, number, state, and id tie-breaks', () => {
    expect(selectLastBook([])).toBeNull();
    expect(dateRank(null)).toBe(0);
    expect(dateRank('not-a-date')).toBe(0);
    expect(dateRank('2026-01-02')).toBeGreaterThan(0);

    expect(
      selectLastBook([
        book({ id: 'old', opening_date: '2025-01-01' }),
        book({ id: 'new', closing_date: '2026-01-01' }),
      ])?.id,
    ).toBe('new');
    expect(
      selectLastBook([
        book({ id: 'one', last_ata_number: 1 }),
        book({ id: 'two', last_ata_number: 2 }),
      ])?.id,
    ).toBe('two');
    expect(selectLastBook([book({ id: 'created' }), book({ id: 'open', state: 'Open' })])?.id).toBe(
      'open',
    );
    expect(selectLastBook([book({ id: 'a' }), book({ id: 'b' })])?.id).toBe('b');
  });

  it('maps book state, dates, counts, and summaries without hiding empty or closed states', () => {
    expect((['Created', 'Open', 'Closed'] as BookState[]).map(bookStateTone)).toEqual([
      'accent',
      'ok',
      'neutral',
    ]);
    expect(bookDateSummary(book())).toBe('Sem data de abertura');
    expect(bookDateSummary(book({ opening_date: '2026-01-01' }))).toBe('Aberto em 2026-01-01');
    expect(bookDateSummary(book({ opening_date: '2026-01-01', closing_date: '2026-02-01' }))).toBe(
      'Aberto em 2026-01-01 · Encerrado em 2026-02-01',
    );

    expect(emptyBookStateCounts()).toEqual({ Created: 0, Open: 0, Closed: 0 });
    expect(bookStateCountsFromSummary({ created: 1, open: 2, closed: 3 })).toEqual({
      Created: 1,
      Open: 2,
      Closed: 3,
    });
    const counts = bookStateCounts([
      book({ state: 'Created' }),
      book({ id: 'open', state: 'Open' }),
      book({ id: 'closed', state: 'Closed' }),
    ]);
    expect(totalBooksFromCounts(counts)).toBe(3);
    expect(bookStateSummary(emptyBookStateCounts())).toBe('0 livros');
    expect(bookStateSummary({ Created: 0, Open: 1, Closed: 0 })).toBe('1 livro · Aberto: 1');
    expect(bookStateSummary(counts)).toContain('3 livros');
  });

  it('classifies every supported activity kind and preserves unknown backend kinds', () => {
    expect(activityTone('registry.imported')).toBe('ok');
    expect(activityTone('act.sealed')).toBe('ok');
    expect(activityTone('entity.statute_updated')).toBe('accent');
    expect(activityTone('unknown')).toBe('neutral');

    const labels: Record<string, string> = {
      'registry.imported': 'Registo importado',
      'entity.statute_updated': 'Entidade atualizada',
      'entity.created': 'Entidade criada',
      'book.opened': 'Livro aberto',
      'book.closed': 'Livro encerrado',
      'book.start_over': 'Livro recomeçado',
      'act.drafted': 'Ata rascunhada',
      'act.advanced': 'Ata avançada',
      'act.sealed': 'Ata selada',
      'act.archived': 'Ata arquivada',
      'convening.dispatched': 'Convocatória expedida',
      'document.generated': 'Documento gerado',
      'document.signed': 'Documento assinado',
      unknown: 'unknown',
    };
    for (const [kind, label] of Object.entries(labels)) expect(activityLabel(kind)).toBe(label);

    expect(activityCategory('registry.imported')).toBe('registry');
    expect(activityCategory('entity.created')).toBe('entity');
    expect(activityCategory('book.opened')).toBe('book');
    expect(activityCategory('convening.dispatched')).toBe('act');
    expect(activityCategory('signature.created')).toBe('document');
    expect(activityCategory('unknown')).toBe('other');
  });

  it('formats registry evidence and dates with explicit invalid and unknown fallbacks', () => {
    expect(formatActivityTimestamp('bad', 'en-GB')).toBe('bad');
    expect(formatActivityDate('bad', 'en-GB')).toBe('bad');
    expect(formatActivityTimestamp('2026-07-16T10:00:00Z', 'en-GB')).not.toBe(
      '2026-07-16T10:00:00Z',
    );
    expect(formatActivityDate('2026-07-16T10:00:00Z', 'en-GB')).not.toBe('2026-07-16T10:00:00Z');
    expect(formatDateValue(null)).toBe('—');
    expect(formatDateValue(undefined, 'missing')).toBe('missing');
    expect(formatDateValue('value')).toBe('value');

    const principal = {
      code: '62010',
      role: 'Principal' as const,
      designation: 'Programação informática',
      level: 'Subclasse' as const,
      revision: 'Rev4' as const,
    };
    expect(caeLabel(principal)).toBe('62010 principal');
    expect(caeDetails(principal)).toContain('Programação informática');
    expect(caeDetails(principal)).toContain('Subclasse · Rev4');
    expect(
      caeDetails({
        ...principal,
        role: 'Secundario',
        designation: null,
        level: null,
        revision: null,
      }),
    ).toBe('62010 secundário');

    expect(registryFreshnessTone(null)).toBe('neutral');
    expect(registryFreshnessTone(registry({ expired: true }))).toBe('warn');
    expect(registryFreshnessTone(registry({ expired: false }))).toBe('ok');
    expect(registryFreshnessTone(registry())).toBe('accent');
    expect(registryFreshnessLabel(null)).toBe('Não importado');
    expect(registryFreshnessLabel(registry({ expired: true }))).toBe('Expirado');
    expect(registryFreshnessLabel(registry({ expired: false }))).toBe('Dentro da validade');
    expect(registryFreshnessLabel(registry())).toBe('Validade desconhecida');
  });

  it('indexes books and evaluates every list-filter mode', () => {
    expect(indexBooksByEntity(undefined).size).toBe(0);
    const open = book({ id: 'open', state: 'Open' });
    const created = book({ id: 'created', state: 'Created' });
    const closed = book({ id: 'closed', entity_id: 'entity-2', state: 'Closed' });
    expect(indexBooksByEntity([open, created, closed]).get('entity-1')).toEqual([open, created]);

    const counts = { Created: 1, Open: 1, Closed: 1 };
    expect(entityMatchesBookFilter(counts, 'all')).toBe(true);
    expect(entityMatchesBookFilter(emptyBookStateCounts(), 'none')).toBe(true);
    expect(entityMatchesBookFilter(counts, 'open')).toBe(true);
    expect(entityMatchesBookFilter(counts, 'created')).toBe(true);
    expect(entityMatchesBookFilter(counts, 'closed')).toBe(true);
    expect(entityMatchesBookFilter({ Created: 1, Open: 0, Closed: 0 }, 'no-open')).toBe(true);
    expect(entityMatchesBookKindFilter([open], 'all')).toBe(true);
    expect(entityMatchesBookKindFilter([open], 'AssembleiaGeral')).toBe(true);
    expect(entityMatchesLastBookFilter(null, 'all')).toBe(true);
    expect(entityMatchesLastBookFilter(null, 'none')).toBe(true);
    expect(entityMatchesLastBookFilter(open, 'Open')).toBe(true);

    expect(entityMatchesActivityFilter(activity, 'all')).toBe(true);
    expect(entityMatchesActivityFilter(null, 'none')).toBe(true);
    expect(entityMatchesActivityFilter(null, 'book')).toBe(false);
    expect(entityMatchesActivityFilter(activity, 'book')).toBe(true);
    expect(entityMatchesActivityKindFilter(activity, 'all')).toBe(true);
    expect(entityMatchesActivityKindFilter(null, 'none')).toBe(true);
    expect(entityMatchesActivityKindFilter(activity, 'book.opened')).toBe(true);
    expect(entityMatchesValidationFilter(entity, 'all')).toBe(true);
    expect(entityMatchesValidationFilter(entity, 'validated')).toBe(true);
    expect(entityMatchesValidationFilter({ ...entity, nipc_validated: false }, 'unvalidated')).toBe(
      true,
    );
    expect(entityMatchesRegistryImportFilter(registry(), 'all')).toBe(true);
    expect(entityMatchesRegistryImportFilter(registry(), 'imported')).toBe(true);
    expect(entityMatchesRegistryImportFilter(null, 'not-imported')).toBe(true);
    expect(entityMatchesRegistryFreshnessFilter(null, 'all')).toBe(true);
    expect(entityMatchesRegistryFreshnessFilter(null, 'no-expiry')).toBe(true);
    expect(entityMatchesRegistryFreshnessFilter(registry({ expired: false }), 'fresh')).toBe(true);
    expect(entityMatchesRegistryFreshnessFilter(registry({ expired: true }), 'expired')).toBe(true);
    expect(entityMatchesRegistryFreshnessFilter(registry(), 'no-expiry')).toBe(true);
  });
});
