/**
 * Livros - the full-width list of every book across all entities. Opening a book lives
 * behind a neat "Abrir livro" button in the panel header, which opens the dedicated
 * open-book route (`/livros/novo`) rather than an always-visible aside form (t13 item 7).
 */
import { useDeferredValue, useMemo, useState } from 'react';
import { useBooks, useEntities } from '../../api/hooks';
import { bookKindLabels, bookStateLabels } from '../../api/labels';
import {
  BOOK_KINDS,
  type BookKind,
  type BookState,
  type BookView,
  type Entity,
} from '../../api/types';
import { useT, type MessageKey } from '../../i18n';
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  PageHeader,
  Select,
  SkeletonTable,
  SkeletonRegion,
} from '../../ui';
import { GateButtonLink } from '../session/permissions';
import { BooksTable } from './BooksTable';

type BookStateFilter = 'all' | BookState;
type BookKindFilter = 'all' | BookKind;
type AdvancedFilter = 'all' | 'has-acts' | 'no-acts' | 'successor' | 'origin';

const STATE_FILTER_OPTIONS: { value: BookStateFilter; labelKey?: MessageKey; label?: string }[] = [
  { value: 'all', labelKey: 'books.filters.state.all' },
  { value: 'Open', label: bookStateLabels.Open },
  { value: 'Created', label: bookStateLabels.Created },
  { value: 'Closed', label: bookStateLabels.Closed },
];

const KIND_FILTER_OPTIONS: { value: BookKindFilter; labelKey?: MessageKey; label?: string }[] = [
  { value: 'all', labelKey: 'books.filters.kind.all' },
  ...BOOK_KINDS.map((value) => ({ value, label: bookKindLabels[value] })),
];

const ADVANCED_FILTER_OPTIONS: { value: AdvancedFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'books.filters.activity.all' },
  { value: 'has-acts', labelKey: 'books.filters.activity.hasActs' },
  { value: 'no-acts', labelKey: 'books.filters.activity.noActs' },
  { value: 'successor', labelKey: 'books.filters.activity.successor' },
  { value: 'origin', labelKey: 'books.filters.activity.origin' },
];

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

function dateRank(value: string | null): number {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function bookSignatorySearchParts(book: BookView): string[] {
  const records = [
    ...(book.required_signatory_records_abertura ?? []),
    ...(book.required_signatory_records_encerramento ?? []),
  ];
  if (records.length > 0) {
    return records.flatMap((signatory) => [
      signatory.name,
      signatory.capacity ?? '',
      signatory.email ?? '',
    ]);
  }
  return [
    ...(book.required_signatories_abertura ?? []),
    ...(book.required_signatories_encerramento ?? []),
  ];
}

function bookSearchText(book: BookView): string {
  return normalizeSearch(
    [
      book.id,
      book.entity_id,
      bookKindLabels[book.kind],
      bookStateLabels[book.state],
      book.purpose ?? '',
      book.opening_date ?? '',
      book.closing_date ?? '',
      book.predecessor ?? '',
      String(book.last_ata_number || ''),
      ...bookSignatorySearchParts(book),
    ].join(' '),
  );
}

export function BooksPage() {
  const t = useT();
  const books = useBooks();
  const entities = useEntities();
  const entitiesById = useMemo(() => {
    const map = new Map<string, Entity>();
    for (const entity of entities.data ?? []) map.set(entity.id, entity);
    return map;
  }, [entities.data]);
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [stateFilter, setStateFilter] = useState<BookStateFilter>('all');
  const [kindFilter, setKindFilter] = useState<BookKindFilter>('all');
  const [advancedFilter, setAdvancedFilter] = useState<AdvancedFilter>('all');
  const [openedFrom, setOpenedFrom] = useState('');
  const [openedTo, setOpenedTo] = useState('');

  const visibleBooks = useMemo(() => {
    const query = normalizeSearch(deferredSearch.trim());
    const fromRank = dateRank(openedFrom || null);
    const toRank = dateRank(openedTo || null);

    return (books.data ?? []).filter((book) => {
      if (stateFilter !== 'all' && book.state !== stateFilter) return false;
      if (kindFilter !== 'all' && book.kind !== kindFilter) return false;
      if (advancedFilter === 'has-acts' && book.last_ata_number <= 0) return false;
      if (advancedFilter === 'no-acts' && book.last_ata_number > 0) return false;
      if (advancedFilter === 'successor' && !book.predecessor) return false;
      if (advancedFilter === 'origin' && book.predecessor) return false;
      const openedRank = dateRank(book.opening_date);
      if (fromRank > 0 && (openedRank === 0 || openedRank < fromRank)) return false;
      if (toRank > 0 && (openedRank === 0 || openedRank > toRank)) return false;
      return query === '' || bookSearchText(book).includes(query);
    });
  }, [advancedFilter, books.data, deferredSearch, kindFilter, openedFrom, openedTo, stateFilter]);

  const hasFilters =
    search.trim() !== '' ||
    stateFilter !== 'all' ||
    kindFilter !== 'all' ||
    advancedFilter !== 'all' ||
    openedFrom !== '' ||
    openedTo !== '';

  function clearFilters() {
    setSearch('');
    setStateFilter('all');
    setKindFilter('all');
    setAdvancedFilter('all');
    setOpenedFrom('');
    setOpenedTo('');
  }

  const stateFilterOptions = STATE_FILTER_OPTIONS.map((option) => ({
    value: option.value,
    label: option.labelKey ? t(option.labelKey) : (option.label ?? ''),
  }));
  const kindFilterOptions = KIND_FILTER_OPTIONS.map((option) => ({
    value: option.value,
    label: option.labelKey ? t(option.labelKey) : (option.label ?? ''),
  }));
  const advancedFilterOptions = ADVANCED_FILTER_OPTIONS.map((option) => ({
    value: option.value,
    label: t(option.labelKey),
  }));

  return (
    <div className="stack">
      <PageHeader
        title={t('books.title')}
        lede={t('books.lede')}
        actions={
          <GateButtonLink
            perm="book.open"
            anyScope
            to="/livros/novo"
            variant="primary"
            icon={<Icon.BookPlus />}
          >
            {t('books.openBook')}
          </GateButtonLink>
        }
      />

      <Card
        title={t('books.allBooks')}
        actions={
          books.data && books.data.length > 0 ? (
            <span
              aria-label={t('books.filters.count.aria', {
                shown: visibleBooks.length,
                total: books.data.length,
              })}
            >
              <Badge>
                {t('books.filters.count', { shown: visibleBooks.length, total: books.data.length })}
              </Badge>
            </span>
          ) : null
        }
      >
        {books.isLoading ? (
          <SkeletonRegion>
            <SkeletonTable cols={5} />
          </SkeletonRegion>
        ) : books.error ? (
          <ErrorNote error={books.error} />
        ) : !books.data || books.data.length === 0 ? (
          <EmptyState title={t('books.empty')} />
        ) : (
          <div className="stack">
            <div
              className="stack--tight books-filters"
              role="search"
              aria-label={t('books.filters.aria')}
            >
              <div className="books-filterbar filter">
                <div className="books-filterbar__primary">
                  <Field label={t('books.filters.search.label')} htmlFor="books-search">
                    <Input
                      id="books-search"
                      type="search"
                      value={search}
                      placeholder={t('books.filters.search.placeholder')}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </Field>
                  <Field label={t('books.filters.state.label')} htmlFor="books-state-filter">
                    <Select
                      id="books-state-filter"
                      value={stateFilter}
                      onChange={(e) => setStateFilter(e.target.value as BookStateFilter)}
                      options={stateFilterOptions}
                    />
                  </Field>
                  <Field label={t('books.filters.kind.label')} htmlFor="books-kind-filter">
                    <Select
                      id="books-kind-filter"
                      value={kindFilter}
                      onChange={(e) => setKindFilter(e.target.value as BookKindFilter)}
                      options={kindFilterOptions}
                    />
                  </Field>
                  <IconButton
                    className="books-filterbar__clear"
                    icon={<Icon.Close />}
                    label={t('books.filters.clear.aria')}
                    disabled={!hasFilters}
                    onClick={clearFilters}
                  />
                </div>
              </div>

              <details className="books-advanced-filters filter-advanced">
                <summary>{t('books.filters.advanced')}</summary>
                <div className="books-advanced-filters__body filter filter-advanced__body">
                  <Field label={t('books.filters.activity.label')} htmlFor="books-activity-filter">
                    <Select
                      id="books-activity-filter"
                      value={advancedFilter}
                      onChange={(e) => setAdvancedFilter(e.target.value as AdvancedFilter)}
                      options={advancedFilterOptions}
                    />
                  </Field>
                  <Field label={t('books.filters.openedFrom')} htmlFor="books-opened-from-filter">
                    <Input
                      id="books-opened-from-filter"
                      type="date"
                      value={openedFrom}
                      onChange={(e) => setOpenedFrom(e.target.value)}
                    />
                  </Field>
                  <Field label={t('books.filters.openedTo')} htmlFor="books-opened-to-filter">
                    <Input
                      id="books-opened-to-filter"
                      type="date"
                      value={openedTo}
                      onChange={(e) => setOpenedTo(e.target.value)}
                    />
                  </Field>
                </div>
              </details>
            </div>

            {visibleBooks.length === 0 ? (
              <EmptyState title={t('books.filters.empty.title')}>
                <p>{t('books.filters.empty.body')}</p>
              </EmptyState>
            ) : (
              <BooksTable
                books={visibleBooks}
                showEntity
                entitiesById={entitiesById}
                entitiesLoading={entities.isLoading}
              />
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
