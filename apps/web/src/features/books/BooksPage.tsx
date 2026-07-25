/**
 * Livros - the full-width list of every book across all entities. Opening a book lives
 * behind a neat "Abrir livro" button in the panel header, which opens the dedicated
 * open-book route (`/books/new`) rather than an always-visible aside form (t13 item 7).
 */
import { useState } from 'react';
import { useBooksPage } from '../../api/hooks';
import { bookKindLabels, bookStateLabels } from '../../api/labels';
import {
  BOOK_COLUMNS,
  BOOK_KINDS,
  type BookColumn,
  type BookKind,
  type BookState,
} from '../../api/types';
import { useT, type MessageKey } from '../../i18n';
import { useTableColumnsT } from '../../i18n/tableColumnsFallback';
import { ColumnPicker } from '../tableColumns/ColumnPicker';
import { useTableColumns, type TableColumnsSpec } from '../tableColumns/useTableColumns';
import {
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
import {
  CollectionPageCount,
  CollectionPager,
  useCollectionNavigation,
  useDebouncedValue,
} from '../common/CollectionPager';
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

/** The hideable book columns (Actions is structural), and the header label each answers to. */
const BOOK_HIDEABLE_COLUMNS = BOOK_COLUMNS.filter(
  (column): column is Exclude<BookColumn, 'Actions'> => column !== 'Actions',
);

const BOOK_COLUMN_LABEL_KEYS: Record<Exclude<BookColumn, 'Actions'>, MessageKey> = {
  Kind: 'books.th.type',
  Purpose: 'books.th.purpose',
  State: 'books.th.state',
  Opening: 'books.th.opening',
  LastAct: 'books.th.lastAct',
};

/** The books table's column spec: all shown by default (the product default), Actions always. */
const BOOKS_COLUMN_SPEC: TableColumnsSpec<BookColumn> = {
  table: 'books',
  columns: BOOK_COLUMNS,
  hideable: BOOK_HIDEABLE_COLUMNS,
  fallback: BOOK_COLUMNS,
};

const ADVANCED_FILTER_OPTIONS: { value: AdvancedFilter; labelKey: MessageKey }[] = [
  { value: 'all', labelKey: 'books.filters.activity.all' },
  { value: 'has-acts', labelKey: 'books.filters.activity.hasActs' },
  { value: 'no-acts', labelKey: 'books.filters.activity.noActs' },
  { value: 'successor', labelKey: 'books.filters.activity.successor' },
  { value: 'origin', labelKey: 'books.filters.activity.origin' },
];

export function BooksPage() {
  const t = useT();
  const ct = useTableColumnsT();
  const columns = useTableColumns(BOOKS_COLUMN_SPEC);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebouncedValue(search);
  const [stateFilter, setStateFilter] = useState<BookStateFilter>('all');
  const [kindFilter, setKindFilter] = useState<BookKindFilter>('all');
  const [advancedFilter, setAdvancedFilter] = useState<AdvancedFilter>('all');
  const [openedFrom, setOpenedFrom] = useState('');
  const [openedTo, setOpenedTo] = useState('');
  const filters = {
    q: debouncedSearch.trim() || undefined,
    state: stateFilter === 'all' ? undefined : stateFilter,
    kind: kindFilter === 'all' ? undefined : kindFilter,
    activity:
      advancedFilter === 'has-acts' || advancedFilter === 'no-acts' ? advancedFilter : undefined,
    lineage:
      advancedFilter === 'successor' || advancedFilter === 'origin' ? advancedFilter : undefined,
    opened_from: openedFrom || undefined,
    opened_to: openedTo || undefined,
    limit: 50,
    sort: 'id',
    order: 'asc' as const,
  };
  const navigation = useCollectionNavigation(JSON.stringify(filters));
  const books = useBooksPage({ ...filters, ...navigation.position });
  // Placeholder data keeps the filter controls mounted during a query-key transition, but rows
  // from the previous filter/page must never masquerade as results for the current one.
  const visibleBooks = books.isPlaceholderData ? [] : (books.data?.items ?? []);

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
    /* `wide-page` widens the shell measure (t64's shared opt-out, see theme.css). The whole
       page is the seven-column book list, whose columns are percentage-fixed and truncate
       rather than wrap — every column scales with the measure and none becomes prose.
       Finalidade, the free-text column, goes 224px → 318px at 1920. */
    <div className="stack wide-page">
      <PageHeader
        title={t('books.title')}
        lede={t('books.lede')}
        actions={
          <GateButtonLink
            perm="book.open"
            anyScope
            to="/books/new"
            variant="primary"
            icon={<Icon.BookPlus />}
          >
            {t('books.openBook')}
          </GateButtonLink>
        }
      />

      <Card
        title={t('books.allBooks')}
        actions={<CollectionPageCount count={visibleBooks.length} />}
      >
        {books.isLoading ? (
          <SkeletonRegion>
            <SkeletonTable cols={5} />
          </SkeletonRegion>
        ) : books.error ? (
          <ErrorNote error={books.error} />
        ) : !books.data ||
          (!books.isPlaceholderData && visibleBooks.length === 0 && !hasFilters) ? (
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

            <ColumnPicker
              columns={BOOK_HIDEABLE_COLUMNS}
              label={ct('tableColumns.summary')}
              hint={ct('tableColumns.books.hint')}
              isVisible={columns.isVisible}
              onToggle={columns.toggle}
              columnLabel={(column) => t(BOOK_COLUMN_LABEL_KEYS[column])}
            />

            {books.isPlaceholderData ? (
              <SkeletonRegion>
                <SkeletonTable cols={5} />
              </SkeletonRegion>
            ) : visibleBooks.length === 0 ? (
              <EmptyState title={t('books.filters.empty.title')}>
                <p>{t('books.filters.empty.body')}</p>
              </EmptyState>
            ) : (
              <BooksTable books={visibleBooks} showEntity visibleColumns={columns.visible} />
            )}
            {!books.isPlaceholderData ? (
              <CollectionPager
                offset={navigation.displayOffset}
                count={visibleBooks.length}
                hasPrevious={navigation.hasPrevious}
                hasNext={books.data?.has_more ?? false}
                disabled={books.isFetching}
                onPrevious={navigation.previous}
                onNext={() =>
                  navigation.next(
                    books.data?.next_offset ?? null,
                    books.data?.next_cursor,
                    navigation.displayOffset + visibleBooks.length,
                  )
                }
              />
            ) : null}
          </div>
        )}
      </Card>
    </div>
  );
}
