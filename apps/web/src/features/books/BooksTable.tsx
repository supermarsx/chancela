/**
 * Shared render of a book list (used on the Livros page and an entity's detail page).
 */
import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { BOOK_COLUMNS, type BookColumn, type BookView, type Entity } from '../../api/types';
import { bookKindLabels, bookStateLabels } from '../../api/labels';
import { useT } from '../../i18n';
import { Badge, EmptyState, Icon, Table, Tooltip, Truncate } from '../../ui';
import { NipcBadge } from '../entities/NipcBadge';

/** The owning-entity column is not part of the per-user set — the page context decides it. */
type BookTableColumn = BookColumn | 'Entity';

function stateTone(state: BookView['state']) {
  if (state === 'Open') return 'ok' as const;
  if (state === 'Closed') return 'neutral' as const;
  return 'accent' as const;
}

function BookTableCell({
  column,
  actions = false,
  children,
}: {
  column: BookTableColumn;
  actions?: boolean;
  children: ReactNode;
}) {
  return (
    <td
      className={`books-table__cell ${
        actions ? 'books-table__cell--actions' : 'books-table__cell--truncate'
      }`}
      data-book-column={column}
    >
      {children}
    </td>
  );
}

function openBookLabel(book: BookView, openLabel: string): string {
  return `${openLabel}: ${book.purpose ?? book.id}`;
}

/**
 * Resolves a book's owning entity to a selectable, linked reference. While the entities
 * query is still loading we show a subtle placeholder (never a flash of the raw id); when
 * the entity is missing we fall back to the id in a muted mono span rather than crash.
 */
function BookEntityRef({
  book,
  entitiesById,
  loading,
}: {
  book: BookView;
  entitiesById?: Map<string, Entity>;
  loading: boolean;
}) {
  const entity = entitiesById?.get(book.entity_id);
  if (entity) {
    return (
      <span className="books-table__entity">
        <Link
          className="truncate books-table__entity-link"
          to={`/entities/${entity.id}`}
          title={entity.name}
        >
          {entity.name}
        </Link>
        {!entity.nipc_validated ? <NipcBadge /> : null}
      </span>
    );
  }
  if (loading) {
    return (
      <span className="books-table__entity-loading muted" aria-hidden="true">
        …
      </span>
    );
  }
  return <Truncate text={book.entity_id} mono className="muted" />;
}

export function BooksTable({
  books,
  showEntity = false,
  entitiesById,
  entitiesLoading = false,
  visibleColumns = BOOK_COLUMNS,
}: {
  books: BookView[];
  /** Show the owning-entity column — the "all books" list where books span entities. */
  showEntity?: boolean;
  /** Entity lookup by id, used to resolve `entity_id` to a display name + NIPC flag. */
  entitiesById?: Map<string, Entity>;
  /** Entities query still loading — render a placeholder instead of the raw id. */
  entitiesLoading?: boolean;
  /**
   * The per-user visible column set (t37). `Actions` is structural and always present; `Entity`
   * is governed by `showEntity`, not this set. Defaults to every column, so call-sites that do
   * not personalise (an entity's own book list) render the full table unchanged.
   */
  visibleColumns?: readonly BookColumn[];
}) {
  const t = useT();
  const openLabel = t('common.open');
  const shows = (column: BookColumn) => visibleColumns.includes(column);
  if (books.length === 0) {
    return <EmptyState title={t('books.empty')} />;
  }
  return (
    <div className={`books-table${showEntity ? ' books-table--with-entity' : ''}`}>
      <Table
        head={
          <tr>
            {showEntity ? <th data-book-column="Entity">{t('books.entity')}</th> : null}
            {shows('Kind') ? <th data-book-column="Kind">{t('books.th.type')}</th> : null}
            {shows('Purpose') ? <th data-book-column="Purpose">{t('books.th.purpose')}</th> : null}
            {shows('State') ? <th data-book-column="State">{t('books.th.state')}</th> : null}
            {shows('Opening') ? <th data-book-column="Opening">{t('books.th.opening')}</th> : null}
            {shows('LastAct') ? <th data-book-column="LastAct">{t('books.th.lastAct')}</th> : null}
            <th data-book-column="Actions" />
          </tr>
        }
      >
        {books.map((book) => {
          const actionLabel = openBookLabel(book, openLabel);
          return (
            <tr key={book.id}>
              {showEntity ? (
                <BookTableCell column="Entity">
                  <BookEntityRef
                    book={book}
                    entitiesById={entitiesById}
                    loading={entitiesLoading}
                  />
                </BookTableCell>
              ) : null}
              {shows('Kind') ? (
                <BookTableCell column="Kind">
                  <Truncate text={bookKindLabels[book.kind]} />
                </BookTableCell>
              ) : null}
              {shows('Purpose') ? (
                <BookTableCell column="Purpose">
                  <Truncate text={book.purpose ?? '—'} />
                </BookTableCell>
              ) : null}
              {shows('State') ? (
                <BookTableCell column="State">
                  {/* No tooltip: the native `title` here repeated the badge's own visible text
                      verbatim, so it revealed nothing (t31). */}
                  <span className="books-table__state">
                    <Badge tone={stateTone(book.state)}>{bookStateLabels[book.state]}</Badge>
                  </span>
                </BookTableCell>
              ) : null}
              {shows('Opening') ? (
                <BookTableCell column="Opening">
                  <Truncate text={book.opening_date ?? '—'} mono />
                </BookTableCell>
              ) : null}
              {shows('LastAct') ? (
                <BookTableCell column="LastAct">
                  <Truncate text={book.last_ata_number > 0 ? String(book.last_ata_number) : '—'} />
                </BookTableCell>
              ) : null}
              <BookTableCell column="Actions" actions>
                <span className="books-table__actions">
                  <Tooltip label={actionLabel} placement="left">
                    <Link
                      className="btn btn--ghost btn--icon btn--iconOnly books-table__open"
                      to={`/books/${book.id}`}
                      aria-label={actionLabel}
                    >
                      <span className="btn__icon" aria-hidden="true">
                        <Icon.ArrowRight />
                      </span>
                    </Link>
                  </Tooltip>
                </span>
              </BookTableCell>
            </tr>
          );
        })}
      </Table>
    </div>
  );
}
