/**
 * Shared render of a book list (used on the Livros page and an entity's detail page).
 */
import { Link } from 'react-router-dom';
import type { BookView } from '../../api/types';
import { bookKindLabels, bookStateLabels } from '../../api/labels';
import { useT } from '../../i18n';
import { Badge, EmptyState, Table } from '../../ui';

function stateTone(state: BookView['state']) {
  if (state === 'Open') return 'ok' as const;
  if (state === 'Closed') return 'neutral' as const;
  return 'accent' as const;
}

export function BooksTable({ books }: { books: BookView[] }) {
  const t = useT();
  if (books.length === 0) {
    return <EmptyState title={t('books.empty')} />;
  }
  return (
    <Table
      head={
        <tr>
          <th>{t('books.th.type')}</th>
          <th>{t('books.th.purpose')}</th>
          <th>{t('books.th.state')}</th>
          <th>{t('books.th.opening')}</th>
          <th>{t('books.th.lastAct')}</th>
          <th />
        </tr>
      }
    >
      {books.map((book) => (
        <tr key={book.id}>
          <td>{bookKindLabels[book.kind]}</td>
          <td>{book.purpose ?? '—'}</td>
          <td>
            <Badge tone={stateTone(book.state)}>{bookStateLabels[book.state]}</Badge>
          </td>
          <td>{book.opening_date ?? '—'}</td>
          <td>{book.last_ata_number > 0 ? book.last_ata_number : '—'}</td>
          <td>
            <Link to={`/livros/${book.id}`}>{t('common.open')}</Link>
          </td>
        </tr>
      ))}
    </Table>
  );
}
