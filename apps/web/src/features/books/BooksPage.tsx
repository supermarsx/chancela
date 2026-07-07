/**
 * Livros — the full-width list of every book across all entities. Opening a book lives
 * behind a neat "Abrir livro" button in the panel header, which opens the dedicated
 * open-book route (`/livros/novo`) rather than an always-visible aside form (t13 item 7).
 */
import { useBooks } from '../../api/hooks';
import { useT } from '../../i18n';
import { ButtonLink, Card, ErrorNote, Icon, PageHeader, SkeletonTable } from '../../ui';
import { BooksTable } from './BooksTable';

export function BooksPage() {
  const t = useT();
  const books = useBooks();

  return (
    <div className="stack">
      <PageHeader
        title={t('books.title')}
        actions={
          <ButtonLink to="/livros/novo" variant="primary" icon={<Icon.BookPlus />}>
            {t('books.openBook')}
          </ButtonLink>
        }
      />

      <Card title={t('books.allBooks')}>
        {books.isLoading ? (
          <SkeletonTable cols={5} />
        ) : books.error ? (
          <ErrorNote error={books.error} />
        ) : (
          <BooksTable books={books.data ?? []} />
        )}
      </Card>
    </div>
  );
}
