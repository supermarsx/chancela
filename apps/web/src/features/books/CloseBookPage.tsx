/**
 * Close a book on its own route (`/books/:id/close`), reached from the neat "Encerrar
 * livro" button on an open book (t13 item 7). Thin shell around `CloseBookForm`; on close
 * it returns to the book, which now shows the termo de encerramento.
 */
import { Link, useNavigate, useParams } from 'react-router-dom';
import { useT } from '../../i18n';
import { Card, PageHeader } from '../../ui';
import { CloseBookForm } from './CloseBookForm';

export function CloseBookPage() {
  const t = useT();
  const { id = '' } = useParams();
  const navigate = useNavigate();

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/books">{t('books.crumb')}</Link> ·{' '}
            <Link to={`/books/${id}`}>{t('books.singular')}</Link> · {t('books.closeCrumb')}
          </>
        }
        title={t('books.closeBook')}
      />

      <Card title={t('books.termoEncerramento')}>
        <CloseBookForm bookId={id} onClosed={() => navigate(`/books/${id}`)} />
      </Card>
    </div>
  );
}
