/**
 * Open a book (WFL-10/11) on its own route (`/books/new`), reached from the neat "Abrir
 * livro" button on the Livros list and on an entity's detail page (t13 item 7). When an
 * `?entidade=<id>` query parameter is present the book is fixed to that entity (no
 * picker); otherwise the operator picks from the registered entities. At least one entity
 * must exist first.
 */
import { Link, useSearchParams } from 'react-router-dom';
import { useEntities } from '../../api/hooks';
import { useT } from '../../i18n';
import { Card, EmptyState, PageHeader, Skeleton } from '../../ui';
import { OpenBookForm } from './OpenBookForm';

export function NewBookPage() {
  const t = useT();
  const [params] = useSearchParams();
  const fixedEntity = params.get('entidade') ?? undefined;
  const entities = useEntities();

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/books">{t('books.crumb')}</Link> · {t('books.newBookCrumb')}
          </>
        }
        title={t('books.newBook')}
      />

      {fixedEntity ? (
        <OpenBookForm entityId={fixedEntity} />
      ) : entities.isLoading ? (
        // Mirror the open-book form's shape while the entity list loads (CONVENTIONS: a
        // content-shaped surface reserves its real box).
        <Card title={t('books.openBook')}>
          <div className="form">
            <Skeleton height="2.4rem" />
            <Skeleton height="2.4rem" />
            <Skeleton height="2.4rem" />
          </div>
        </Card>
      ) : entities.data && entities.data.length > 0 ? (
        <OpenBookForm entities={entities.data} />
      ) : (
        <Card title={t('books.openBook')}>
          <EmptyState title={t('books.noEntities')}>
            <p>
              {t('books.needEntity.before')}
              <Link to="/entities">{t('books.needEntity.link')}</Link>
              {t('books.needEntity.after')}
            </p>
          </EmptyState>
        </Card>
      )}
    </div>
  );
}
