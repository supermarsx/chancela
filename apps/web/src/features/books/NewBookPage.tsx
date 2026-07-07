/**
 * Open a book (WFL-10/11) on its own route (`/livros/novo`), reached from the neat "Abrir
 * livro" button on the Livros list and on an entity's detail page (t13 item 7). When an
 * `?entidade=<id>` query parameter is present the book is fixed to that entity (no
 * picker); otherwise the operator picks from the registered entities. At least one entity
 * must exist first.
 */
import { Link, useSearchParams } from 'react-router-dom';
import { useEntities } from '../../api/hooks';
import { useT } from '../../i18n';
import { Card, EmptyState, Loading, PageHeader } from '../../ui';
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
            <Link to="/livros">{t('books.crumb')}</Link> · {t('books.newBookCrumb')}
          </>
        }
        title={t('books.newBook')}
      />

      {fixedEntity ? (
        <OpenBookForm entityId={fixedEntity} />
      ) : entities.isLoading ? (
        <Loading />
      ) : entities.data && entities.data.length > 0 ? (
        <OpenBookForm entities={entities.data} />
      ) : (
        <Card title={t('books.openBook')}>
          <EmptyState title={t('books.noEntities')}>
            <p>
              {t('books.needEntity.before')}
              <Link to="/entidades">{t('books.needEntity.link')}</Link>
              {t('books.needEntity.after')}
            </p>
          </EmptyState>
        </Card>
      )}
    </div>
  );
}
