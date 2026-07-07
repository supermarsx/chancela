/**
 * Draft a new ata on its own route (`/livros/:id/nova-ata`), reached from the neat "Nova
 * ata" button on an open book (t13 item 7). Thin shell around `DraftAtaForm`, which
 * navigates to the ata editor on success.
 */
import { Link, useParams } from 'react-router-dom';
import { useT } from '../../i18n';
import { Card, PageHeader } from '../../ui';
import { DraftAtaForm } from './DraftAtaForm';

export function NewAtaPage() {
  const t = useT();
  const { id = '' } = useParams();

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/livros">{t('books.crumb')}</Link> ·{' '}
            <Link to={`/livros/${id}`}>{t('books.singular')}</Link> · {t('acts.newAta')}
          </>
        }
        title={t('acts.newAta')}
      />

      <Card title={t('acts.newAta')}>
        <DraftAtaForm bookId={id} />
      </Card>
    </div>
  );
}
