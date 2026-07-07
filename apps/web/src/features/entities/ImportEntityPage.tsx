/**
 * Create an entity from a certidão permanente (t13 item 2). The import-from-registry
 * flow used to live inline in the Entidades aside; it now has its own route
 * (`/entidades/importar`), reached from a neat button, so the list runs full width. The
 * form itself (`ImportFromRegistryForm`) already navigates to the new entity on success
 * and keeps the código de acesso strictly transient.
 */
import { Link } from 'react-router-dom';
import { useT } from '../../i18n';
import { PageHeader } from '../../ui';
import { ImportFromRegistryForm } from '../registry/ImportFromRegistryForm';

export function ImportEntityPage() {
  const t = useT();
  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/entidades">{t('entities.crumb')}</Link> · {t('entities.importCrumb')}
          </>
        }
        title={t('entities.importPageTitle')}
      />
      <ImportFromRegistryForm />
    </div>
  );
}
