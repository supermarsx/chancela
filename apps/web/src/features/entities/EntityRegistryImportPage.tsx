/**
 * Enrich an existing entity from its certidão permanente (t13 item 3). The import panel
 * used to crowd the entity-detail aside; it now opens on its own route
 * (`/entidades/:id/importar`) from a neat button, leaving the entity's "Registo
 * comercial" provenance full width. On return to the entity, the refetched provenance
 * reflects whatever was imported. The panel keeps the conflict/overwrite flow and the
 * transient-secret handling intact.
 */
import { Link, useParams } from 'react-router-dom';
import { useEntity } from '../../api/hooks';
import { useT } from '../../i18n';
import { PageHeader } from '../../ui';
import { RegistryImportPanel } from '../registry/RegistryImportPanel';

export function EntityRegistryImportPage() {
  const t = useT();
  const { id = '' } = useParams();
  const entity = useEntity(id);
  const name = entity.data?.name ?? '…';

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/entidades">{t('entities.crumb')}</Link> ·{' '}
            <Link to={`/entidades/${id}`}>{name}</Link> · {t('entities.importCrumb')}
          </>
        }
        title={t('entities.importPageTitle')}
      />

      <RegistryImportPanel entityId={id} />

      <p>
        <Link to={`/entidades/${id}`}>{t('entities.backToEntity')}</Link>
      </p>
    </div>
  );
}
