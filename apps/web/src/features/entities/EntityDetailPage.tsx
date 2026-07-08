/**
 * A single entity, full width. Its "Registo comercial" provenance now spans the whole
 * column (t13 item 3), with the certidão import moved behind a neat button that opens
 * `/entidades/:id/importar`. Opening a book against this entity is likewise a neat
 * button that carries the entity through to the open-book page.
 */
import { Link, useParams } from 'react-router-dom';
import { useBooks, useEntity } from '../../api/hooks';
import { entityFamilyLabels, entityKindLabels } from '../../api/labels';
import { useT } from '../../i18n';
import {
  Card,
  ErrorNote,
  Icon,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
} from '../../ui';
import { GateButtonLink, scopeEntity } from '../session/permissions';
import { BooksTable } from '../books/BooksTable';
import { RegistryProvenance } from '../registry/RegistryProvenance';
import { EntityStatuteEditor } from './EntityStatuteEditor';
import { NipcBadge } from './NipcBadge';
import { PrintButton } from './PrintButton';
import { EntityPrintDocument } from './EntityPrintDocument';

export function EntityDetailPage() {
  const t = useT();
  const { id = '' } = useParams();
  const entity = useEntity(id);
  const books = useBooks(id);

  if (entity.isLoading) {
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/entidades">{t('entities.crumb')}</Link>}
          title={<Skeleton width="16rem" height="1.6rem" />}
        />
        <Card title={t('entities.identificationCard')}>
          <SkeletonDeflist />
        </Card>
      </div>
    );
  }
  if (entity.error) return <ErrorNote error={entity.error} />;
  if (!entity.data) return null;

  const ent = entity.data;

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            <Link to="/entidades">{t('entities.crumb')}</Link> · {ent.name}
          </>
        }
        title={ent.name}
        actions={<PrintButton />}
      />

      <Card title={t('entities.identificationCard')}>
        <dl className="deflist">
          <div>
            <dt>{t('entities.field.nipc')}</dt>
            <dd>
              <span className="nipc-cell">
                <code className="mono">{ent.nipc}</code>
                {!ent.nipc_validated ? <NipcBadge /> : null}
              </span>
            </dd>
          </div>
          <div>
            <dt>{t('entities.field.seat')}</dt>
            <dd>{ent.seat}</dd>
          </div>
          <div>
            <dt>{t('entities.field.legalForm')}</dt>
            <dd>{entityKindLabels[ent.kind]}</dd>
          </div>
          <div>
            <dt>{t('entities.field.family')}</dt>
            <dd>{entityFamilyLabels[ent.family]}</dd>
          </div>
        </dl>
      </Card>

      <EntityStatuteEditor entity={ent} />

      <section className="stack">
        <div className="section-head">
          <h3 className="section-subtitle">{t('entities.registrySection')}</h3>
          <GateButtonLink
            perm="entity.registry.import"
            scope={scopeEntity(ent.id)}
            to={`/entidades/${ent.id}/importar`}
            icon={<Icon.Tray />}
          >
            {t('entities.importButton')}
          </GateButtonLink>
        </div>
        <RegistryProvenance entityId={ent.id} />
      </section>

      <Card
        title={t('entities.booksCard')}
        actions={
          <GateButtonLink
            perm="book.open"
            scope={scopeEntity(ent.id)}
            to={`/livros/novo?entidade=${ent.id}`}
            variant="primary"
            icon={<Icon.BookPlus />}
          >
            {t('entities.openBookButton')}
          </GateButtonLink>
        }
      >
        {books.isLoading ? (
          <SkeletonTable cols={5} />
        ) : books.error ? (
          <ErrorNote error={books.error} />
        ) : (
          <BooksTable books={books.data ?? []} />
        )}
      </Card>

      {/* Print-only filing abstract (portaled to <body>, hidden on screen). */}
      <EntityPrintDocument entityId={ent.id} />
    </div>
  );
}
