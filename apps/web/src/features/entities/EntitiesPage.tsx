/**
 * Entidades — the full-width list of registered entities. Creating an entity (by hand or
 * from a certidão permanente) lives behind neat buttons in the panel header, each opening
 * its own dedicated route (`/entidades/nova`, `/entidades/importar`) — so the list is no
 * longer squeezed by an always-visible aside form (t13 items 1–2).
 */
import { Link } from 'react-router-dom';
import { useEntities } from '../../api/hooks';
import { entityFamilyLabels } from '../../api/labels';
import { useT } from '../../i18n';
import {
  Badge,
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Icon,
  PageHeader,
  SkeletonTable,
  Table,
} from '../../ui';
import { NipcBadge } from './NipcBadge';

export function EntitiesPage() {
  const t = useT();
  const { data, isLoading, error } = useEntities();

  return (
    <div className="stack">
      <PageHeader
        title={t('entities.title')}
        actions={
          <>
            <ButtonLink to="/entidades/importar" icon={<Icon.Tray />}>
              {t('entities.importButton')}
            </ButtonLink>
            <ButtonLink to="/entidades/nova" variant="primary" icon={<Icon.Plus />}>
              {t('entities.newButton')}
            </ButtonLink>
          </>
        }
      />

      <Card title={t('entities.registeredCard')}>
        {isLoading ? (
          <SkeletonTable cols={5} />
        ) : error ? (
          <ErrorNote error={error} />
        ) : !data || data.length === 0 ? (
          <EmptyState title={t('entities.empty.title')}>
            <p>
              {t('entities.emptyBody.before')}
              <strong>{t('entities.newButton')}</strong>
              {t('entities.emptyBody.after')}
            </p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{t('entities.th.name')}</th>
                <th>{t('entities.th.nipc')}</th>
                <th>{t('entities.th.seat')}</th>
                <th>{t('entities.th.form')}</th>
                <th />
              </tr>
            }
          >
            {data.map((ent) => (
              <tr key={ent.id}>
                <td>{ent.name}</td>
                <td>
                  <span className="nipc-cell">
                    <code className="mono">{ent.nipc}</code>
                    {!ent.nipc_validated ? <NipcBadge /> : null}
                  </span>
                </td>
                <td>{ent.seat}</td>
                <td>
                  <Badge>{entityFamilyLabels[ent.family]}</Badge>
                </td>
                <td>
                  <Link to={`/entidades/${ent.id}`}>{t('common.open')}</Link>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
