/**
 * The integrations body of the Administração surface (t36) — Grupos / Conectores / Repositórios ZK.
 *
 * This is the BODY of the retired `OperationsPage`, re-parented: the tenant picker (`?tenant=`, from
 * the entities directory), the entity-list gate (loading / error / empty-tenant), and the dispatch
 * to the three area panels. What it deliberately DROPS is the old page-level chrome — the
 * `PageHeader` and the `useSectionNav` 3-way strip. In the admin surface those belong to
 * SettingsPage: the page title is "Administração" and the active integrations area arrives as the
 * `sub` prop off the `/admin/:sub` segment. The three area components
 * ({@link GroupsOperations} / {@link ConnectorOperations} / {@link RepositoryOperations}) and their
 * logic modules are reused UNCHANGED; only their host moved.
 *
 * The tenant and every per-panel selection stay query params: they narrow what a panel shows rather
 * than naming which area you are on, so they survive the move and travel with a bookmark.
 */
import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useEntities } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Card,
  ErrorNote,
  Field,
  InlineWarning,
  Select,
  SkeletonForm,
  SkeletonRegion,
  SkeletonTable,
} from '../../ui';
import { tenantIdsFromEntities } from '../operations/operatorModels';
import { ConnectorOperations } from '../operations/ConnectorOperations';
import { GroupsOperations } from '../operations/GroupsOperations';
import { RepositoryOperations } from '../operations/RepositoryOperations';
import '../operations/OperationsPage.css';

/** The three integrations areas. Slugs are English, matching the admin `:sub` segments. */
export type OperationsSection = 'groups' | 'connectors' | 'repositories';

/** An unknown segment falls back to Grupos rather than blanking the panel. */
export function operationsSectionFromParam(value: string | null | undefined): OperationsSection {
  if (value === 'connectors' || value === 'repositories') return value;
  return 'groups';
}

export function AdminIntegrationsPanel({ sub }: { sub: OperationsSection }) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const entities = useEntities();
  const tenantIds = tenantIdsFromEntities(entities.data ?? []);
  const requestedTenant = params.get('tenant') ?? '';
  const tenantId = tenantIds.includes(requestedTenant) ? requestedTenant : (tenantIds[0] ?? '');

  useEffect(() => {
    if (!tenantId || requestedTenant === tenantId) return;
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.set('tenant', tenantId);
        return next;
      },
      { replace: true },
    );
  }, [requestedTenant, setParams, tenantId]);

  function selectTenant(nextTenant: string) {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.set('tenant', nextTenant);
        next.delete('group');
        next.delete('library');
        next.delete('target');
        next.delete('job');
        next.delete('repository');
        next.delete('object');
        return next;
      },
      { replace: true },
    );
  }

  return (
    <div className="stack operations-page">
      {/* The tenant picker was the OperationsPage header's action; in the admin surface the header
          belongs to SettingsPage, so it leads the panel body instead. */}
      {tenantIds.length > 0 ? (
        <Field label={t('operations.tenant.label')} htmlFor="admin-integrations-tenant">
          <Select
            id="admin-integrations-tenant"
            value={tenantId}
            onChange={(event) => selectTenant(event.target.value)}
            options={tenantIds.map((id) => ({
              value: id,
              label:
                entities.data?.find((entity) => entity.tenant_id === id)?.name ??
                t('operations.tenant.fallback', { id }),
            }))}
          />
        </Field>
      ) : null}

      {/* The entity list gates both the tenant picker and the whole section body, so this
          wait is the panel. Every area below is the same two-card shape — a create form over a
          list table — so the placeholder reserves exactly that and the real panel swaps in
          without shoving the page down. */}
      {entities.isLoading ? (
        <SkeletonRegion className="stack">
          <Card>
            <SkeletonForm fields={2} />
          </Card>
          <Card>
            <SkeletonTable cols={4} />
          </Card>
        </SkeletonRegion>
      ) : null}
      {entities.error ? <ErrorNote error={entities.error} /> : null}
      {!entities.isLoading && !entities.error && tenantIds.length === 0 ? (
        <InlineWarning tone="info" title={t('operations.tenant.empty.title')}>
          <p>{t('operations.tenant.empty.body')}</p>
          <Link className="btn btn--secondary" to="/entities/new">
            {t('operations.tenant.empty.action')}
          </Link>
        </InlineWarning>
      ) : null}

      {tenantId ? (
        <div className="route-transition" key={`${tenantId}:${sub}`}>
          {sub === 'groups' ? (
            <GroupsOperations
              tenantId={tenantId}
              entities={(entities.data ?? []).filter((entity) => entity.tenant_id === tenantId)}
            />
          ) : null}
          {sub === 'connectors' ? <ConnectorOperations tenantId={tenantId} /> : null}
          {sub === 'repositories' ? (
            <RepositoryOperations tenantId={tenantId} entities={entities.data ?? []} />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
