import { useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { useEntities } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Card,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  PageHeader,
  Select,
  SkeletonForm,
  SkeletonRegion,
  SkeletonTable,
  SubNav,
} from '../../ui';
import { tenantIdsFromEntities } from './operatorModels';
import { ConnectorOperations } from './ConnectorOperations';
import { GroupsOperations } from './GroupsOperations';
import { RepositoryOperations } from './RepositoryOperations';
import './OperationsPage.css';

export type OperationsSection = 'groups' | 'connectors' | 'repositories';

export function operationsSectionFromParam(value: string | null): OperationsSection {
  if (value === 'connectors' || value === 'repositories') return value;
  return 'groups';
}

export function OperationsPage() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const entities = useEntities();
  const tenantIds = tenantIdsFromEntities(entities.data ?? []);
  const requestedTenant = params.get('tenant') ?? '';
  const tenantId = tenantIds.includes(requestedTenant) ? requestedTenant : (tenantIds[0] ?? '');
  const section = operationsSectionFromParam(params.get('view'));

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

  function selectSection(nextSection: OperationsSection) {
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (nextSection === 'groups') next.delete('view');
        else next.set('view', nextSection);
        return next;
      },
      { replace: true },
    );
  }

  return (
    <div className="stack operations-page">
      <PageHeader
        title={t('operations.title')}
        lede={t('operations.lede')}
        actions={
          tenantIds.length > 0 ? (
            <Field label={t('operations.tenant.label')} htmlFor="operations-tenant">
              <Select
                id="operations-tenant"
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
          ) : null
        }
      >
        <SubNav<OperationsSection>
          ariaLabel={t('operations.tabs.aria')}
          active={section}
          onSelect={selectSection}
          items={[
            { id: 'groups', label: t('operations.tabs.groups'), icon: <Icon.Users /> },
            { id: 'connectors', label: t('operations.tabs.connectors'), icon: <Icon.Shuffle /> },
            {
              id: 'repositories',
              label: t('operations.tabs.repositories'),
              icon: <Icon.Archive />,
            },
          ]}
        />
      </PageHeader>

      {/* The entity list gates both the tenant picker and the whole section body, so this
          wait is the page. Every section below is the same two-card shape — a create form
          over a list table — so the placeholder reserves exactly that and the real panel
          swaps in without shoving the page down. */}
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
          <Link className="btn btn--secondary" to="/entidades/nova">
            {t('operations.tenant.empty.action')}
          </Link>
        </InlineWarning>
      ) : null}

      {tenantId ? (
        <div className="route-transition" key={`${tenantId}:${section}`}>
          {section === 'groups' ? (
            <GroupsOperations
              tenantId={tenantId}
              entities={(entities.data ?? []).filter((entity) => entity.tenant_id === tenantId)}
            />
          ) : null}
          {section === 'connectors' ? <ConnectorOperations tenantId={tenantId} /> : null}
          {section === 'repositories' ? (
            <RepositoryOperations tenantId={tenantId} entities={entities.data ?? []} />
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
