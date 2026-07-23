import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { useLocation } from 'react-router-dom';
import type { Entity, TenantRepositoryPolicy } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { AdminIntegrationsPanel, operationsSectionFromParam } from './AdminIntegrationsPanel';

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

const entity = {
  id: 'entity-1',
  tenant_id: 'tenant-1',
  group_id: null,
  name: 'Entidade Operadora, Lda.',
  nipc: '500000000',
} as Entity;

const tenantPolicy: TenantRepositoryPolicy = {
  tenant_id: 'tenant-1',
  encryption_mode: 'standard',
  custody: {
    bring_your_own_key: true,
    webauthn_prf_unsealing: false,
    split_key_recovery: null,
  },
  gdpr_obligations_remain: true,
  created_at: '2026-07-16T00:00:00Z',
  updated_at: '2026-07-16T00:00:00Z',
};

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('AdminIntegrationsPanel', () => {
  it('falls back unknown or absent deep-link areas to groups', () => {
    expect(operationsSectionFromParam(null)).toBe('groups');
    expect(operationsSectionFromParam('unknown')).toBe('groups');
    expect(operationsSectionFromParam('connectors')).toBe('connectors');
    expect(operationsSectionFromParam('repositories')).toBe('repositories');
  });

  it('explains the current tenant-directory boundary when no entity exposes a tenant', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([])));

    renderWithProviders(<AdminIntegrationsPanel sub="groups" />, ['/admin/groups']);

    expect(await screen.findByText('Ainda não existe uma organização selecionável')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Criar entidade' }).getAttribute('href')).toBe(
      '/entities/new',
    );
    expect(screen.queryByLabelText('Organização')).toBeNull();
  });

  it('reports a failed entity load instead of pretending no organization exists', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(json({ error: 'Diretório indisponível' }, 503)),
    );

    renderWithProviders(<AdminIntegrationsPanel sub="groups" />, ['/admin/groups']);

    expect(await screen.findByText('Diretório indisponível')).toBeTruthy();
    expect(screen.queryByText('Ainda não existe uma organização selecionável')).toBeNull();
    expect(screen.queryByLabelText('Organização')).toBeNull();
  });

  it('switching organization drops the selections scoped to the previous one', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
        const url = typeof input === 'string' ? input : input.toString();
        if (url === '/v1/entities') {
          return json([entity, { ...entity, id: 'entity-2', tenant_id: 'tenant-2' }]);
        }
        if (url.endsWith('/groups')) return json([]);
        throw new Error(`Unexpected request: ${url}`);
      }),
    );

    renderWithProviders(
      <>
        <AdminIntegrationsPanel sub="groups" />
        <LocationProbe />
      </>,
      ['/admin/groups?tenant=tenant-1&group=group-1&repository=repo-1&object=obj-1'],
    );

    const picker = (await screen.findByLabelText('Organização')) as HTMLSelectElement;
    // Both tenants are offered, named by the entity that exposes them.
    expect(Array.from(picker.options, (option) => option.value)).toEqual(['tenant-1', 'tenant-2']);
    fireEvent.change(picker, { target: { value: 'tenant-2' } });

    await waitFor(() =>
      expect(screen.getByTestId('location').textContent).toBe('/admin/groups?tenant=tenant-2'),
    );
  });

  it('renders the area named by the `sub` prop against the selected tenant', async () => {
    const requests: string[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      requests.push(url);
      if (url === '/v1/entities') return json([entity]);
      if (url.includes('/connector-targets')) return json([]);
      if (url.includes('/connector-jobs')) {
        return json({ jobs: [], next_before_created_unix_millis: null });
      }
      if (url.endsWith('/repository-policy')) return json({ policy: tenantPolicy });
      if (url.endsWith('/repositories')) return json([]);
      if (url.endsWith('/groups')) return json([]);
      throw new Error(`Unexpected request: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    // Conectores: the area body renders, and the tenant is resolved off the entities directory.
    const connectors = renderWithProviders(<AdminIntegrationsPanel sub="connectors" />, [
      '/admin/connectors',
    ]);
    expect(await screen.findByText('Ainda não existem destinos de conector.')).toBeTruthy();
    expect(screen.getByText('Apenas referências de credenciais')).toBeTruthy();
    expect(requests.some((url) => url.includes('/connector-targets'))).toBe(true);
    connectors.unmount();

    // Repositórios ZK.
    const repositories = renderWithProviders(<AdminIntegrationsPanel sub="repositories" />, [
      '/admin/repositories',
    ]);
    expect(await screen.findByText('Ainda não existem repositórios.')).toBeTruthy();
    expect(screen.getByText('Zero knowledge é uma opção explícita')).toBeTruthy();
    expect(requests.some((url) => url.endsWith('/repositories'))).toBe(true);
    repositories.unmount();

    // Grupos.
    renderWithProviders(<AdminIntegrationsPanel sub="groups" />, ['/admin/groups']);
    expect(await screen.findByText('Ainda não existem grupos nesta organização.')).toBeTruthy();
    expect(requests.some((url) => url.endsWith('/groups'))).toBe(true);
  });
});
