import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useLocation } from 'react-router-dom';
import type { Entity, TenantRepositoryPolicy } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { OperationsPage, operationsSectionFromParam } from './OperationsPage';

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

describe('OperationsPage', () => {
  it('falls back unknown or absent deep-link sections to groups', () => {
    expect(operationsSectionFromParam(null)).toBe('groups');
    expect(operationsSectionFromParam('unknown')).toBe('groups');
    expect(operationsSectionFromParam('connectors')).toBe('connectors');
    expect(operationsSectionFromParam('repositories')).toBe('repositories');
  });

  it('explains the current tenant-directory boundary when no entity exposes a tenant', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json([])));

    renderWithProviders(<OperationsPage />, ['/operations']);

    expect(await screen.findByRole('heading', { name: 'Operações' })).toBeTruthy();
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

    renderWithProviders(<OperationsPage />, ['/operations']);

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
        <OperationsPage />
        <LocationProbe />
      </>,
      ['/operations?tenant=tenant-1&group=group-1&repository=repo-1&object=obj-1'],
    );

    const picker = (await screen.findByLabelText('Organização')) as HTMLSelectElement;
    // Both tenants are offered, named by the entity that exposes them.
    expect(Array.from(picker.options, (option) => option.value)).toEqual(['tenant-1', 'tenant-2']);
    fireEvent.change(picker, { target: { value: 'tenant-2' } });

    await waitFor(() =>
      expect(screen.getByTestId('location').textContent).toBe('/operations?tenant=tenant-2'),
    );
  });

  it('keeps every operator area reachable through URL-backed task tabs', async () => {
    const requests: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL) => {
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
      }),
    );

    renderWithProviders(
      <>
        <OperationsPage />
        <LocationProbe />
      </>,
      ['/operations/connectors'],
    );

    const tabs = await screen.findByRole('group', { name: 'Áreas de operações' });
    expect(
      within(tabs)
        .getByRole('button', { name: 'Conectores e trabalhos' })
        .getAttribute('aria-pressed'),
    ).toBe('true');
    expect(await screen.findByText('Ainda não existem destinos de conector.')).toBeTruthy();
    expect(screen.getByText('Apenas referências de credenciais')).toBeTruthy();
    await waitFor(() =>
      expect(screen.getByTestId('location').textContent).toBe(
        '/operations/connectors?tenant=tenant-1',
      ),
    );

    fireEvent.click(within(tabs).getByRole('button', { name: 'Grupos e bibliotecas' }));
    expect(await screen.findByText('Ainda não existem grupos nesta organização.')).toBeTruthy();
    expect(screen.getByTestId('location').textContent).toBe('/operations?tenant=tenant-1');

    fireEvent.click(within(tabs).getByRole('button', { name: 'Repositórios ZK' }));
    expect(await screen.findByText('Ainda não existem repositórios.')).toBeTruthy();
    expect(screen.getByText('Zero knowledge é uma opção explícita')).toBeTruthy();
    expect(screen.getByTestId('location').textContent).toBe(
      '/operations/repositories?tenant=tenant-1',
    );

    expect(requests.some((url) => url.includes('/connector-targets'))).toBe(true);
    expect(requests.some((url) => url.endsWith('/groups'))).toBe(true);
    expect(requests.some((url) => url.endsWith('/repositories'))).toBe(true);
  });
});
