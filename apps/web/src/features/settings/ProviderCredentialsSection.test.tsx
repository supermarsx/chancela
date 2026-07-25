import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import type { ProviderCredentialProbeResponse, ProviderCredentialsListView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';

const list: ProviderCredentialsListView = {
  strict: false,
  protection_level: 'confidential',
  can_store: true,
  providers: [
    {
      mode: 'csc',
      provider_id: 'encosto qtsp',
      entries: [
        {
          entry_id: 'entry/a',
          label: 'Primária',
          priority: 0,
          enabled: true,
          endpoint: 'https://qtsp.example/csc',
          selectors: { authorization: 'service' },
          fields: [{ field_name: 'client_secret', configured: true }],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
        {
          entry_id: 'entry-b',
          label: 'Secundária',
          priority: 1,
          enabled: false,
          selectors: {},
          fields: [],
          created_at: '2026-07-01T11:00:00Z',
          updated_at: '2026-07-01T11:00:00Z',
        },
      ],
    },
  ],
};

const probe: ProviderCredentialProbeResponse = {
  mode: 'csc',
  provider_id: 'encosto qtsp',
  entry_id: 'entry/a',
  status: 'ok',
  provider_contacted: true,
  private_key_operation_performed: false,
  signer_authorization_requested: false,
  document_signed: false,
  legal_validity_claimed: false,
  qualified_status_determined: false,
  checks: [{ name: 'credentials_info', status: 'passed', detail: 'Certificate parsed.' }],
  tested_at: '2026-07-25T10:00:00Z',
  duration_ms: 42,
};

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(
  view: ProviderCredentialsListView = list,
  probeResult: ProviderCredentialProbeResponse = probe,
  options: {
    listStatus?: number;
    listBody?: unknown;
    hangList?: boolean;
    writeStatus?: number;
    writeBody?: unknown;
  } = {},
) {
  const {
    listStatus = 200,
    listBody = view,
    hangList = false,
    writeStatus = 200,
    writeBody = { mode: 'csc', provider_id: 'encosto qtsp', deleted: false },
  } = options;
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (method === 'GET' && hangList) return new Promise<Response>(() => {});
    const body = method === 'GET' ? listBody : url.endsWith('/probe') ? probeResult : writeBody;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status: method === 'GET' ? listStatus : writeStatus,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as unknown as typeof fetch;
  return { fn, calls };
}

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{`${location.pathname}${location.search}`}</output>;
}

function renderSection() {
  return renderWithProviders(
    <Routes>
      <Route path="/admin/signing/providers" element={<ProviderCredentialsSection />} />
      <Route path="*" element={<LocationProbe />} />
    </Routes>,
    ['/admin/signing/providers'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ProviderCredentialsSection', () => {
  it('renders a metadata-only provider table and navigates create/edit to dedicated pages', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    expect(await screen.findByText('Primária')).toBeTruthy();
    expect(screen.getByText('https://qtsp.example/csc')).toBeTruthy();
    expect(screen.getByText(/client_secret · configurado/)).toBeTruthy();
    expect(document.body.textContent).not.toContain('sk_live');

    const primaryRow = screen.getByText('Primária').closest('tr') as HTMLElement;
    fireEvent.click(within(primaryRow).getByRole('button', { name: 'Editar' }));
    expect(screen.getByTestId('location').textContent).toBe(
      '/admin/signing/providers/csc/encosto%20qtsp/entry%2Fa/edit',
    );
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
  });

  it('opens top-level and per-provider create actions on the new page', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    const view = renderSection();

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    expect(screen.getByTestId('location').textContent).toBe('/admin/signing/providers/new');
    view.unmount();

    renderSection();
    const card = (await screen.findByText('QTSP CSC · encosto qtsp')).closest(
      '.panel',
    ) as HTMLElement;
    fireEvent.click(within(card).getByRole('button', { name: 'Adicionar entrada' }));
    expect(screen.getByTestId('location').textContent).toBe(
      '/admin/signing/providers/new?mode=csc&provider=encosto+qtsp',
    );
  });

  it('redirects the retired inline configure bookmark to the dedicated page', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(
      <Routes>
        <Route path="/admin/signing/providers" element={<ProviderCredentialsSection />} />
        <Route path="*" element={<LocationProbe />} />
      </Routes>,
      ['/admin/signing/providers?configure=pkcs12'],
    );

    await waitFor(() =>
      expect(screen.getByTestId('location').textContent).toBe(
        '/admin/signing/providers/new?mode=pkcs12',
      ),
    );
  });

  it('runs the exact-entry probe and keeps its list result compact and honest', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const row = (await screen.findByText('Primária')).closest('tr') as HTMLElement;
    fireEvent.click(within(row).getByRole('button', { name: 'Testar' }));

    await waitFor(() => {
      expect(
        stub.calls.some(
          (call) =>
            call.method === 'POST' &&
            call.url.endsWith('/provider-credentials/csc/encosto%20qtsp/entries/entry%2Fa/probe'),
        ),
      ).toBe(true);
    });
    expect(within(row).getByText('Operacional')).toBeTruthy();
    expect(within(row).getByText(/não assina documentos/i)).toBeTruthy();
    expect(within(row).queryByRole('heading', { name: 'Resultado do teste' })).toBeNull();
  });

  it('confirms a PKCS#12 list probe and sends nothing on cancel', async () => {
    const view: ProviderCredentialsListView = {
      ...list,
      providers: [
        {
          mode: 'pkcs12',
          provider_id: 'local',
          entries: [
            {
              entry_id: 'entry-p12',
              label: 'Chave local',
              priority: 0,
              enabled: true,
              selectors: {},
              fields: [{ field_name: 'pfx_der', configured: true }],
              created_at: '2026-07-01T10:00:00Z',
              updated_at: '2026-07-01T10:00:00Z',
            },
          ],
        },
      ],
    };
    const stub = stubFetch(view);
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    fireEvent.click(await screen.findByRole('button', { name: 'Testar' }));
    expect(await screen.findByRole('dialog')).toBeTruthy();
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));
    expect(screen.queryByRole('dialog')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Testar' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Executar operação de chave' }));
    await waitFor(() => {
      const request = stub.calls.find(
        (call) => call.method === 'POST' && call.url.endsWith('/probe'),
      );
      expect(JSON.parse(request?.body ?? '{}')).toEqual({
        confirm_private_key_operation: true,
      });
      expect(screen.queryByRole('dialog')).toBeNull();
    });
  });

  it('keeps reorder, enable/disable and delete mutations on the list', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const first = (await screen.findByText('Primária')).closest('tr') as HTMLElement;
    fireEvent.click(within(first).getByRole('button', { name: 'Descer prioridade' }));
    fireEvent.click(within(first).getByRole('switch', { name: 'Ativa' }));
    fireEvent.click(within(first).getByRole('button', { name: 'Remover' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Remover entrada' }));

    await waitFor(() => {
      expect(stub.calls.some((call) => call.url.endsWith('/reorder'))).toBe(true);
      expect(stub.calls.some((call) => call.method === 'PATCH')).toBe(true);
      expect(stub.calls.some((call) => call.method === 'DELETE')).toBe(true);
    });
  });

  it('disables configuring and probing for a principal without signing.configure', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <ProviderCredentialsSection />
      </StaticPermissionsProvider>,
      ['/admin/signing/providers'],
    );

    const create = await screen.findByRole('button', { name: 'Nova entrada' });
    expect(create.getAttribute('aria-disabled')).toBe('true');
    const test = screen.getAllByRole('button', { name: 'Testar' })[0];
    expect(test.getAttribute('aria-disabled')).toBe('true');
    fireEvent.click(test);
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
  });

  it('states when secrets cannot be stored and keeps create inert', async () => {
    const stub = stubFetch({
      strict: true,
      can_store: false,
      storage_failure: 'not_persistent',
      providers: [],
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    expect(await screen.findByText('Não é possível guardar credenciais')).toBeTruthy();
    const create = screen.getByRole('button', { name: 'Nova entrada' }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
  });

  it('keeps loading, list errors, and all storage postures honest', async () => {
    vi.stubGlobal('fetch', stubFetch(list, probe, { hangList: true }).fn);
    const loading = renderSection();
    expect(screen.getByText('A carregar…')).toBeTruthy();
    loading.unmount();

    vi.stubGlobal(
      'fetch',
      stubFetch(list, probe, {
        listStatus: 503,
        listBody: { error: 'cofre temporariamente indisponível' },
      }).fn,
    );
    const failed = renderSection();
    expect(await screen.findByText(/cofre temporariamente indisponível/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Nova entrada' })).toBeNull();
    failed.unmount();

    vi.stubGlobal(
      'fetch',
      stubFetch({ ...list, strict: true, protection_level: 'confidential', providers: [] }).fn,
    );
    const confidential = renderSection();
    expect(await screen.findByText('Armazenamento confidencial')).toBeTruthy();
    expect(screen.getByText('Sem credenciais de fornecedor')).toBeTruthy();
    confidential.unmount();

    vi.stubGlobal(
      'fetch',
      stubFetch({
        ...list,
        strict: true,
        protection_level: 'obfuscation',
        providers: [],
      }).fn,
    );
    const strict = renderSection();
    expect(await screen.findByText(/modo estrito está ativo/i)).toBeTruthy();
    strict.unmount();

    vi.stubGlobal(
      'fetch',
      stubFetch({
        ...list,
        can_store: undefined,
        protection_level: undefined,
        providers: [],
      }).fn,
    );
    renderSection();
    expect(await screen.findByText('Não é possível guardar credenciais')).toBeTruthy();
    expect(screen.queryByText('Ofuscação — defesa em profundidade')).toBeNull();
  });

  it('reports reorder failures and preserves the requested permutation', async () => {
    const stub = stubFetch(list, probe, {
      writeStatus: 500,
      writeBody: { error: 'ordenação recusada' },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const second = (await screen.findByText('Secundária')).closest('tr') as HTMLElement;
    fireEvent.click(within(second).getByRole('button', { name: 'Subir prioridade' }));

    expect(await screen.findByText(/ordenação recusada/)).toBeTruthy();
    const request = stub.calls.find((call) => call.url.endsWith('/reorder'));
    expect(JSON.parse(request?.body ?? '{}').order).toEqual(['entry-b', 'entry/a']);
  });
});
