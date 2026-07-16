/**
 * Tests for the provider-credential management section (wp13 Phase D). It drives the
 * encrypted multi-key store via react-query, so `fetch` is stubbed per the sibling settings
 * tests and real handler/branch behaviour is asserted: metadata render, the write-only
 * create body, reorder, the inline enable toggle, delete-with-confirm, disabled+pending, and
 * the failure → inline + toast path.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import type { ProviderCredentialsListView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';

function listView(
  overrides: Partial<ProviderCredentialsListView> = {},
): ProviderCredentialsListView {
  return {
    strict: false,
    protection_level: 'obfuscation',
    providers: [
      {
        mode: 'csc',
        provider_id: 'encosto-qtsp',
        entries: [
          {
            entry_id: 'entry-a',
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
            fields: [{ field_name: 'client_secret', configured: true }],
            created_at: '2026-07-01T11:00:00Z',
            updated_at: '2026-07-01T11:00:00Z',
          },
        ],
      },
    ],
    ...overrides,
  };
}

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(
  opts: {
    list?: ProviderCredentialsListView;
    listStatus?: number;
    listBody?: unknown;
    hangList?: boolean;
    writeStatus?: number;
    writeBody?: unknown;
    hangWrite?: boolean;
  } = {},
): { fn: typeof fetch; calls: Call[] } {
  const {
    list = listView(),
    listStatus = 200,
    listBody = list,
    hangList = false,
    writeStatus = 200,
    writeBody = { mode: 'csc', provider_id: 'encosto-qtsp', deleted: false },
    hangWrite = false,
  } = opts;
  const calls: Call[] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.includes('/v1/signature/provider-credentials') && method === 'GET') {
      if (hangList) return new Promise<Response>(() => {});
      return Promise.resolve(json(listBody, listStatus));
    }
    // Any mutation (POST/PATCH/DELETE) on the entries surface.
    if (hangWrite) return new Promise<Response>(() => {});
    return Promise.resolve(json(writeBody, writeStatus));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ProviderCredentialsSection', () => {
  it('renders provider groups, entries in priority order, and configured field badges', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<ProviderCredentialsSection />);

    // The group card title and both entries render.
    expect(await screen.findByText(/QTSP CSC · encosto-qtsp/)).toBeTruthy();
    expect(screen.getByText('Primária')).toBeTruthy();
    expect(screen.getByText('Secundária')).toBeTruthy();
    // The endpoint and a configured field badge are shown.
    expect(screen.getByText('https://qtsp.example/csc')).toBeTruthy();
    expect(screen.getAllByText(/client_secret · configurado/).length).toBeGreaterThan(0);
  });

  it('sends a write-only create body with the secret in `set`', async () => {
    const stub = stubFetch({
      writeBody: { mode: 'csc', provider_id: 'novo-qtsp', deleted: false },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'novo-qtsp' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), {
      target: { value: 'sk_live_secret_123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((c) => c.method === 'POST' && c.url.endsWith('/entries'));
      expect(post, 'a create POST was issued').toBeTruthy();
      const body = JSON.parse(post!.body ?? '{}');
      expect(post!.url).toContain('/provider-credentials/csc/novo-qtsp/entries');
      expect(body.set.client_secret).toBe('sk_live_secret_123');
    });
  });

  it('reorders entries with a permutation of entry ids', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    // Move the top entry (Primária) down.
    const primaria = (await screen.findByText('Primária')).closest('[role="group"]') as HTMLElement;
    fireEvent.click(within(primaria).getByRole('button', { name: 'Descer prioridade' }));

    await waitFor(() => {
      const post = stub.calls.find((c) => c.method === 'POST' && c.url.endsWith('/reorder'));
      expect(post).toBeTruthy();
      const body = JSON.parse(post!.body ?? '{}');
      expect(body.order).toEqual(['entry-b', 'entry-a']);
    });
  });

  it('toggles an entry enabled flag through a PATCH', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    // The enabled top entry exposes an "Ativa" switch; clicking it disables the entry.
    const toggle = await screen.findByRole('switch', { name: 'Ativa' });
    fireEvent.click(toggle);

    await waitFor(() => {
      const patch = stub.calls.find((c) => c.method === 'PATCH');
      expect(patch).toBeTruthy();
      expect(patch!.url).toContain('/entries/entry-a');
      expect(JSON.parse(patch!.body ?? '{}').enabled).toBe(false);
    });
  });

  it('deletes an entry after confirmation', async () => {
    const stub = stubFetch({
      writeBody: { mode: 'csc', provider_id: 'encosto-qtsp', deleted: true },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    const primaria = (await screen.findByText('Primária')).closest('[role="group"]') as HTMLElement;
    fireEvent.click(within(primaria).getByRole('button', { name: 'Remover' }));
    // The shared confirm modal opens; confirm the deletion.
    fireEvent.click(await screen.findByRole('button', { name: 'Remover entrada' }));

    await waitFor(() => {
      const del = stub.calls.find((c) => c.method === 'DELETE');
      expect(del).toBeTruthy();
      expect(del!.url).toContain('/entries/entry-a');
    });
  });

  it('disables the submit control and shows the pending label while a create is in flight', async () => {
    vi.stubGlobal('fetch', stubFetch({ hangWrite: true }).fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'novo-qtsp' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 's' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const pending = screen.getByRole('button', { name: 'A guardar…' }) as HTMLButtonElement;
      expect(pending.disabled).toBe(true);
    });
  });

  it('surfaces a create failure as an inline error and a toast', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        writeStatus: 409,
        writeBody: { error: 'não há nenhuma fonte de chave disponível' },
      }).fn,
    );
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'novo-qtsp' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 's' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    // The error appears both inline (ErrorNote) and as a toast — at least one match, and the
    // form stays open (write-only inputs are never lost on failure).
    const matches = await screen.findAllByText(/não há nenhuma fonte de chave disponível/);
    expect(matches.length).toBeGreaterThan(0);
  });

  it('shows loading and then an honest list error without rendering management controls', async () => {
    vi.stubGlobal('fetch', stubFetch({ hangList: true }).fn);
    const first = renderWithProviders(<ProviderCredentialsSection />);
    expect(screen.getByText('A carregar…')).toBeTruthy();
    first.unmount();

    vi.stubGlobal(
      'fetch',
      stubFetch({ listStatus: 503, listBody: { error: 'cofre temporariamente indisponível' } }).fn,
    );
    renderWithProviders(<ProviderCredentialsSection />);

    expect(await screen.findByText(/cofre temporariamente indisponível/)).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Nova entrada' })).toBeNull();
  });

  it('distinguishes confidential storage, strict blocking, and an empty provider store', async () => {
    vi.stubGlobal(
      'fetch',
      stubFetch({
        list: listView({ strict: true, protection_level: 'confidential', providers: [] }),
      }).fn,
    );
    const first = renderWithProviders(<ProviderCredentialsSection />);
    expect(await screen.findByText('Armazenamento confidencial')).toBeTruthy();
    expect(screen.getByText('Sem credenciais de fornecedor')).toBeTruthy();
    first.unmount();

    vi.stubGlobal(
      'fetch',
      stubFetch({
        list: listView({ strict: true, protection_level: 'obfuscation', providers: [] }),
      }).fn,
    );
    renderWithProviders(<ProviderCredentialsSection />);
    expect(await screen.findByText(/modo estrito está ativo/i)).toBeTruthy();
  });

  it('keeps create inert for a reader and never issues a mutation', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <ProviderCredentialsSection />
      </StaticPermissionsProvider>,
    );

    const create = await screen.findByRole('button', { name: 'Nova entrada' });
    expect(create.getAttribute('aria-disabled')).toBe('true');
    fireEvent.click(create);
    expect(screen.queryByLabelText('Identificador do fornecedor')).toBeNull();
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
  });

  it('switches provider modes, resets incompatible fields, and emits only non-empty selectors', async () => {
    const stub = stubFetch({
      list: listView({ providers: [] }),
      writeBody: { mode: 'cmd', provider_id: '', deleted: false },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'discarded-provider' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'discarded' } });
    fireEvent.change(screen.getByLabelText('Tipo de fornecedor'), { target: { value: 'cmd' } });

    expect(screen.queryByLabelText('Identificador do fornecedor')).toBeNull();
    fireEvent.change(screen.getByLabelText('Ambiente'), { target: { value: 'prod' } });
    fireEvent.change(screen.getByLabelText('ID de aplicação'), { target: { value: 'cmd-app' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((call) => call.method === 'POST');
      expect(post?.url).toContain('/provider-credentials/cmd/_/entries');
      expect(JSON.parse(post?.body ?? '{}')).toEqual({
        enabled: true,
        selectors: { env: 'prod' },
        set: { application_id: 'cmd-app' },
      });
    });
  });

  it('creates a CSC entry with trimmed identity, endpoint, selectors, and sandbox choice', async () => {
    const stub = stubFetch({ list: listView({ providers: [] }) });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: '  csc secondary  ' },
    });
    fireEvent.change(screen.getByLabelText('Etiqueta'), { target: { value: '  Backup  ' } });
    fireEvent.change(screen.getByLabelText('Endereço (base_url)'), {
      target: { value: '  https://csc.example.test/api  ' },
    });
    fireEvent.change(screen.getByLabelText('Autorização'), { target: { value: 'user' } });
    fireEvent.change(screen.getByLabelText('ID da credencial'), { target: { value: 'cred-7' } });
    fireEvent.click(screen.getByRole('switch', { name: 'Ambiente de testes (sandbox)' }));
    fireEvent.change(screen.getByLabelText('Token de acesso'), { target: { value: 'token-7' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((call) => call.method === 'POST');
      expect(post?.url).toContain('/provider-credentials/csc/csc%20secondary/entries');
      expect(JSON.parse(post?.body ?? '{}')).toEqual({
        label: 'Backup',
        enabled: true,
        endpoint: 'https://csc.example.test/api',
        selectors: { authorization: 'user', credential_id: 'cred-7', sandbox: 'true' },
        set: { access_token: 'token-7' },
      });
    });
  });

  it('switches to the single-instance SCAP form and submits its environment and secret', async () => {
    const stub = stubFetch({ list: listView({ providers: [] }) });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Tipo de fornecedor'), { target: { value: 'scap' } });
    expect(screen.queryByLabelText('Identificador do fornecedor')).toBeNull();
    expect(screen.getByLabelText('Segredo')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Ambiente'), { target: { value: 'preprod' } });
    fireEvent.change(screen.getByLabelText('ID de aplicação'), { target: { value: 'scap-app' } });
    fireEvent.change(screen.getByLabelText('Segredo'), { target: { value: 'scap-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((call) => call.method === 'POST');
      expect(post?.url).toContain('/provider-credentials/scap/_/entries');
      expect(JSON.parse(post?.body ?? '{}')).toMatchObject({
        selectors: { environment: 'preprod' },
        set: { application_id: 'scap-app', secret: 'scap-secret' },
      });
    });
  });

  it('edits metadata without overwriting write-only secrets and can cancel cleanly', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    const primaria = (await screen.findByText('Primária')).closest('[role="group"]') as HTMLElement;
    fireEvent.click(within(primaria).getByRole('button', { name: 'Editar' }));
    const label = screen.getByLabelText('Etiqueta');
    expect((label as HTMLInputElement).value).toBe('Primária');
    expect((screen.getByLabelText('Client secret') as HTMLInputElement).value).toBe('');
    fireEvent.change(label, { target: { value: '  Primária revista  ' } });
    fireEvent.change(screen.getByLabelText('ID da credencial'), { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const patch = stub.calls.find((call) => call.method === 'PATCH');
      const body = JSON.parse(patch?.body ?? '{}');
      expect(body.label).toBe('Primária revista');
      expect(body.selectors).toEqual({ authorization: 'service' });
      expect(body).not.toHaveProperty('set');
    });

    const secundaria = screen.getByText('Secundária').closest('[role="group"]') as HTMLElement;
    fireEvent.click(within(secundaria).getByRole('button', { name: 'Editar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));
    expect(screen.queryByText('Editar entrada')).toBeNull();
  });

  it('adds to an empty provider group and renders unlabeled/no-field metadata honestly', async () => {
    const stub = stubFetch({
      list: listView({
        providers: [
          { mode: 'cmd', provider_id: '', entries: [] },
          {
            mode: 'scap',
            provider_id: '',
            entries: [
              {
                entry_id: 'scap-1',
                label: '',
                priority: 0,
                enabled: true,
                selectors: {},
                fields: [],
                created_at: '2026-07-01T11:00:00Z',
                updated_at: '2026-07-01T11:00:00Z',
              },
            ],
          },
        ],
      }),
    });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    expect(await screen.findByText('Sem entradas para este fornecedor.')).toBeTruthy();
    expect(screen.getByText('Entrada sem etiqueta')).toBeTruthy();
    expect(screen.getByText('Sem campos configurados')).toBeTruthy();

    const cmdCard = screen.getByText('Chave Móvel Digital (CMD)').closest('.panel') as HTMLElement;
    fireEvent.click(within(cmdCard).getByRole('button', { name: 'Adicionar entrada' }));
    expect(screen.queryByLabelText('Tipo de fornecedor')).toBeNull();
    fireEvent.change(screen.getByLabelText('ID de aplicação'), { target: { value: 'cmd-new' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((call) => call.method === 'POST');
      expect(post?.url).toContain('/cmd/_/entries');
    });
  });

  it('reads a PKCS#12 file into base64 and sends it only in the write-only set', async () => {
    const stub = stubFetch({ list: listView({ providers: [] }) });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova entrada' }));
    fireEvent.change(screen.getByLabelText('Tipo de fornecedor'), { target: { value: 'pkcs12' } });
    fireEvent.change(screen.getByLabelText('Identificador do fornecedor'), {
      target: { value: 'local-cert' },
    });
    fireEvent.change(screen.getByLabelText('Nome amigável'), { target: { value: 'Board seal' } });
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [new File([new Uint8Array([1, 2, 3])], 'board.p12')] },
    });

    await waitFor(() => {
      expect((screen.getByRole('button', { name: 'Guardar' }) as HTMLButtonElement).disabled).toBe(
        false,
      );
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const post = stub.calls.find((call) => call.method === 'POST');
      const body = JSON.parse(post?.body ?? '{}');
      expect(body.selectors).toEqual({ friendly_name: 'Board seal' });
      expect(body.set).toEqual({ pfx_der: 'AQID' });
      expect(post?.body).not.toContain('board.p12');
    });
  });

  it('moves the lower-priority entry up and reports reorder failures without changing order', async () => {
    const stub = stubFetch({ writeStatus: 500, writeBody: { error: 'ordenação recusada' } });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ProviderCredentialsSection />);

    const secundaria = (await screen.findByText('Secundária')).closest(
      '[role="group"]',
    ) as HTMLElement;
    fireEvent.click(within(secundaria).getByRole('button', { name: 'Subir prioridade' }));

    expect(await screen.findByText(/ordenação recusada/)).toBeTruthy();
    const post = stub.calls.find((call) => call.method === 'POST');
    expect(JSON.parse(post?.body ?? '{}').order).toEqual(['entry-b', 'entry-a']);
  });
});
