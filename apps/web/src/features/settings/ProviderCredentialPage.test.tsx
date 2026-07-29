import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { ProviderCredentialPage } from './ProviderCredentialPage';
import type { ProviderCredentialProbeResponse, ProviderCredentialsListView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { hasUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { providerCredentialsPtPT as copy } from '../../i18n/providerCredentialsFallback';

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
          entry_id: 'entry-a',
          label: 'Primária',
          priority: 0,
          enabled: true,
          endpoint: 'https://qtsp.example/csc',
          selectors: { authorization: 'service' },
          fields: [
            { field_name: 'client_id', configured: true },
            { field_name: 'client_secret', configured: true },
          ],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
      ],
    },
  ],
};

function entryView(
  mode: 'csc' | 'pkcs12',
  providerId: string,
  entryId: string,
): ProviderCredentialsListView {
  return {
    ...list,
    providers: [
      {
        mode,
        provider_id: providerId,
        entries: [
          {
            entry_id: entryId,
            label: 'Chave local',
            priority: 0,
            enabled: true,
            selectors: {},
            fields:
              mode === 'pkcs12'
                ? [
                    { field_name: 'pfx_der', configured: true },
                    { field_name: 'passphrase', configured: true },
                  ]
                : [{ field_name: 'client_secret', configured: true }],
            created_at: '2026-07-01T10:00:00Z',
            updated_at: '2026-07-01T10:00:00Z',
          },
        ],
      },
    ],
  };
}

/** A stored CMD entry — the only mode with an end-to-end test to reach from this page (t82). */
const cmdEntryView: ProviderCredentialsListView = {
  ...list,
  providers: [
    {
      mode: 'cmd',
      provider_id: '',
      entries: [
        {
          entry_id: 'cmd-entry-1',
          label: 'CMD principal',
          priority: 0,
          enabled: true,
          selectors: { env: 'prod' },
          fields: [{ field_name: 'application_id', configured: true }],
          created_at: '2026-07-01T10:00:00Z',
          updated_at: '2026-07-01T10:00:00Z',
        },
      ],
    },
  ],
};

const probe: ProviderCredentialProbeResponse = {
  mode: 'csc',
  provider_id: 'encosto qtsp',
  entry_id: 'entry-a',
  status: 'ok',
  provider_contacted: true,
  private_key_operation_performed: false,
  signer_authorization_requested: false,
  document_signed: false,
  legal_validity_claimed: false,
  qualified_status_determined: false,
  checks: [
    {
      name: 'credentials_info',
      status: 'passed',
      detail: 'CSC returned a parseable signing certificate.',
    },
  ],
  tested_at: '2026-07-25T10:00:00Z',
  duration_ms: 37,
};

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(
  options: {
    view?: ProviderCredentialsListView;
    writeStatus?: number;
    writeBody?: unknown;
    hangWrite?: boolean;
  } = {},
) {
  const {
    view = list,
    writeStatus = 200,
    writeBody = { mode: 'csc', provider_id: 'encosto qtsp', deleted: false },
    hangWrite = false,
  } = options;
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (method !== 'GET' && !url.endsWith('/probe') && hangWrite)
      return new Promise<Response>(() => {});
    const body = method === 'GET' ? view : url.endsWith('/probe') ? probe : writeBody;
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status:
          method === 'POST' && !url.endsWith('/probe')
            ? writeStatus === 200
              ? 201
              : writeStatus
            : method === 'PATCH'
              ? writeStatus
              : 200,
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

function renderPage(path: string, child: ReactNode = <ProviderCredentialPage />) {
  return renderWithProviders(
    <Routes>
      <Route path="/admin/signing/providers/new" element={child} />
      <Route path="/admin/signing/providers/:mode/:providerId/:entryId/edit" element={child} />
      <Route path="/admin/signing/providers" element={<LocationProbe />} />
    </Routes>,
    [path],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ProviderCredentialPage', () => {
  it('creates on a dedicated mode-prefilled page and returns to the provider list', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/new?mode=cmd');

    const mode = (await screen.findByLabelText('Tipo de fornecedor')) as HTMLSelectElement;
    expect(mode.value).toBe('cmd');
    fireEvent.change(screen.getByLabelText('ID de aplicação'), {
      target: { value: 'cmd-app-id' },
    });
    await waitFor(() => expect(hasUnsavedChanges()).toBe(true));
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const create = stub.calls.find(
        (call) => call.method === 'POST' && call.url.endsWith('/cmd/_/entries'),
      );
      expect(JSON.parse(create?.body ?? '{}')).toEqual({
        enabled: true,
        selectors: {},
        set: { application_id: 'cmd-app-id' },
      });
      expect(screen.getByTestId('location').textContent).toBe('/admin/signing/providers');
    });
  });

  it('resets incompatible fields when switching modes and submits the exact CMD body', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/new');

    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: 'discarded-provider' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), {
      target: { value: 'discarded-secret' },
    });
    fireEvent.change(screen.getByLabelText('Tipo de fornecedor'), { target: { value: 'cmd' } });

    expect(screen.queryByLabelText('Identificador do fornecedor')).toBeNull();
    fireEvent.change(screen.getByLabelText('Ambiente'), { target: { value: 'prod' } });
    fireEvent.change(screen.getByLabelText('ID de aplicação'), { target: { value: 'cmd-app' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const create = stub.calls.find((call) => call.method === 'POST');
      expect(create?.url).toContain('/provider-credentials/cmd/_/entries');
      expect(JSON.parse(create?.body ?? '{}')).toEqual({
        enabled: true,
        selectors: { env: 'prod' },
        set: { application_id: 'cmd-app' },
      });
      expect(create?.body).not.toContain('discarded');
    });
  });

  it('creates CSC and SCAP entries with trimmed metadata and write-only provider secrets', async () => {
    const csc = stubFetch();
    vi.stubGlobal('fetch', csc.fn);
    const first = renderPage('/admin/signing/providers/new?mode=csc');

    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: '  csc secondary  ' },
    });
    fireEvent.change(screen.getByLabelText('Etiqueta'), { target: { value: '  Backup  ' } });
    fireEvent.change(screen.getByLabelText('Endereço (base_url)'), {
      target: { value: '  https://csc.example.test/api  ' },
    });
    fireEvent.change(screen.getByLabelText('Autorização'), { target: { value: 'user' } });
    fireEvent.change(screen.getByLabelText('ID da credencial'), { target: { value: 'cred-7' } });
    // `sandbox` is the only `kind: 'toggle'` selector, so this click is what proves a toggle reaches
    // `selectors` at all — the guarantee this case holds, alongside the trimming and write-only
    // assertions. A new entry starts NOT sandboxed (`newEntryOn: false`), so the click turns it ON:
    // opting IN to the relaxed HTTPS rule, which is the direction that should take a deliberate act.
    fireEvent.click(screen.getByRole('switch', { name: 'Ambiente de testes (sandbox)' }));
    fireEvent.change(screen.getByLabelText('Token de acesso'), { target: { value: 'token-7' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const create = csc.calls.find((call) => call.method === 'POST');
      expect(create?.url).toContain('/provider-credentials/csc/csc%20secondary/entries');
      expect(JSON.parse(create?.body ?? '{}')).toEqual({
        label: 'Backup',
        enabled: true,
        endpoint: 'https://csc.example.test/api',
        selectors: { authorization: 'user', credential_id: 'cred-7', sandbox: 'true' },
        set: { access_token: 'token-7' },
      });
    });
    first.unmount();

    const scap = stubFetch();
    vi.stubGlobal('fetch', scap.fn);
    renderPage('/admin/signing/providers/new?mode=scap');
    fireEvent.change(await screen.findByLabelText('Ambiente'), { target: { value: 'preprod' } });
    fireEvent.change(screen.getByLabelText('ID de aplicação'), { target: { value: 'scap-app' } });
    fireEvent.change(screen.getByLabelText('Segredo'), { target: { value: 'scap-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const create = scap.calls.find((call) => call.method === 'POST');
      expect(create?.url).toContain('/provider-credentials/scap/_/entries');
      expect(JSON.parse(create?.body ?? '{}')).toMatchObject({
        selectors: { environment: 'preprod' },
        set: { application_id: 'scap-app', secret: 'scap-secret' },
      });
    });
  });

  // The successor to the case that pinned the opposite guarantee ("still omits the sandbox
  // selector…"). Omission is precisely what made a new entry sandboxed without anyone choosing it:
  // the server reads `selector_bool(entry, "sandbox", true)`, so a missing key means ON, and ON
  // relaxes `CscConfig::validate` to accept `http://localhost` in place of required HTTPS. An
  // untouched create form must therefore SEND the key, not leave it to the server's default. If
  // this ever stops finding `sandbox: 'false'` in the body, silent sandboxing is back.
  it('writes sandbox off explicitly when the operator never touches the toggle', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/new?mode=csc');

    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: 'untouched-provider' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), { target: { value: 'secret-1' } });
    // The control shows what will actually be applied, and it is off.
    expect(
      (screen.getByRole('switch', { name: 'Ambiente de testes (sandbox)' }) as HTMLInputElement)
        .checked,
    ).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const create = stub.calls.find((call) => call.method === 'POST');
      expect(create).toBeTruthy();
      const selectors = JSON.parse(create?.body ?? '{}').selectors as Record<string, string>;
      expect(selectors).toEqual({ sandbox: 'false' });
    });
  });

  // Seeding a create-time value must not leak into an edit. `update_entry` swaps the whole selector
  // map for what the form sends, so a form that invented `sandbox` here would rewrite the stored
  // posture of every legacy entry on any unrelated save — a label change flipping HTTPS
  // enforcement. Absent stays absent, and the server keeps applying exactly the default it applies
  // today; the toggle still shows that default honestly (checked) via `defaultOn`.
  it('leaves an existing entry without a sandbox selector untouched on edit', async () => {
    const stub = stubFetch({ view: entryView('csc', 'legacy-provider', 'legacy-entry') });
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/csc/legacy-provider/legacy-entry/edit');

    await waitFor(() =>
      expect(
        (screen.getByRole('switch', { name: 'Ambiente de testes (sandbox)' }) as HTMLInputElement)
          .checked,
      ).toBe(true),
    );
    fireEvent.change(screen.getByLabelText('Etiqueta'), { target: { value: 'Renomeada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const patch = stub.calls.find((call) => call.method === 'PATCH');
      expect(patch).toBeTruthy();
      const selectors = JSON.parse(patch?.body ?? '{}').selectors as Record<string, string>;
      expect(selectors).not.toHaveProperty('sandbox');
      expect(selectors).toEqual({});
    });
  });

  it('keeps the form pending during a save and preserves inputs when the save fails', async () => {
    const pending = stubFetch({ hangWrite: true });
    vi.stubGlobal('fetch', pending.fn);
    const first = renderPage('/admin/signing/providers/new?mode=csc');
    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: 'pending-provider' },
    });
    fireEvent.change(screen.getByLabelText('Client secret'), {
      target: { value: 'pending-secret' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));
    await waitFor(() => {
      const button = screen.getByRole('button', { name: 'A guardar…' }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
    });
    first.unmount();

    const failed = stubFetch({
      writeStatus: 409,
      writeBody: { error: 'não há nenhuma fonte de chave disponível' },
    });
    vi.stubGlobal('fetch', failed.fn);
    renderPage('/admin/signing/providers/new?mode=csc');
    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: 'failed-provider' },
    });
    const secret = screen.getByLabelText('Client secret') as HTMLInputElement;
    fireEvent.change(secret, { target: { value: 'still-local' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    expect(
      (await screen.findAllByText(/não há nenhuma fonte de chave disponível/)).length,
    ).toBeGreaterThan(0);
    expect(secret.value).toBe('still-local');
  });

  it('edits metadata with write-only fields blank and never sends an unchanged secret', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/csc/encosto%20qtsp/entry-a/edit');

    const label = (await screen.findByLabelText('Etiqueta')) as HTMLInputElement;
    expect(label.value).toBe('Primária');
    expect((screen.getByLabelText('Client secret') as HTMLInputElement).value).toBe('');
    fireEvent.change(label, { target: { value: 'Primária revista' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const update = stub.calls.find((call) => call.method === 'PATCH');
      const body = JSON.parse(update?.body ?? '{}');
      expect(body.label).toBe('Primária revista');
      expect(body).not.toHaveProperty('set');
      expect(update?.url).toContain('/entries/entry-a');
    });
  });

  it('cancels an untouched edit without issuing a write', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/csc/encosto%20qtsp/entry-a/edit');

    fireEvent.click(await screen.findByRole('button', { name: 'Cancelar' }));
    expect(screen.getByTestId('location').textContent).toBe('/admin/signing/providers');
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
  });

  it('keeps an uploaded PKCS#12 blob write-only and out of the route', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/new?mode=pkcs12');

    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: 'local cert' },
    });
    fireEvent.change(screen.getByLabelText('Nome amigável'), {
      target: { value: 'Board seal' },
    });
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [new File([new Uint8Array([1, 2, 3])], 'board.p12')] },
    });
    await waitFor(() =>
      expect((screen.getByRole('button', { name: 'Guardar' }) as HTMLButtonElement).disabled).toBe(
        false,
      ),
    );
    fireEvent.change(screen.getByLabelText('Frase-passe'), {
      target: { value: 'write-only-passphrase' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const create = stub.calls.find(
        (call) => call.method === 'POST' && call.url.endsWith('/pkcs12/local%20cert/entries'),
      );
      expect(JSON.parse(create?.body ?? '{}')).toMatchObject({
        selectors: { friendly_name: 'Board seal' },
        set: { pfx_der: 'AQID', passphrase: 'write-only-passphrase' },
      });
      expect(create?.url).not.toContain('write-only-passphrase');
      expect(create?.url).not.toContain('AQID');
      expect(create?.body).not.toContain('board.p12');
    });
  });

  it('reports a PKCS#12 file-read failure without issuing a write', async () => {
    class FailingFileReader {
      error = new Error('ficheiro ilegível');
      result: string | ArrayBuffer | null = null;
      onerror: null | (() => void) = null;
      onload: null | (() => void) = null;
      readAsDataURL() {
        this.onerror?.();
      }
    }
    vi.stubGlobal('FileReader', FailingFileReader);
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/new?mode=pkcs12');
    fireEvent.change(await screen.findByLabelText('Identificador do fornecedor'), {
      target: { value: 'local-cert' },
    });
    fireEvent.change(screen.getByLabelText('Ficheiro PKCS#12/PFX'), {
      target: { files: [new File([new Uint8Array([1])], 'broken.p12')] },
    });

    expect(await screen.findByText(/ficheiro ilegível/)).toBeTruthy();
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
    expect((screen.getByRole('button', { name: 'Guardar' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it('tests the saved exact entry and renders the full structured honesty result', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage('/admin/signing/providers/csc/encosto%20qtsp/entry-a/edit');

    fireEvent.click(await screen.findByRole('button', { name: 'Testar' }));
    expect(await screen.findByRole('heading', { name: 'Resultado do teste' })).toBeTruthy();
    expect(screen.getByText('Fornecedor contactado').nextElementSibling?.textContent).toBe('Sim');
    expect(screen.getByText('Documento assinado').nextElementSibling?.textContent).toBe('Não');
    expect(screen.getByText('Validade jurídica alegada').nextElementSibling?.textContent).toBe(
      'Não',
    );
    expect(
      screen.getByText('Estatuto qualificado determinado').nextElementSibling?.textContent,
    ).toBe('Não');
    expect(screen.getByText(/não determina o estatuto qualificado/i)).toBeTruthy();
    expect(
      stub.calls.some(
        (call) =>
          call.method === 'POST' && call.url.endsWith('/csc/encosto%20qtsp/entries/entry-a/probe'),
      ),
    ).toBe(true);
  });

  it('requires signing.perform and explicit confirmation before a PKCS#12 key operation', async () => {
    const denied = stubFetch({ view: entryView('pkcs12', 'local', 'entry-p12') });
    vi.stubGlobal('fetch', denied.fn);
    const first = renderPage(
      '/admin/signing/providers/pkcs12/local/entry-p12/edit',
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'signing.configure')}
      >
        <ProviderCredentialPage />
      </StaticPermissionsProvider>,
    );
    const blocked = (await screen.findByRole('button', { name: 'Testar' })) as HTMLButtonElement;
    expect(blocked.disabled).toBe(true);
    expect(blocked.title).toContain('signing.perform');
    fireEvent.click(blocked);
    expect(denied.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
    first.unmount();

    const allowed = stubFetch({ view: entryView('pkcs12', 'local', 'entry-p12') });
    vi.stubGlobal('fetch', allowed.fn);
    renderPage('/admin/signing/providers/pkcs12/local/entry-p12/edit');

    fireEvent.click(await screen.findByRole('button', { name: 'Testar' }));
    const dialog = await screen.findByRole('dialog');
    expect(allowed.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancelar' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(allowed.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);

    fireEvent.click(screen.getByRole('button', { name: 'Testar' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Executar operação de chave' }));
    await waitFor(() => {
      const request = allowed.calls.find(
        (call) => call.method === 'POST' && call.url.endsWith('/probe'),
      );
      expect(JSON.parse(request?.body ?? '{}')).toEqual({
        confirm_private_key_operation: true,
      });
      expect(screen.queryByRole('dialog')).toBeNull();
    });
  });

  it('fails closed on a direct route without signing.configure and performs no read', () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderPage(
      '/admin/signing/providers/new',
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <ProviderCredentialPage />
      </StaticPermissionsProvider>,
    );

    expect(screen.getByText('Sem permissão')).toBeTruthy();
    expect(stub.calls).toHaveLength(0);
  });

  /**
   * The route from the safe probe to the real end-to-end test (t82).
   *
   * An operator who probes a CMD credential on this page reads `live_provider_operation` as NOT
   * RUN, with a correct explanation of why no live CMD operation is safe. Until now that was the
   * last word on the page: the end-to-end control existed only in the credential list's table row,
   * so the product looked like it could not test CMD at all. The real test therefore lives on this
   * page too — and only for CMD, since no other provider has this two-phase flow.
   */
  it('offers the end-to-end CMD test on the same page as the probe that refuses to run one', async () => {
    vi.stubGlobal('fetch', stubFetch({ view: cmdEntryView }).fn);
    // `_` is the empty-provider sentinel `providerCredentialEditPath` mints; CMD has no provider id.
    renderPage('/admin/signing/providers/cmd/_/cmd-entry-1/edit');

    expect(
      await screen.findByRole('button', {
        name: copy['providerCredentials.cmdTest.button'],
      }),
    ).toBeTruthy();
    // The section names the connection to the probe rather than sitting there unexplained.
    expect(screen.getByText(copy['providerCredentials.cmdTest.sectionIntro'])).toBeTruthy();
    expect(screen.getByText(copy['providerCredentials.cmdTest.sectionWhatItDoes'])).toBeTruthy();
  });

  it('does not offer the end-to-end CMD test on a non-CMD credential page', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderPage('/admin/signing/providers/csc/encosto%20qtsp/entry-a/edit');

    expect(await screen.findByRole('button', { name: 'Testar' })).toBeTruthy();
    expect(
      screen.queryByRole('button', { name: copy['providerCredentials.cmdTest.button'] }),
    ).toBeNull();
  });
});
