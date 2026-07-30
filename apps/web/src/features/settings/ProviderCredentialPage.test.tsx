import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { ProviderCredentialPage } from './ProviderCredentialPage';
import type {
  AmaCertificateInspectResponse,
  ProviderCredentialProbeResponse,
  ProviderCredentialsListView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { hasUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';
import { providerCredentialsPtPT as copy } from '../../i18n/providerCredentialsFallback';
import { ptPT } from '../../i18n/locales/pt-PT';

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

/**
 * What the server says about a candidate AMA certificate: it parses, it carries an RSA key, it is
 * in date — and, as values, the four things nobody checked. Mirrors the real DTO, including the
 * `detail_code` that keeps the sentences out of an English-prose channel.
 */
const amaCertInspection: AmaCertificateInspectResponse = {
  parsed: true,
  input_kind: 'certificate',
  rsa_public_key: true,
  key_bits: 2048,
  within_validity: true,
  public_key_sha256_fingerprint: '1a7b3c5d9e0f24681357bd02468ace13579bdf02468ace13579bdf02468ace13',
  certificate_sha256_fingerprint:
    '9f2c4a6e0b1d83577e4c1a90de2f6b3418c705d9a2e64bf07c31d85a49e0b2c6',
  subject: 'CN=CMD Field Encryption,O=AMA,C=PT',
  issuer: 'CN=CMD Field Encryption,O=AMA,C=PT',
  not_before: '2026-07-06T18:43:30Z',
  not_after: '2036-07-03T18:43:30Z',
  chain_validated: false,
  trusted_list_checked: false,
  issuer_authenticated: false,
  legal_validity_claimed: false,
  checks: [
    {
      name: 'certificate_parsed',
      status: 'passed',
      detail: 'The text parses as an X.509 certificate.',
      detail_code: 'ama_cert_parsed',
    },
    {
      name: 'rsa_public_key',
      status: 'passed',
      detail: 'This input carries an RSA public key of 2048 bits.',
      detail_code: 'ama_cert_rsa_key_present',
      detail_params: { bits: '2048' },
    },
    {
      name: 'validity_window',
      status: 'passed',
      detail: "The current server time falls inside the certificate's validity window.",
      detail_code: 'ama_cert_within_validity',
    },
    {
      name: 'trust_established',
      status: 'skipped',
      detail: "Whether this key is genuinely AMA's was not determined.",
      detail_code: 'ama_cert_trust_not_established',
    },
  ],
};

/**
 * The same key, supplied as a bare `PUBLIC KEY` block.
 *
 * The public-key fingerprint is deliberately the SAME value as above — that is the property that
 * makes it the one an operator can compare — while the certificate fingerprint, the subject, the
 * issuer and the dates are simply not there. The `certificate_fields` finding is what turns those
 * absences into a statement instead of four empty rows.
 */
const amaPublicKeyInspection: AmaCertificateInspectResponse = {
  parsed: true,
  input_kind: 'public_key',
  rsa_public_key: true,
  key_bits: 2048,
  public_key_sha256_fingerprint: amaCertInspection.public_key_sha256_fingerprint,
  chain_validated: false,
  trusted_list_checked: false,
  issuer_authenticated: false,
  legal_validity_claimed: false,
  checks: [
    {
      name: 'public_key_parsed',
      status: 'passed',
      detail: 'The text parses as a bare public key (a SubjectPublicKeyInfo).',
      detail_code: 'ama_key_public_key_parsed',
    },
    {
      name: 'rsa_public_key',
      status: 'passed',
      detail: 'This input carries an RSA public key of 2048 bits.',
      detail_code: 'ama_cert_rsa_key_present',
      detail_params: { bits: '2048' },
    },
    {
      name: 'certificate_fields',
      status: 'skipped',
      detail: 'This input is a public key on its own, so it has no subject, issuer or validity.',
      detail_code: 'ama_key_certificate_fields_absent',
    },
    {
      name: 'trust_established',
      status: 'skipped',
      detail: "Whether this key is genuinely AMA's was not determined.",
      detail_code: 'ama_cert_trust_not_established',
    },
  ],
};

const INSPECT_PATH = '/provider-credentials/cmd/ama-certificate/inspect';

function stubFetch(
  options: {
    view?: ProviderCredentialsListView;
    writeStatus?: number;
    writeBody?: unknown;
    hangWrite?: boolean;
    inspectBody?: AmaCertificateInspectResponse;
  } = {},
) {
  const {
    view = list,
    writeStatus = 200,
    writeBody = { mode: 'csc', provider_id: 'encosto qtsp', deleted: false },
    hangWrite = false,
    inspectBody = amaCertInspection,
  } = options;
  const calls: Call[] = [];
  const fn = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.endsWith(INSPECT_PATH)) {
      return Promise.resolve(
        new Response(JSON.stringify(inspectBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
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
      // `env` is written explicitly, and written as `preprod`. It is the only place the CMD
      // environment can be expressed now that the settings card carries no default, so a new entry
      // must not leave the server to infer one — and must not start in production.
      expect(JSON.parse(create?.body ?? '{}')).toEqual({
        enabled: true,
        selectors: { env: 'preprod' },
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
    // Progress and the log moved into a dialog (t112); the honest legal-status grid is unchanged
    // and is asserted inside it.
    expect(await screen.findByTestId('provider-probe-modal')).toBeTruthy();
    expect(await screen.findByTestId('provider-probe-result')).toBeTruthy();
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
    });
    // The key-operation gate is gone and the progress dialog has replaced it — never both at once,
    // and the gate is never re-offered from inside the result (a re-run is a real key operation).
    const progress = await screen.findByTestId('provider-probe-modal');
    expect(
      within(progress).queryByRole('button', { name: 'Executar operação de chave' }),
    ).toBeNull();
    expect(within(progress).queryByRole('button', { name: 'Executar de novo' })).toBeNull();
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

    expect(await screen.findByTestId('cmd-test-signature-open')).toBeTruthy();
    // The section names the connection to the probe rather than sitting there unexplained.
    expect(screen.getByText(copy['providerCredentials.cmdTest.sectionIntro'])).toBeTruthy();
    expect(screen.getByText(copy['providerCredentials.cmdTest.sectionWhatItDoes'])).toBeTruthy();
  });

  /**
   * The one control on this surface that is deliberately NOT icon-only.
   *
   * Alone under its heading, and a completed run costs a real qualified electronic signature — so
   * the consequence has to be legible from the button itself, not only from the paragraph above
   * it. The assertions are on the accessible name (read out of the catalog, never a pasted
   * sentence) and on the rendered structure, so they survive a re-translation.
   */
  it('labels the end-to-end test rather than leaving the gravest action as a bare glyph', async () => {
    vi.stubGlobal('fetch', stubFetch({ view: cmdEntryView }).fn);
    renderPage('/admin/signing/providers/cmd/_/cmd-entry-1/edit');

    const button = await screen.findByTestId('cmd-test-signature-open');
    const label = ptPT['settings.providerCredentials.cmdTest.runEndToEnd'];
    // The label is VISIBLE text, not only an `aria-label`: an icon-only control would carry the
    // name without rendering it.
    expect(button.textContent).toContain(label);
    expect(button.getAttribute('aria-label')).toBeNull();
    expect(button.className).not.toContain('btn--iconOnly');
    // The glyph stays alongside it, which is this app's primary-button idiom.
    expect(button.querySelector('.btn__icon')).toBeTruthy();
    expect(screen.getByRole('button', { name: label })).toBe(button);
  });

  it('does not offer the end-to-end CMD test on a non-CMD credential page', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderPage('/admin/signing/providers/csc/encosto%20qtsp/entry-a/edit');

    expect(await screen.findByRole('button', { name: 'Testar' })).toBeTruthy();
    expect(screen.queryByTestId('cmd-test-signature-open')).toBeNull();
  });

  /**
   * The AMA field-encryption certificate field (t112): load from a file, paste from the clipboard,
   * and ask the server what it could establish.
   *
   * Assertions are on structure, stable test ids and CODES — never on translated prose, except
   * where the point of the assertion is that a specific catalog string is what reached the screen.
   */
  describe('the AMA certificate field', () => {
    const PEM = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
    /** The other armour this field accepts: the key on its own, with no certificate around it. */
    const PUBLIC_KEY_PEM = '-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n';

    /** A `File` whose `text()` and `size` are controlled, without needing a real Blob polyfill. */
    function certFile(name: string, text: string, size = text.length): File {
      return {
        name,
        size,
        text: () => Promise.resolve(text),
      } as unknown as File;
    }

    function stubClipboard(readText: () => Promise<string>) {
      vi.stubGlobal('navigator', { ...navigator, clipboard: { readText } });
    }

    async function openCmdCreatePage() {
      const stub = stubFetch();
      vi.stubGlobal('fetch', stub.fn);
      renderPage('/admin/signing/providers/new?mode=cmd');
      const field = (await screen.findByLabelText(
        ptPT['settings.providerCredentials.field.amaCertPem'],
      )) as HTMLTextAreaElement;
      return { stub, field };
    }

    it('reads a chosen file as TEXT into the field, never a path', async () => {
      const { field } = await openCmdCreatePage();
      const input = screen.getByTestId('ama-cert-file-input') as HTMLInputElement;

      Object.defineProperty(input, 'files', { value: [certFile('ama.pem', PEM)] });
      fireEvent.change(input);

      await waitFor(() => expect(field.value).toBe(PEM));
      // The FILENAME is feedback; the field holds the certificate's content. A path in the field
      // would be the `CHANCELA_CMD_AMA_CERT_PEM` confusion this control exists to avoid.
      expect(screen.getByText(/ama\.pem/)).toBeTruthy();
      expect(field.value).not.toContain('ama.pem');
    });

    it('refuses an implausibly large file without reading it, and says so', async () => {
      const { field } = await openCmdCreatePage();
      const input = screen.getByTestId('ama-cert-file-input') as HTMLInputElement;
      let read = false;
      const huge = {
        name: 'huge.pem',
        size: 64 * 1024 + 1,
        text: () => {
          read = true;
          return Promise.resolve('x');
        },
      } as unknown as File;

      Object.defineProperty(input, 'files', { value: [huge] });
      fireEvent.change(input);

      await screen.findByRole('alert');
      // The whole point of bounding by `size`: the bytes are never pulled into memory.
      expect(read).toBe(false);
      expect(field.value).toBe('');
    });

    it('pastes from the clipboard', async () => {
      stubClipboard(() => Promise.resolve(PEM));
      const { field } = await openCmdCreatePage();

      fireEvent.click(screen.getByTestId('ama-cert-from-clipboard'));

      await waitFor(() => expect(field.value).toBe(PEM));
    });

    it.each([
      ['unavailable', undefined],
      ['denied', () => Promise.reject(new Error('denied'))],
      ['empty', () => Promise.resolve('   ')],
    ] as const)(
      'shows a clipboard %s failure instead of doing nothing silently',
      async (_label, readText) => {
        vi.stubGlobal('navigator', {
          ...navigator,
          clipboard: readText ? { readText } : undefined,
        });
        const { field } = await openCmdCreatePage();

        fireEvent.click(screen.getByTestId('ama-cert-from-clipboard'));

        // Visible and assertive, per the rule `DiagnosticsSection.copyReport` set for the write
        // direction: an operator who gets nothing must be told to paste by hand.
        const alert = await screen.findByRole('alert');
        expect(alert.textContent?.trim()).toBeTruthy();
        expect(field.value).toBe('');
      },
    );

    it('refuses to inspect an empty field and sends no request', async () => {
      const { stub } = await openCmdCreatePage();

      fireEvent.click(screen.getByTestId('ama-cert-inspect'));

      await screen.findByRole('alert');
      expect(stub.calls.some((call) => call.url.endsWith(INSPECT_PATH))).toBe(false);
    });

    it('inspects through the server and states what was NOT checked as explicit values', async () => {
      const { stub, field } = await openCmdCreatePage();
      fireEvent.change(field, { target: { value: PEM } });
      fireEvent.click(screen.getByTestId('ama-cert-inspect'));

      const panel = await screen.findByTestId('ama-cert-inspect-result');
      const request = await waitFor(() => {
        const call = stub.calls.find((c) => c.url.endsWith(INSPECT_PATH));
        expect(call).toBeTruthy();
        return call!;
      });
      // The candidate travels as content, and only the content — trimmed, so trailing whitespace
      // from a paste is not what the parser is asked to judge.
      expect(JSON.parse(request.body ?? '{}')).toEqual({ pem: PEM.trim() });

      // Findings render TRANSLATED through the shared code→key resolver, not as server English.
      expect(
        within(panel).getByText(ptPT['settings.providerCredentials.probe.detail.ama_cert_parsed']),
      ).toBeTruthy();
      expect(panel.textContent).not.toContain('The text parses as an X.509 certificate.');
      // The RSA finding keeps its machine parameter verbatim.
      expect(panel.querySelector('[data-check="rsa_public_key"]')?.textContent).toContain('2048');

      // The four negatives are shown as values. Four "Não" rows, not an omitted disclaimer.
      for (const key of [
        'settings.providerCredentials.field.amaCertPem.inspect.chainValidated',
        'settings.providerCredentials.field.amaCertPem.inspect.trustedListChecked',
        'settings.providerCredentials.field.amaCertPem.inspect.issuerAuthenticated',
        'settings.providerCredentials.field.amaCertPem.inspect.legalValidityClaimed',
      ] as const) {
        expect(within(panel).getByText(ptPT[key]).nextElementSibling?.textContent).toBe(
          copy['providerCredentials.probe.no'],
        );
      }

      // And nowhere does the panel pronounce the certificate valid or trusted. `Válido a partir
      // de` / `Válido até` are date LABELS, so the guard looks for the verdict words only.
      expect(panel.textContent).not.toMatch(/\bcertificado v[áa]lido\b/i);
      expect(panel.textContent).not.toMatch(/\bconfi[áa]vel\b/i);
    });

    /**
     * The fingerprints are the only checkable things on the panel, and they must not read as a
     * verdict — nor as each other.
     *
     * Subject, issuer and dates all come out of the candidate itself and would look identical on a
     * substituted certificate. The two SHA-256 values are what an operator can hold against what AMA
     * published, and they are different numbers over different bytes: the public-key one covers the
     * key, the certificate one covers the whole certificate. Both are shown verbatim, each under a
     * label that says which, and the sentence beside them says who has to do the comparing —
     * because the server did not.
     */
    it('shows both fingerprints, each labelled, and leaves the comparison to the operator', async () => {
      const { field } = await openCmdCreatePage();
      fireEvent.change(field, { target: { value: PEM } });
      fireEvent.click(screen.getByTestId('ama-cert-inspect'));

      const panel = await screen.findByTestId('ama-cert-inspect-result');
      expect(within(panel).getByTestId('ama-cert-public-key-fingerprint').textContent).toBe(
        amaCertInspection.public_key_sha256_fingerprint,
      );
      expect(within(panel).getByTestId('ama-cert-certificate-fingerprint').textContent).toBe(
        amaCertInspection.certificate_sha256_fingerprint,
      );
      // Distinct values under distinct labels: showing one of them unlabelled would send an
      // operator comparing the wrong number against what AMA published.
      expect(amaCertInspection.public_key_sha256_fingerprint).not.toBe(
        amaCertInspection.certificate_sha256_fingerprint,
      );
      for (const key of [
        'settings.providerCredentials.field.amaCertPem.inspect.publicKeyFingerprint',
        'settings.providerCredentials.field.amaCertPem.inspect.certificateFingerprint',
        'settings.providerCredentials.field.amaCertPem.inspect.fingerprintHint',
      ] as const) {
        expect(within(panel).getByText(ptPT[key])).toBeTruthy();
      }
    });

    /**
     * A bare public key: the same key, and four facts that are absent rather than unreadable.
     *
     * The panel must not render an empty subject/issuer/validity grid here. Blank rows on what an
     * operator believes is a certificate read as a damaged file, which is a different fault with a
     * different remedy — so the grid is gone and a translated finding says why.
     */
    it('reports a bare public key as such, with no empty certificate rows', async () => {
      const stub = stubFetch({ inspectBody: amaPublicKeyInspection });
      vi.stubGlobal('fetch', stub.fn);
      renderPage('/admin/signing/providers/new?mode=cmd');
      const field = (await screen.findByLabelText(
        ptPT['settings.providerCredentials.field.amaCertPem'],
      )) as HTMLTextAreaElement;
      fireEvent.change(field, { target: { value: PUBLIC_KEY_PEM } });
      fireEvent.click(screen.getByTestId('ama-cert-inspect'));

      const panel = await screen.findByTestId('ama-cert-inspect-result');
      // Which artefact arrived is stated, in the operator's language.
      expect(within(panel).getByTestId('ama-cert-input-kind').textContent).toBe(
        ptPT['settings.providerCredentials.field.amaCertPem.inspect.inputKind.publicKey'],
      );
      // The absence is a sentence, not four blanks.
      expect(
        within(panel).getByText(
          ptPT['settings.providerCredentials.probe.detail.ama_key_certificate_fields_absent'],
        ),
      ).toBeTruthy();
      for (const key of [
        'settings.providerCredentials.field.amaCertPem.inspect.subject',
        'settings.providerCredentials.field.amaCertPem.inspect.issuer',
        'settings.providerCredentials.field.amaCertPem.inspect.notBefore',
        'settings.providerCredentials.field.amaCertPem.inspect.notAfter',
      ] as const) {
        expect(within(panel).queryByText(ptPT[key])).toBeNull();
      }
      // The key fingerprint is still there — it is the value that survives the change of artefact —
      // and the certificate one is not, because there is no certificate to fingerprint.
      expect(within(panel).getByTestId('ama-cert-public-key-fingerprint').textContent).toBe(
        amaCertInspection.public_key_sha256_fingerprint,
      );
      expect(within(panel).queryByTestId('ama-cert-certificate-fingerprint')).toBeNull();
    });

    /**
     * A refusal must name the defect, in the operator's language, not read as "invalid".
     *
     * The server normalises first and only then refuses, so anything that reaches this path is a
     * real difference that would have changed the decoded certificate. Each one carries its own
     * code; this proves the client has a translated sentence for them rather than falling back to
     * the server's English.
     */
    it.each([
      ['ama_cert_wrong_pem_label', { label: 'PRIVATE KEY' }],
      ['ama_cert_multiple_blocks', { count: '2' }],
      ['ama_cert_illegal_character', { character: 'U+201C', offset: '95' }],
      ['ama_cert_armour_missing', {}],
    ] as const)('names a %s refusal in the operator’s language', async (code, params) => {
      const refused: AmaCertificateInspectResponse = {
        parsed: false,
        rsa_public_key: false,
        chain_validated: false,
        trusted_list_checked: false,
        issuer_authenticated: false,
        legal_validity_claimed: false,
        checks: [
          {
            name: 'certificate_parsed',
            status: 'failed',
            detail: 'server English that must not reach the screen',
            detail_code: code,
            detail_params: params as Record<string, string>,
          },
        ],
      };
      vi.stubGlobal('fetch', stubFetch({ inspectBody: refused }).fn);
      renderPage('/admin/signing/providers/new?mode=cmd');
      const field = (await screen.findByLabelText(
        ptPT['settings.providerCredentials.field.amaCertPem'],
      )) as HTMLTextAreaElement;
      fireEvent.change(field, { target: { value: PEM } });
      fireEvent.click(screen.getByTestId('ama-cert-inspect'));

      const panel = await screen.findByTestId('ama-cert-inspect-result');
      expect(panel.textContent).not.toContain('server English that must not reach the screen');
      // The machine parameters reach the operator verbatim — they are what a person greps for.
      for (const value of Object.values(params)) {
        expect(panel.querySelector('[data-check="certificate_parsed"]')?.textContent).toContain(
          value,
        );
      }
      // Nothing was fingerprinted, so nothing pretends to identify a certificate.
      expect(within(panel).queryByTestId('ama-cert-fingerprint')).toBeNull();
    });

    it('renders an expired certificate as a failed check, keeping the parse result honest', async () => {
      const expired: AmaCertificateInspectResponse = {
        ...amaCertInspection,
        within_validity: false,
        not_after: '2021-01-01T00:00:00Z',
        checks: [
          amaCertInspection.checks[0],
          amaCertInspection.checks[1],
          {
            name: 'validity_window',
            status: 'failed',
            detail: 'The certificate has expired.',
            detail_code: 'ama_cert_expired',
          },
          amaCertInspection.checks[3],
        ],
      };
      const stub = stubFetch({ inspectBody: expired });
      vi.stubGlobal('fetch', stub.fn);
      renderPage('/admin/signing/providers/new?mode=cmd');
      const field = (await screen.findByLabelText(
        ptPT['settings.providerCredentials.field.amaCertPem'],
      )) as HTMLTextAreaElement;
      fireEvent.change(field, { target: { value: PEM } });
      fireEvent.click(screen.getByTestId('ama-cert-inspect'));

      const panel = await screen.findByTestId('ama-cert-inspect-result');
      const validity = panel.querySelector('[data-check="validity_window"]') as HTMLElement;
      expect(validity.textContent).toContain(
        ptPT['settings.providerCredentials.probe.detail.ama_cert_expired'],
      );
      // Expiry must not read as "broken": the parse and the key stay reported as passed, or the
      // operator goes looking for the wrong fault.
      expect(
        within(panel).getByText(ptPT['settings.providerCredentials.probe.detail.ama_cert_parsed']),
      ).toBeTruthy();
    });
  });
});
