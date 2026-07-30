import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router-dom';
import {
  ProviderCredentialEntryForm,
  ProviderCredentialsSection,
} from './ProviderCredentialsSection';
import { ptPT } from '../../i18n/locales/pt-PT';
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
  checks: [
    {
      name: 'credentials_info',
      status: 'passed',
      detail: 'CSC returned a parseable signing certificate and 2 issuer certificate(s).',
      detail_code: 'csc_credential_info_ok',
      detail_params: { issuer_count: '2' },
    },
    // A code this build does not know: the panel must show the server's English, MARKED, rather
    // than blank it or pass it off as translated copy (t112).
    {
      name: 'invented_check',
      status: 'failed',
      detail: 'A sentence only a newer server knows.',
      detail_code: 'invented_by_a_newer_server',
    },
  ],
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

  it('runs the exact-entry probe and reports progress and the log in a dialog', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const row = (await screen.findByText('Primária')).closest('tr') as HTMLElement;
    // Asserted by its stable test id, not by its visible text: the control is icon-only now, and
    // an accessible name is translated prose that must not be pinned here.
    fireEvent.click(within(row).getByTestId('provider-probe-run'));

    await waitFor(() => {
      expect(
        stub.calls.some(
          (call) =>
            call.method === 'POST' &&
            call.url.endsWith('/provider-credentials/csc/encosto%20qtsp/entries/entry%2Fa/probe'),
        ),
      ).toBe(true);
    });

    // The log lives in the dialog, never spilled back into the table cell it was launched from.
    const dialog = await screen.findByTestId('provider-probe-modal');
    expect(await within(dialog).findByTestId('provider-probe-result')).toBeTruthy();
    expect(within(row).queryByTestId('provider-probe-result')).toBeNull();

    // A known code renders TRANSLATED, with its machine parameter verbatim, and never leaks the
    // catalog key itself.
    expect(within(dialog).queryByText(/settings\.providerCredentials/)).toBeNull();
    const info = dialog.querySelector('[data-check="credentials_info"]') as HTMLElement;
    expect(info.textContent).toContain('2');
    expect(info.textContent).not.toContain('CSC returned a parseable');

    // An unknown code keeps the server's English, marked and tagged `lang="en"`.
    const unknown = dialog.querySelector('[data-check="invented_check"]') as HTMLElement;
    expect(unknown.querySelector('[lang="en"]')?.textContent).toBe(
      'A sentence only a newer server knows.',
    );
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

    fireEvent.click(await screen.findByTestId('provider-probe-run'));
    expect(await screen.findByRole('dialog')).toBeTruthy();
    expect(stub.calls.filter((call) => call.method !== 'GET')).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));
    expect(screen.queryByRole('dialog')).toBeNull();
    // The progress dialog must not stand in for the key-operation gate: cancelling the gate
    // leaves nothing open at all.
    expect(screen.queryByTestId('provider-probe-modal')).toBeNull();

    fireEvent.click(screen.getByTestId('provider-probe-run'));
    fireEvent.click(await screen.findByRole('button', { name: 'Executar operação de chave' }));
    await waitFor(() => {
      const request = stub.calls.find(
        (call) => call.method === 'POST' && call.url.endsWith('/probe'),
      );
      expect(JSON.parse(request?.body ?? '{}')).toEqual({
        confirm_private_key_operation: true,
      });
    });
    // Only AFTER the gate is granted does the progress dialog take over; the two never stack.
    const dialog = await screen.findByTestId('provider-probe-modal');
    expect(within(dialog).queryByRole('button', { name: 'Executar operação de chave' })).toBeNull();
  });

  it('keeps reorder, enable/disable and delete mutations on the list', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderSection();

    const first = (await screen.findByText('Primária')).closest('tr') as HTMLElement;
    fireEvent.click(within(first).getByRole('button', { name: 'Descer prioridade' }));
    fireEvent.click(within(first).getByRole('switch', { name: 'Ativa' }));
    fireEvent.click(within(first).getByTestId('provider-entry-remove'));
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
    const test = screen.getAllByTestId('provider-probe-run')[0];
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

  // The modes overview (t105). Every assertion below is on a mode token, a role, a path or a
  // structural attribute — never on rendered copy, which is translated into fourteen locales.
  it('lists every provider mode in the overview, with an honest entry count including zero', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    const { container } = renderSection();
    await screen.findByText('Primária');

    const rows = [...container.querySelectorAll('tr[data-mode]')];
    expect(rows.map((row) => row.getAttribute('data-mode'))).toEqual([
      'cmd',
      'csc',
      'scap',
      'pkcs12',
    ]);
    // The fixture configures two `csc` entries and nothing else, so the other three modes are
    // present at zero — which is the whole reason the table is built from the mode list rather
    // than from the response.
    expect(
      Object.fromEntries(
        rows.map((row) => [
          row.getAttribute('data-mode'),
          row.querySelector('.badge')?.textContent,
        ]),
      ),
    ).toEqual({ cmd: '0', csc: '2', scap: '0', pkcs12: '0' });
  });

  it('routes each overview action to that mode create page, unconfigured modes included', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    const first = renderSection();
    await screen.findByText('Primária');

    // `scap` has no group card at all, so before this row there was no way to reach its form.
    const scapRow = first.container.querySelector('tr[data-mode="scap"]') as HTMLElement;
    fireEvent.click(within(scapRow).getByRole('button'));
    expect(screen.getByTestId('location').textContent).toBe(
      '/admin/signing/providers/new?mode=scap',
    );
    first.unmount();

    const second = renderSection();
    await screen.findByText('Primária');
    const cmdRow = second.container.querySelector('tr[data-mode="cmd"]') as HTMLElement;
    fireEvent.click(within(cmdRow).getByRole('button'));
    expect(screen.getByTestId('location').textContent).toBe(
      '/admin/signing/providers/new?mode=cmd',
    );
  });

  it('explains every column of both tables through a keyboard-reachable help control', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    const { container } = renderSection();
    await screen.findByText('Primária');

    // Group cards render before the modes card, so the entry grid is first.
    const [entryTable, modesTable] = [...container.querySelectorAll('table')];
    expect(entryTable.querySelectorAll('thead th')).toHaveLength(6);
    expect(modesTable.querySelectorAll('thead th')).toHaveLength(5);
    // The hidden caption is what names each grid to assistive tech; adding help must not cost it.
    expect(entryTable.querySelector('caption.sr-only')).toBeTruthy();
    expect(modesTable.querySelector('caption.sr-only')).toBeTruthy();

    for (const th of [
      ...entryTable.querySelectorAll('thead th'),
      ...modesTable.querySelectorAll('thead th'),
    ]) {
      // A real <button> — so the explanation is a tab stop, not a hover-only decoration.
      const trigger = th.querySelector('button.field-help') as HTMLButtonElement | null;
      expect(trigger).toBeTruthy();
      expect(trigger?.disabled).toBe(false);
      // The sentence rides `aria-describedby`, and the bubble it points at is always mounted.
      const bubbleId = trigger?.getAttribute('aria-describedby') ?? '';
      expect(document.getElementById(bubbleId)?.textContent).toBeTruthy();
      // The `<th>` keeps its own accessible name, so the help button is not recited per cell.
      expect(th.getAttribute('aria-label')).toBeTruthy();
    }

    // Keyboard focus alone opens the bubble (no pointer involved).
    const probe = entryTable.querySelector('thead th button.field-help') as HTMLButtonElement;
    const bubble = document.getElementById(probe.getAttribute('aria-describedby') ?? '');
    expect(bubble?.className).not.toContain('is-open');
    fireEvent.focus(probe);
    expect(bubble?.className).toContain('is-open');
    fireEvent.blur(probe);
    expect(bubble?.className).not.toContain('is-open');
  });

  // CSC has no default base address (`probe_csc` fails the entry `configuration_incomplete`
  // without one) while SCAP defaults it per environment, so one shared sentence would be false for
  // whichever mode it was not written for. Asserted through the catalog key, never a copy literal,
  // so the check survives a re-translation.
  it('gives the endpoint field the help and hint its mode actually warrants', () => {
    const noop = () => {};
    const csc = renderWithProviders(
      <ProviderCredentialEntryForm mode="csc" disabled={false} onDone={noop} onCancel={noop} />,
    );
    expect(document.body.textContent).toContain(
      ptPT['settings.providerCredentials.form.endpointHint.csc'],
    );
    expect(document.body.textContent).toContain(
      ptPT['settings.providerCredentials.help.endpoint.csc'],
    );
    expect(document.body.textContent).not.toContain(
      ptPT['settings.providerCredentials.form.endpointHint'],
    );
    csc.unmount();

    // No handle needed: the shared `afterEach` cleanup unmounts this one.
    renderWithProviders(
      <ProviderCredentialEntryForm mode="scap" disabled={false} onDone={noop} onCancel={noop} />,
    );
    expect(document.body.textContent).toContain(
      ptPT['settings.providerCredentials.form.endpointHint'],
    );
    expect(document.body.textContent).not.toContain(
      ptPT['settings.providerCredentials.form.endpointHint.csc'],
    );
  });

  const sandboxSwitch = () => {
    const label = screen
      .getByText(ptPT['settings.providerCredentials.field.sandbox'])
      .closest('label') as HTMLElement;
    return label.querySelector('input[role="switch"]') as HTMLInputElement;
  };

  // The assertion that would have caught the defect: the server reads
  // `selector_bool(&entry, "sandbox", true)`, so an ABSENT selector means ON. The form used to
  // render `checked={value === 'true'}`, showing a security-relevant switch as off while
  // `http://localhost` was being accepted in place of required HTTPS.
  //
  // This is about STORED data only. New entries no longer reach the server without the key (see
  // the create case below), so `existing` is now the only way an absent selector arrives — which
  // makes the guarantee narrower but no weaker: those entries exist and still read as on.
  it('shows an absent sandbox selector in the state the server actually applies', () => {
    const noop = () => {};

    // A stored entry that predates the selector, or was created through the API without it.
    const legacy = renderWithProviders(
      <ProviderCredentialEntryForm
        mode="csc"
        providerId="encosto qtsp"
        existing={list.providers[0].entries[1]}
        disabled={false}
        onDone={noop}
        onCancel={noop}
      />,
    );
    expect(list.providers[0].entries[1].selectors.sandbox).toBeUndefined();
    expect(sandboxSwitch().checked).toBe(true);
    legacy.unmount();

    // An explicit `false` still reads as off — the default must not swallow a real value.
    renderWithProviders(
      <ProviderCredentialEntryForm
        mode="csc"
        providerId="encosto qtsp"
        existing={{ ...list.providers[0].entries[1], selectors: { sandbox: 'false' } }}
        disabled={false}
        onDone={noop}
        onCancel={noop}
      />,
    );
    expect(sandboxSwitch().checked).toBe(false);
  });

  // The other half of the pair above, and the reason the two questions needed separate fields on
  // `SelectorFieldSpec`: what an ABSENT stored value means (on) is not what a NEW entry should be
  // (off). Sandbox relaxes `CscConfig::validate` to accept `http://localhost` in place of required
  // HTTPS, so an entry only gets that because the operator asked for it — while the toggle stays a
  // toggle and moves freely in both directions.
  it('starts a new entry unsandboxed and keeps the toggle switchable both ways', () => {
    const noop = () => {};
    renderWithProviders(
      <ProviderCredentialEntryForm mode="csc" disabled={false} onDone={noop} onCancel={noop} />,
    );

    expect(sandboxSwitch().checked).toBe(false);
    fireEvent.click(sandboxSwitch());
    expect(sandboxSwitch().checked).toBe(true);
    fireEvent.click(sandboxSwitch());
    expect(sandboxSwitch().checked).toBe(false);
  });

  it('says what an empty endpoint means for the mode, instead of claiming a default', async () => {
    // `csc` has no default to fall back on, so the row must not read like the other modes.
    vi.stubGlobal('fetch', stubFetch().fn);
    const csc = renderSection();
    const secondary = (await screen.findByText('Secundária')).closest('tr') as HTMLElement;
    expect(secondary.textContent).toContain(
      ptPT['settings.providerCredentials.table.endpointRequired'],
    );
    expect(secondary.textContent).not.toContain(
      ptPT['settings.providerCredentials.table.endpointDefault'],
    );
    csc.unmount();

    // A local keystore has no address at all — neither a default nor a missing one.
    vi.stubGlobal(
      'fetch',
      stubFetch({
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
                fields: [],
                created_at: '2026-07-01T10:00:00Z',
                updated_at: '2026-07-01T10:00:00Z',
              },
            ],
          },
        ],
      }).fn,
    );
    renderSection();
    const p12 = (await screen.findByText('Chave local')).closest('tr') as HTMLElement;
    expect(p12.textContent).toContain(
      ptPT['settings.providerCredentials.table.endpointNotApplicable'],
    );
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
