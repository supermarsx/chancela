import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useSearchParams } from 'react-router-dom';
import type {
  ConnectorJobView,
  ConnectorProbeView,
  ConnectorTargetView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { ConnectorOperations } from './ConnectorOperations';
import { connectorConfigTemplate } from './operatorModels';

const TENANT = 'tenant-1';

const TARGET: ConnectorTargetView = {
  schema_version: 1,
  id: 'target-1',
  repository_id: 'repo-1',
  tenant_id: TENANT,
  name: 'Arquivo WebDAV',
  enabled: true,
  purposes: ['sync', 'backup'],
  kind: 'web_dav',
  config: connectorConfigTemplate('web_dav'),
  credential_storage: 'environment_or_confined_file_reference',
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-01T10:00:00Z',
  archived_at: null,
};

function job(overrides: Partial<ConnectorJobView> = {}): ConnectorJobView {
  return {
    id: 'job-1',
    tenant_id: TENANT,
    target_id: 'target-1',
    repository_id: 'repo-1',
    purpose: 'sync',
    destination: 'atas/2026/ata-3.pdf',
    content_type: 'application/pdf',
    source_sha256: 'a'.repeat(64),
    bytes: 4096,
    created_unix_millis: 1_752_000_000_000,
    state: 'queued',
    attempt: 1,
    not_before_unix_millis: null,
    error_class: null,
    detail: 'Aguarda o executor durável.',
    receipt: null,
    ...overrides,
  };
}

const PROBE_READY: ConnectorProbeView = {
  target_id: 'target-1',
  checked_at: '2026-07-16T09:00:00Z',
  status: {
    target_id: 'target-1',
    kind: 'web_dav',
    state: 'ready',
    capabilities: ['upload', 'remote_checksum'],
    detail: 'Ligação estabelecida com o servidor WebDAV.',
  },
  error_class: null,
  error: null,
};

interface Recorded {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function stubFetch(override?: (call: Recorded) => Response | null): Recorded[] {
  const calls: Recorded[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const call: Recorded = {
      url,
      method: init?.method ?? 'GET',
      body: init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null,
    };
    calls.push(call);
    const custom = override?.(call);
    if (custom) return custom;
    if (call.method === 'GET' && url.includes('/connector-targets')) return jsonResponse([TARGET]);
    if (call.method === 'GET' && /\/connector-jobs\/[^/?]+$/.test(url)) {
      return jsonResponse(job());
    }
    if (call.method === 'GET' && url.includes('/connector-jobs')) {
      return jsonResponse({ jobs: [job()], next_before_created_unix_millis: null });
    }
    if (call.method !== 'GET') return new Response(null, { status: 204 });
    throw new Error(`Unexpected ${call.method} ${url}`);
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

function SearchProbe() {
  const [params] = useSearchParams();
  return <output data-testid="search">{params.toString()}</output>;
}

function renderConnectors(entries = ['/operacoes?view=connectors']) {
  return renderWithProviders(
    <>
      <ConnectorOperations tenantId={TENANT} />
      <SearchProbe />
    </>,
    entries,
  );
}

/** The purposes fieldset of one form (create and edit both render one). */
function purposesFieldset(form: HTMLElement): HTMLElement {
  return within(form).getByRole('group', { name: 'Finalidades permitidas' });
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('connector target list', () => {
  it('lists a target with its kind, allowed purposes, and enabled state', async () => {
    stubFetch();
    renderConnectors();

    const row = (await screen.findByText('Arquivo WebDAV')).closest('tr');
    const cells = within(row as HTMLTableRowElement).getAllByRole('cell');
    expect(cells[1].textContent).toBe('WebDAV');
    expect(cells[2].textContent).toBe('Sincronização, Cópia de segurança');
    expect(cells[3].textContent).toBe('Sim');
  });

  it('marks a disabled target as inactive rather than silently listing it as usable', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-targets')
        ? jsonResponse([{ ...TARGET, enabled: false }])
        : null,
    );
    renderConnectors();

    const row = (await screen.findByText('Arquivo WebDAV')).closest('tr');
    expect(within(row as HTMLTableRowElement).getAllByRole('cell')[3].textContent).toBe('Não');
  });

  it('reads each durable job state with the tone its outcome deserves', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-jobs')
        ? jsonResponse({
            jobs: [
              job({ id: 'j1', state: 'retry_scheduled', destination: '1.pdf' }),
              job({ id: 'j2', state: 'cancelled', destination: '2.pdf' }),
              job({ id: 'j3', state: 'recovered', destination: '3.pdf' }),
              job({ id: 'j4', state: 'running', destination: '4.pdf' }),
            ],
            next_before_created_unix_millis: null,
          })
        : null,
    );
    renderConnectors();

    expect((await screen.findByText('Nova tentativa agendada')).className).toContain('badge--warn');
    expect(screen.getByText('Cancelado').className).toContain('badge--neutral');
    expect(screen.getByText('Recuperado').className).toContain('badge--ok');
    expect(screen.getByText('Em execução').className).toContain('badge--info');
  });

  it('surfaces a failed target listing instead of an empty configured-targets panel', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-targets')
        ? jsonResponse({ error: 'Integrações indisponíveis' }, 502)
        : null,
    );
    renderConnectors();

    expect(await screen.findByText('Integrações indisponíveis')).toBeTruthy();
    expect(screen.queryByText('Ainda não existem destinos de conector.')).toBeNull();
  });

  it('opens a target into a deep-linked editor', async () => {
    stubFetch();
    renderConnectors();

    const row = (await screen.findByText('Arquivo WebDAV')).closest('tr') as HTMLTableRowElement;
    fireEvent.click(within(row).getByRole('button', { name: 'Abrir' }));

    expect(await screen.findByRole('heading', { name: 'Configuração do destino' })).toBeTruthy();
    await waitFor(() =>
      expect(screen.getByTestId('search').textContent).toContain('target=target-1'),
    );
  });
});

describe('CreateConnectorForm', () => {
  it('swaps the configuration template and narrows the purposes when the kind changes', async () => {
    stubFetch();
    renderConnectors();

    const kind = (await screen.findByLabelText('Tipo')) as HTMLSelectElement;
    const config = screen.getByLabelText('Configuração avançada JSON') as HTMLTextAreaElement;
    expect(JSON.parse(config.value).kind).toBe('web_dav');

    fireEvent.change(kind, { target: { value: 's3' } });

    const parsed = JSON.parse(config.value) as Record<string, unknown>;
    expect(parsed.kind).toBe('s3');
    expect(parsed.bucket).toBe('chancela-backups');
    // S3 is a backup destination, so sync must not stay silently selected.
    const fieldset = purposesFieldset(config.closest('form') as HTMLFormElement);
    expect((within(fieldset).getByLabelText('Sincronização') as HTMLInputElement).checked).toBe(
      false,
    );
    expect(
      (within(fieldset).getByLabelText('Cópia de segurança') as HTMLInputElement).checked,
    ).toBe(true);
  });

  it('refuses malformed configuration in the client without calling the API', async () => {
    const calls = stubFetch();
    renderConnectors();

    fireEvent.change(await screen.findByLabelText('Nome', {
      selector: '#operations-connector-name',
    }), { target: { value: 'Destino novo' } });
    fireEvent.change(screen.getByLabelText('Configuração avançada JSON'), {
      target: { value: '{ not json' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Criar conector/ }));

    expect(await screen.findByText('Connector configuration must be valid JSON')).toBeTruthy();
    expect(calls.some((call) => call.method === 'POST')).toBe(false);
  });

  it('refuses a raw credential in the configuration before it can reach the API', async () => {
    const calls = stubFetch();
    renderConnectors();

    fireEvent.change(await screen.findByLabelText('Nome', {
      selector: '#operations-connector-name',
    }), { target: { value: 'Destino novo' } });
    fireEvent.change(screen.getByLabelText('Configuração avançada JSON'), {
      target: {
        value: JSON.stringify({ kind: 'web_dav', id: 'pending-target', password: 'hunter2' }),
      },
    });
    fireEvent.click(screen.getByRole('button', { name: /Criar conector/ }));

    expect(await screen.findByText(/looks like secret material/)).toBeTruthy();
    expect(calls.some((call) => call.method === 'POST')).toBe(false);
  });

  it('cannot create a target with no purpose selected', async () => {
    stubFetch();
    renderConnectors();

    const name = (await screen.findByLabelText('Nome', {
      selector: '#operations-connector-name',
    })) as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Destino novo' } });
    const create = screen.getByRole('button', { name: /Criar conector/ });
    expect(create.hasAttribute('disabled')).toBe(false);

    const fieldset = purposesFieldset(name.closest('form') as HTMLFormElement);
    fireEvent.click(within(fieldset).getByLabelText('Sincronização'));
    expect(create.hasAttribute('disabled')).toBe(true);
  });

  it('creates a target from the validated template and clears the name', async () => {
    const calls = stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith('/connector-targets')
        ? jsonResponse({ ...TARGET, id: 'target-2', name: 'Destino novo' })
        : null,
    );
    renderConnectors();

    const name = (await screen.findByLabelText('Nome', {
      selector: '#operations-connector-name',
    })) as HTMLInputElement;
    fireEvent.change(name, { target: { value: '  Destino novo  ' } });
    fireEvent.click(screen.getByRole('button', { name: /Criar conector/ }));

    await waitFor(() => expect(calls.some((call) => call.method === 'POST')).toBe(true));
    const posted = calls.find((call) => call.method === 'POST')?.body;
    expect(posted).toMatchObject({ name: 'Destino novo', enabled: true, purposes: ['sync'] });
    expect((posted?.config as Record<string, unknown>).kind).toBe('web_dav');
    await waitFor(() => expect(name.value).toBe(''));
  });

  it('reports a server refusal once, without a spurious client-side validation note', async () => {
    stubFetch((call) =>
      call.method === 'POST' && call.url.endsWith('/connector-targets')
        ? jsonResponse({ error: 'Já existe um destino com este nome' }, 409)
        : null,
    );
    renderConnectors();

    const name = (await screen.findByLabelText('Nome', {
      selector: '#operations-connector-name',
    })) as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Arquivo WebDAV' } });
    fireEvent.click(screen.getByRole('button', { name: /Criar conector/ }));

    expect(
      (await screen.findAllByText('Já existe um destino com este nome')).length,
    ).toBe(1);
    expect(name.value).toBe('Arquivo WebDAV');
  });
});

describe('TargetEditor', () => {
  it('reports a successful probe with the capabilities the destination advertises', async () => {
    stubFetch((call) => (call.url.endsWith('/probe') ? jsonResponse(PROBE_READY) : null));
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    fireEvent.click(await screen.findByRole('button', { name: /Testar ligação/ }));

    expect(
      await screen.findByText('Ligação estabelecida com o servidor WebDAV.'),
    ).toBeTruthy();
    expect(screen.getByText('upload, remote_checksum')).toBeTruthy();
  });

  it('reports a probe that returned no status through its error text', async () => {
    stubFetch((call) =>
      call.url.endsWith('/probe')
        ? jsonResponse({
            ...PROBE_READY,
            status: null,
            error_class: 'authentication',
            error: 'Credencial recusada pelo destino.',
          })
        : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    fireEvent.click(await screen.findByRole('button', { name: /Testar ligação/ }));

    expect(await screen.findByText('Credencial recusada pelo destino.')).toBeTruthy();
  });

  it('blocks probing and running while the target is disabled', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-targets')
        ? jsonResponse([{ ...TARGET, enabled: false }])
        : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    expect(
      (await screen.findByRole('button', { name: /Testar ligação/ })).hasAttribute('disabled'),
    ).toBe(true);
    fireEvent.change(screen.getByLabelText('Destino relativo'), {
      target: { value: 'atas/2026' },
    });
    fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: 'act-1' } });
    expect(
      screen.getByRole('button', { name: /Colocar trabalho em fila/ }).hasAttribute('disabled'),
    ).toBe(true);
  });

  it('queues a sync run as a signed act document and clears the destination', async () => {
    const calls = stubFetch((call) =>
      call.url.endsWith('/run') ? jsonResponse(job({ id: 'job-new' })) : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    const destination = (await screen.findByLabelText('Destino relativo')) as HTMLInputElement;
    fireEvent.change(destination, { target: { value: '  atas/2026/ata-3.pdf  ' } });
    fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: '  act-1  ' } });
    fireEvent.click(screen.getByRole('button', { name: /Colocar trabalho em fila/ }));

    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/run'))).toBe(true));
    expect(calls.find((call) => call.url.endsWith('/run'))?.body).toMatchObject({
      purpose: 'sync',
      destination: 'atas/2026/ata-3.pdf',
      artifact: { kind: 'act_document', act_id: 'act-1', variant: 'signed' },
    });
    await waitFor(() => expect(destination.value).toBe(''));
  });

  it('queues a backup run without asking for an act, sending the instance-backup artifact', async () => {
    const calls = stubFetch((call) =>
      call.url.endsWith('/run') ? jsonResponse(job({ id: 'job-new', purpose: 'backup' })) : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    fireEvent.change(await screen.findByLabelText('Finalidade'), {
      target: { value: 'backup' },
    });
    expect(screen.queryByLabelText('ID do ato')).toBeNull();
    fireEvent.change(screen.getByLabelText('Destino relativo'), {
      target: { value: 'copias/instancia.tar' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Colocar trabalho em fila/ }));

    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/run'))).toBe(true));
    expect(calls.find((call) => call.url.endsWith('/run'))?.body).toMatchObject({
      purpose: 'backup',
      artifact: { kind: 'latest_instance_backup' },
    });
  });

  it('offers only the purposes the target itself declares', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-targets')
        ? jsonResponse([{ ...TARGET, purposes: ['backup'] }])
        : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    const purpose = (await screen.findByLabelText('Finalidade')) as HTMLSelectElement;
    expect(Array.from(purpose.options, (option) => option.value)).toEqual(['backup']);
  });

  it('reports a rejected run without clearing the destination the operator typed', async () => {
    stubFetch((call) =>
      call.url.endsWith('/run') ? jsonResponse({ error: 'Destino fora da raiz' }, 422) : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    const destination = (await screen.findByLabelText('Destino relativo')) as HTMLInputElement;
    fireEvent.change(destination, { target: { value: '../fora' } });
    fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: 'act-1' } });
    fireEvent.click(screen.getByRole('button', { name: /Colocar trabalho em fila/ }));

    expect(await screen.findByText('Destino fora da raiz')).toBeTruthy();
    expect(destination.value).toBe('../fora');
  });

  it('refuses to save configuration that fails the credential boundary', async () => {
    const calls = stubFetch();
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    fireEvent.change(await screen.findByLabelText('Configuração avançada JSON', {
      selector: '#operations-target-edit-config',
    }), {
      target: { value: JSON.stringify({ kind: 'web_dav', id: 'x', token_ref: 'TOKEN' }) },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    expect(
      await screen.findByText(
        'config.token_ref must be a CHANCELA_CONNECTOR_SECRET_* environment or confined-file reference',
      ),
    ).toBeTruthy();
    expect(calls.some((call) => call.method === 'PATCH')).toBe(false);
  });

  it('saves the renamed target with the narrowed purpose set', async () => {
    const calls = stubFetch((call) =>
      call.method === 'PATCH' ? jsonResponse({ ...TARGET, purposes: ['sync'] }) : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    const name = (await screen.findByLabelText('Nome', {
      selector: '#operations-target-edit-name',
    })) as HTMLInputElement;
    fireEvent.change(name, { target: { value: '  Arquivo WebDAV II  ' } });
    const form = name.closest('form') as HTMLFormElement;
    fireEvent.click(within(purposesFieldset(form)).getByLabelText('Cópia de segurança'));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PATCH')).toBe(true));
    expect(calls.find((call) => call.method === 'PATCH')?.body).toMatchObject({
      name: 'Arquivo WebDAV II',
      purposes: ['sync'],
    });
  });

  it('reports a rejected save on the target editor', async () => {
    stubFetch((call) =>
      call.method === 'PATCH' ? jsonResponse({ error: 'Destino arquivado' }, 409) : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    const name = await screen.findByLabelText('Nome', {
      selector: '#operations-target-edit-name',
    });
    fireEvent.click(
      within(name.closest('form') as HTMLFormElement).getByRole('button', { name: 'Guardar' }),
    );

    expect(await screen.findByText('Destino arquivado')).toBeTruthy();
  });

  it('queues a canonical document when that variant is chosen', async () => {
    const calls = stubFetch((call) =>
      call.url.endsWith('/run') ? jsonResponse(job({ id: 'job-new' })) : null,
    );
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    fireEvent.change(await screen.findByLabelText('Destino relativo'), {
      target: { value: 'atas/2026/ata-3.pdf' },
    });
    fireEvent.change(screen.getByLabelText('ID do ato'), { target: { value: 'act-1' } });
    fireEvent.change(screen.getByLabelText('Variante documental'), {
      target: { value: 'canonical' },
    });
    fireEvent.click(screen.getByRole('button', { name: /Colocar trabalho em fila/ }));

    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/run'))).toBe(true));
    expect(calls.find((call) => call.url.endsWith('/run'))?.body).toMatchObject({
      artifact: { kind: 'act_document', act_id: 'act-1', variant: 'canonical' },
    });
  });

  it('archives the target through its own action', async () => {
    const calls = stubFetch();
    renderConnectors(['/operacoes?view=connectors&target=target-1']);

    fireEvent.click(await screen.findByRole('button', { name: /Arquivar destino/ }));

    await waitFor(() =>
      expect(
        calls.some(
          (call) => call.method === 'DELETE' && call.url.endsWith('/connector-targets/target-1'),
        ),
      ).toBe(true),
    );
  });
});

describe('connector jobs', () => {
  it('shows the empty state when no durable job has ever run', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-jobs')
        ? jsonResponse({ jobs: [], next_before_created_unix_millis: null })
        : null,
    );
    renderConnectors();

    expect(
      await screen.findByText('Ainda não existem trabalhos para esta organização.'),
    ).toBeTruthy();
  });

  it('surfaces a failed job listing', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-jobs')
        ? jsonResponse({ error: 'Fila indisponível' }, 503)
        : null,
    );
    renderConnectors();

    expect(await screen.findByText('Fila indisponível')).toBeTruthy();
  });

  it('reads a failed job as an error and a finished job as a success', async () => {
    stubFetch((call) =>
      call.method === 'GET' && call.url.includes('/connector-jobs')
        ? jsonResponse({
            jobs: [
              job({ id: 'job-failed', state: 'failed', destination: 'a.pdf' }),
              job({ id: 'job-done', state: 'succeeded', destination: 'b.pdf' }),
            ],
            next_before_created_unix_millis: null,
          })
        : null,
    );
    renderConnectors();

    expect((await screen.findByText('Falhou')).className).toContain('badge--error');
    expect(screen.getByText('Concluído').className).toContain('badge--ok');
  });

  it('opens a job into a detail panel carrying its receipt evidence', async () => {
    stubFetch((call) =>
      call.method === 'GET' && /\/connector-jobs\/[^/?]+$/.test(call.url)
        ? jsonResponse(
            job({
              state: 'succeeded',
              attempt: 2,
              receipt: {
                completed_unix_millis: 1_752_000_100_000,
                connector: 'web_dav',
                provider_object_id: 'obj-9',
                provider_revision: null,
                etag: null,
                remote_bytes: 4096,
                checksum_evidence: 'remote_confirmed',
              },
            }),
          )
        : null,
    );
    renderConnectors();

    const jobRow = (await screen.findByText('atas/2026/ata-3.pdf'))
      .closest('tr') as HTMLTableRowElement;
    fireEvent.click(within(jobRow).getByRole('button', { name: 'Abrir' }));

    const detail = (await screen.findByRole('heading', { name: 'Detalhe do trabalho' }))
      .closest('section') as HTMLElement;
    expect(within(detail).getByText('Tentativa').nextElementSibling?.textContent).toBe('2');
    expect(within(detail).getByText('a'.repeat(64))).toBeTruthy();
    expect(
      within(detail).getByText('4096 bytes remotos; evidência de integridade: confirmado pelo destino.'),
    ).toBeTruthy();
  });

  it('allows cancelling a queued job but not retrying it', async () => {
    const calls = stubFetch((call) =>
      call.url.endsWith('/cancel') ? jsonResponse(job({ state: 'cancelled' })) : null,
    );
    renderConnectors(['/operacoes?view=connectors&job=job-1']);

    const cancel = await screen.findByRole('button', { name: 'Cancelar trabalho' });
    expect(cancel.hasAttribute('disabled')).toBe(false);
    expect(screen.getByRole('button', { name: 'Tentar novamente' }).hasAttribute('disabled')).toBe(
      true,
    );
    fireEvent.click(cancel);

    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/cancel'))).toBe(true));
  });

  it('allows retrying a failed job but not cancelling it', async () => {
    const calls = stubFetch((call) => {
      if (call.url.endsWith('/retry')) return jsonResponse(job({ state: 'queued' }));
      if (call.method === 'GET' && /\/connector-jobs\/[^/?]+$/.test(call.url)) {
        return jsonResponse(job({ state: 'failed', error_class: 'permanent' }));
      }
      return null;
    });
    renderConnectors(['/operacoes?view=connectors&job=job-1']);

    const retry = await screen.findByRole('button', { name: 'Tentar novamente' });
    expect(retry.hasAttribute('disabled')).toBe(false);
    expect(
      screen.getByRole('button', { name: 'Cancelar trabalho' }).hasAttribute('disabled'),
    ).toBe(true);
    fireEvent.click(retry);

    await waitFor(() => expect(calls.some((call) => call.url.endsWith('/retry'))).toBe(true));
  });

  it('surfaces a failed job detail load', async () => {
    stubFetch((call) =>
      call.method === 'GET' && /\/connector-jobs\/[^/?]+$/.test(call.url)
        ? jsonResponse({ error: 'Trabalho desconhecido' }, 404)
        : null,
    );
    renderConnectors(['/operacoes?view=connectors&job=job-missing']);

    expect(await screen.findByText('Trabalho desconhecido')).toBeTruthy();
  });

  it('pages back through older jobs and returns to the newest page', async () => {
    const calls = stubFetch((call) => {
      if (call.method !== 'GET' || !call.url.includes('/connector-jobs')) return null;
      if (call.url.includes('before_created_unix_millis=')) {
        return jsonResponse({
          jobs: [job({ id: 'job-old', destination: 'antigo.pdf' })],
          next_before_created_unix_millis: null,
        });
      }
      return jsonResponse({
        jobs: [job({ destination: 'recente.pdf' })],
        next_before_created_unix_millis: 1_751_000_000_000,
      });
    });
    renderConnectors();

    fireEvent.click(await screen.findByRole('button', { name: 'Carregar trabalhos anteriores' }));

    expect(await screen.findByText('antigo.pdf')).toBeTruthy();
    expect(
      calls.some((call) => call.url.includes('before_created_unix_millis=1751000000000')),
    ).toBe(true);
    expect(screen.queryByRole('button', { name: 'Carregar trabalhos anteriores' })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Voltar aos mais recentes' }));
    expect(await screen.findByText('recente.pdf')).toBeTruthy();
  });
});
