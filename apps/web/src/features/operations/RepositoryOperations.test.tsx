import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useSearchParams } from 'react-router-dom';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(async () => ({ kind: 'browser-download' as const })),
  saveBlobResultMessage: vi.fn(() => 'Transferência iniciada pelo navegador.'),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import type {
  BookView,
  Entity,
  OpaqueBlobManifest,
  StoredRepositoryPolicy,
  TenantRepositoryPolicy,
  ZkObjectVersionView,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { RepositoryOperations } from './RepositoryOperations';
import { bytesToBase64, encryptZkObject } from './zkCrypto';

const TENANT = 'tenant-1';

const ENTITY: Entity = {
  id: 'entity-1',
  tenant_id: TENANT,
  group_id: null,
  name: 'Encosto Estratégico, Lda.',
  nipc: '503004642',
} as Entity;

const OTHER_TENANT_ENTITY: Entity = {
  id: 'entity-2',
  tenant_id: 'tenant-2',
  group_id: null,
  name: 'Fundação Sul',
  nipc: '500999888',
} as Entity;

const BOOKS = [
  { id: 'book-1', entity_id: 'entity-1', kind: 'Atas' },
  { id: 'book-2', entity_id: 'entity-2', kind: 'Atas' },
] as unknown as BookView[];

const TENANT_POLICY: TenantRepositoryPolicy = {
  tenant_id: TENANT,
  encryption_mode: 'standard',
  custody: {
    bring_your_own_key: true,
    webauthn_prf_unsealing: false,
    split_key_recovery: null,
  },
  gdpr_obligations_remain: true,
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-01T10:00:00Z',
};

function repository(
  overrides: Partial<StoredRepositoryPolicy['policy']> = {},
): StoredRepositoryPolicy {
  return {
    policy: {
      repository_id: 'repo-1',
      tenant_id: TENANT,
      name: 'Arquivo principal',
      encryption_mode: 'standard',
      zk_scope: null,
      custody: {
        bring_your_own_key: true,
        webauthn_prf_unsealing: false,
        split_key_recovery: null,
      },
      gdpr_obligations_remain: true,
      created_at: '2026-07-01T10:00:00Z',
      updated_at: '2026-07-01T10:00:00Z',
      ...overrides,
    },
    policy_source: 'repository',
  };
}

const ZK_REPOSITORY = repository({ encryption_mode: 'zero_knowledge' });

/** A 32-byte BYOK key in base64, deterministic per seed. */
function byok(seed: number): string {
  return bytesToBase64(Uint8Array.from({ length: 32 }, (_, index) => (seed + index) % 256));
}

const OBJECT_KEY = byok(5);

/** Build a real client-encrypted object so decryption tests exercise the true crypto path. */
async function encryptedObject(plaintext: string) {
  const encrypted = await encryptZkObject({
    plaintext: new TextEncoder().encode(plaintext).buffer as ArrayBuffer,
    repositoryId: 'repo-1',
    objectId: 'object-1',
    version: 1,
    byokBase64: OBJECT_KEY,
    recipientId: 'primary-custodian',
    now: new Date('2026-07-16T12:00:00.000Z'),
  });
  const view: ZkObjectVersionView = {
    archive_id: 'archive-1',
    tenant_id: TENANT,
    manifest: encrypted.manifest,
    ciphertext_url: '/v1/opaque/object-1',
    committed_at: '2026-07-16T12:00:00Z',
  };
  return { view, ciphertext: encrypted.ciphertext, manifest: encrypted.manifest };
}

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

interface StubOptions {
  tenantPolicy?: Response;
  repositories?: StoredRepositoryPolicy[];
  objects?: ZkObjectVersionView[];
  ciphertext?: ArrayBuffer;
  override?: (call: Recorded) => Response | null;
}

function stubFetch(options: StubOptions = {}): Recorded[] {
  const calls: Recorded[] = [];
  const fn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const call: Recorded = {
      url,
      method: init?.method ?? 'GET',
      // Opaque ciphertext is PUT as raw bytes, so only JSON bodies are parsed.
      body:
        typeof init?.body === 'string' ? (JSON.parse(init.body) as Record<string, unknown>) : null,
    };
    calls.push(call);
    const custom = options.override?.(call);
    if (custom) return custom;
    if (call.method === 'GET') {
      if (url.endsWith('/repository-policy')) {
        return options.tenantPolicy ?? jsonResponse(TENANT_POLICY);
      }
      if (url.endsWith(`/tenants/${TENANT}/repositories`)) {
        return jsonResponse(options.repositories ?? []);
      }
      if (url.endsWith('/objects')) return jsonResponse(options.objects ?? []);
      if (url.endsWith('/ciphertext')) {
        return new Response(options.ciphertext ?? new ArrayBuffer(0), {
          headers: { 'Content-Type': 'application/octet-stream' },
        });
      }
      if (url.includes('/v1/books')) return jsonResponse(BOOKS);
      throw new Error(`Unexpected GET ${url}`);
    }
    return new Response(null, { status: 204 });
  }) as typeof fetch;
  vi.stubGlobal('fetch', fn);
  return calls;
}

function SearchProbe() {
  const [params] = useSearchParams();
  return <output data-testid="search">{params.toString()}</output>;
}

function renderRepositories(
  entries = ['/operacoes?view=repositories'],
  entities: Entity[] = [ENTITY, OTHER_TENANT_ENTITY],
) {
  return renderWithProviders(
    <>
      <RepositoryOperations tenantId={TENANT} entities={entities} />
      <SearchProbe />
    </>,
    entries,
  );
}

const GDPR_ACK =
  'Confirmo que a custódia de chaves não elimina obrigações RGPD, retenção ou legibilidade.';

/**
 * The tenant-policy form. Several of its labels ("Modo de cifragem", the GDPR acknowledgement)
 * also appear on the create-repository form, so every assertion is scoped to one of them.
 */
async function tenantPolicyForm(): Promise<HTMLFormElement> {
  const mode = await screen.findByLabelText('Modo de cifragem', {
    selector: '#operations-tenant-policy-mode',
  });
  return mode.closest('form') as HTMLFormElement;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  saveFileMock.saveBlobAs.mockClear();
});

describe('TenantPolicy', () => {
  it('treats an absent tenant policy as a blank opt-in form, not an error', async () => {
    stubFetch({ tenantPolicy: jsonResponse({ error: 'Sem política' }, 404) });
    renderRepositories();

    expect(await tenantPolicyForm()).toBeTruthy();
    expect(screen.queryByText('Sem política')).toBeNull();
    // With no stored policy there is nothing to remove.
    expect(screen.queryByRole('button', { name: 'Remover política própria' })).toBeNull();
  });

  it('reports a real policy failure and withholds the editor', async () => {
    stubFetch({ tenantPolicy: jsonResponse({ error: 'Política indisponível' }, 500) });
    renderRepositories();

    expect(await screen.findByText('Política indisponível')).toBeTruthy();
    expect(
      screen.queryByLabelText('Modo de cifragem', { selector: '#operations-tenant-policy-mode' }),
    ).toBeNull();
  });

  it('offers removal only once a tenant-owned policy exists', async () => {
    const calls = stubFetch();
    renderRepositories();

    fireEvent.click(await screen.findByRole('button', { name: 'Remover política própria' }));

    await waitFor(() =>
      expect(
        calls.some((call) => call.method === 'DELETE' && call.url.endsWith('/repository-policy')),
      ).toBe(true),
    );
  });
});

describe('TenantPolicyEditor', () => {
  it('requires the GDPR acknowledgement before the policy can be saved', async () => {
    stubFetch();
    renderRepositories();

    const form = await tenantPolicyForm();
    const save = within(form).getByRole('button', { name: 'Guardar política' });
    expect(save.hasAttribute('disabled')).toBe(true);

    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    expect(save.hasAttribute('disabled')).toBe(false);
  });

  it('sends an empty custody policy while the tenant stays on server-managed encryption', async () => {
    const calls = stubFetch({
      override: (call) =>
        call.method === 'PUT' ? jsonResponse({ ...TENANT_POLICY, updated_at: 'x' }) : null,
    });
    renderRepositories();

    const form = await tenantPolicyForm();
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    expect(within(form).queryByText('Custódia e recuperação')).toBeNull();
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar política' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PUT')).toBe(true));
    expect(calls.find((call) => call.method === 'PUT')?.body).toEqual({
      encryption_mode: 'standard',
      custody: {
        bring_your_own_key: false,
        webauthn_prf_unsealing: false,
        split_key_recovery: null,
      },
      gdpr_obligations_remain: true,
    });
  });

  it('reveals custody options only for zero knowledge, and the split plan only when chosen', async () => {
    stubFetch();
    renderRepositories();

    const form = await tenantPolicyForm();
    fireEvent.change(within(form).getByLabelText('Modo de cifragem'), {
      target: { value: 'zero_knowledge' },
    });

    expect(within(form).getByText('Custódia e recuperação')).toBeTruthy();
    expect(within(form).queryByLabelText('Limiar necessário')).toBeNull();

    fireEvent.click(within(form).getByLabelText('Plano de recuperação com chave repartida'));
    expect(within(form).getByLabelText('Limiar necessário')).toBeTruthy();
    expect(within(form).getByLabelText('Número de partes')).toBeTruthy();
    expect(within(form).getByLabelText('Rótulos públicos dos custodiantes')).toBeTruthy();
  });

  it('refuses a split-recovery plan whose labels do not cover every share', async () => {
    const calls = stubFetch();
    renderRepositories();

    const form = await tenantPolicyForm();
    fireEvent.change(within(form).getByLabelText('Modo de cifragem'), {
      target: { value: 'zero_knowledge' },
    });
    fireEvent.click(within(form).getByLabelText('Plano de recuperação com chave repartida'));
    fireEvent.change(within(form).getByLabelText('Rótulos públicos dos custodiantes'), {
      target: { value: 'Jurídico, Segurança' },
    });
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar política' }));

    // Three shares were declared but only two labels supplied — refused in the client.
    expect(
      await screen.findByText(
        'Recovery needs at least two shares and one public label per custodian',
      ),
    ).toBeTruthy();
    expect(calls.some((call) => call.method === 'PUT')).toBe(false);
  });

  it('sends the public split-recovery plan once the labels match the share count', async () => {
    const calls = stubFetch({
      override: (call) => (call.method === 'PUT' ? jsonResponse(TENANT_POLICY) : null),
    });
    renderRepositories();

    const form = await tenantPolicyForm();
    fireEvent.change(within(form).getByLabelText('Modo de cifragem'), {
      target: { value: 'zero_knowledge' },
    });
    fireEvent.click(within(form).getByLabelText('Plano de recuperação com chave repartida'));
    fireEvent.change(within(form).getByLabelText('Rótulos públicos dos custodiantes'), {
      target: { value: 'Jurídico, Segurança, Continuidade' },
    });
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar política' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PUT')).toBe(true));
    expect(calls.find((call) => call.method === 'PUT')?.body).toMatchObject({
      encryption_mode: 'zero_knowledge',
      custody: {
        bring_your_own_key: true,
        split_key_recovery: {
          threshold: 2,
          share_count: 3,
          custodian_labels: ['Continuidade', 'Jurídico', 'Segurança'],
        },
      },
    });
  });

  it('carries every custody choice the operator made into the saved policy', async () => {
    const calls = stubFetch({
      override: (call) => (call.method === 'PUT' ? jsonResponse(TENANT_POLICY) : null),
    });
    renderRepositories();

    const form = await tenantPolicyForm();
    fireEvent.change(within(form).getByLabelText('Modo de cifragem'), {
      target: { value: 'zero_knowledge' },
    });
    fireEvent.click(within(form).getByLabelText('Chave trazida pelo cliente (BYOK)'));
    fireEvent.click(within(form).getByLabelText('Desbloqueio WebAuthn PRF planeado'));
    fireEvent.click(within(form).getByLabelText('Plano de recuperação com chave repartida'));
    fireEvent.change(within(form).getByLabelText('Limiar necessário'), { target: { value: '3' } });
    fireEvent.change(within(form).getByLabelText('Número de partes'), { target: { value: '4' } });
    fireEvent.change(within(form).getByLabelText('Rótulos públicos dos custodiantes'), {
      target: { value: 'A, B, C, D' },
    });
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar política' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PUT')).toBe(true));
    expect(calls.find((call) => call.method === 'PUT')?.body).toMatchObject({
      custody: {
        bring_your_own_key: false,
        webauthn_prf_unsealing: true,
        split_key_recovery: {
          threshold: 3,
          share_count: 4,
          custodian_labels: ['A', 'B', 'C', 'D'],
        },
      },
    });
  });

  it('reports a rejected policy save from the server', async () => {
    stubFetch({
      override: (call) =>
        call.method === 'PUT' ? jsonResponse({ error: 'Política bloqueada' }, 409) : null,
    });
    renderRepositories();

    const form = await tenantPolicyForm();
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar política' }));

    expect(await screen.findByText('Política bloqueada')).toBeTruthy();
  });
});

describe('CreateRepository', () => {
  it('hides the per-repository policy fields when the repository inherits the tenant policy', async () => {
    const calls = stubFetch({
      override: (call) =>
        call.method === 'POST' && call.url.endsWith(`/tenants/${TENANT}/repositories`)
          ? jsonResponse(repository())
          : null,
    });
    renderRepositories();

    const name = (await screen.findByLabelText('Nome')) as HTMLInputElement;
    fireEvent.change(name, { target: { value: '  Arquivo novo  ' } });
    fireEvent.click(screen.getByLabelText('Herdar política da organização'));
    expect(
      screen.queryByLabelText('Modo de cifragem', { selector: '#operations-repository-mode' }),
    ).toBeNull();

    const create = screen.getByRole('button', { name: /Criar repositório/ });
    expect(create.hasAttribute('disabled')).toBe(true);
    fireEvent.click(within(name.closest('form') as HTMLFormElement).getByLabelText(GDPR_ACK));
    fireEvent.click(create);

    await waitFor(() => expect(calls.some((call) => call.method === 'POST')).toBe(true));
    expect(calls.find((call) => call.method === 'POST')?.body).toEqual({
      name: 'Arquivo novo',
      inherit_tenant_policy: true,
    });
    await waitFor(() => expect(name.value).toBe(''));
  });

  it('creates a zero-knowledge repository with its own custody policy', async () => {
    const calls = stubFetch({
      override: (call) =>
        call.method === 'POST' && call.url.endsWith(`/tenants/${TENANT}/repositories`)
          ? jsonResponse(ZK_REPOSITORY)
          : null,
    });
    renderRepositories();

    const name = (await screen.findByLabelText('Nome')) as HTMLInputElement;
    const form = name.closest('form') as HTMLFormElement;
    fireEvent.change(name, { target: { value: 'Arquivo ZK' } });
    fireEvent.change(within(form).getByLabelText('Modo de cifragem'), {
      target: { value: 'zero_knowledge' },
    });
    fireEvent.click(within(form).getByLabelText('Desbloqueio WebAuthn PRF planeado'));
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: /Criar repositório/ }));

    await waitFor(() => expect(calls.some((call) => call.method === 'POST')).toBe(true));
    expect(calls.find((call) => call.method === 'POST')?.body).toEqual({
      name: 'Arquivo ZK',
      inherit_tenant_policy: false,
      encryption_mode: 'zero_knowledge',
      custody: {
        bring_your_own_key: true,
        webauthn_prf_unsealing: true,
        split_key_recovery: null,
      },
      gdpr_obligations_remain: true,
    });
  });

  it('reports a rejected repository creation', async () => {
    stubFetch({
      override: (call) =>
        call.method === 'POST' ? jsonResponse({ error: 'Limite de repositórios' }, 409) : null,
    });
    renderRepositories();

    const name = (await screen.findByLabelText('Nome')) as HTMLInputElement;
    const form = name.closest('form') as HTMLFormElement;
    fireEvent.change(name, { target: { value: 'Arquivo extra' } });
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: /Criar repositório/ }));

    expect(await screen.findByText('Limite de repositórios')).toBeTruthy();
    expect(name.value).toBe('Arquivo extra');
  });
});

describe('repository list', () => {
  it('distinguishes a zero-knowledge repository from a standard one and names the policy source', async () => {
    stubFetch({
      repositories: [repository(), { policy: ZK_REPOSITORY.policy, policy_source: 'tenant' }],
    });
    renderRepositories();

    const rows = await screen.findAllByText('Arquivo principal');
    const standardCells = within(rows[0].closest('tr') as HTMLTableRowElement).getAllByRole('cell');
    expect(standardCells[1].textContent).toBe('Padrão gerido pelo servidor');
    expect(standardCells[2].textContent).toBe('Repositório');

    const zkCells = within(rows[1].closest('tr') as HTMLTableRowElement).getAllByRole('cell');
    expect(zkCells[1].textContent).toBe('Zero knowledge gerido pelo cliente');
    expect(zkCells[2].textContent).toBe('Organização');
  });

  it('shows the empty state when the tenant owns no repository', async () => {
    stubFetch({ repositories: [] });
    renderRepositories();

    expect(await screen.findByText('Ainda não existem repositórios.')).toBeTruthy();
  });

  it('surfaces a failed repository listing', async () => {
    stubFetch({
      override: (call) =>
        call.method === 'GET' && call.url.endsWith(`/tenants/${TENANT}/repositories`)
          ? jsonResponse({ error: 'Repositórios indisponíveis' }, 503)
          : null,
    });
    renderRepositories();

    expect(await screen.findByText('Repositórios indisponíveis')).toBeTruthy();
  });

  it('opening a repository deep-links it and drops a stale object selection', async () => {
    stubFetch({ repositories: [repository()] });
    renderRepositories(['/operacoes?view=repositories&object=object-9:1']);

    const row = (await screen.findByText('Arquivo principal')).closest('tr') as HTMLTableRowElement;
    fireEvent.click(within(row).getByRole('button', { name: 'Abrir' }));

    await waitFor(() =>
      expect(screen.getByTestId('search').textContent).toBe('view=repositories&repository=repo-1'),
    );
  });
});

describe('RepositoryDetail', () => {
  it('explains that opaque object operations need zero knowledge on a standard repository', async () => {
    stubFetch({ repositories: [repository()] });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    expect(await screen.findByText('Operações opacas indisponíveis')).toBeTruthy();
    expect(screen.queryByText('Cifrar e carregar objeto')).toBeNull();
  });

  it('deletes the repository through its own action', async () => {
    const calls = stubFetch({ repositories: [repository()] });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    fireEvent.click(await screen.findByRole('button', { name: /Eliminar repositório/ }));

    await waitFor(() =>
      expect(
        calls.some((call) => call.method === 'DELETE' && call.url.endsWith('/repositories/repo-1')),
      ).toBe(true),
    );
  });

  it('switches a repository to its own zero-knowledge policy', async () => {
    const calls = stubFetch({
      repositories: [repository()],
      override: (call) => (call.method === 'PATCH' ? jsonResponse(ZK_REPOSITORY) : null),
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    const name = await screen.findByLabelText('Nome', {
      selector: '#operations-repository-edit-name',
    });
    const form = name.closest('form') as HTMLFormElement;
    fireEvent.change(
      within(form).getByLabelText('Modo de cifragem', {
        selector: '#operations-repository-edit-mode',
      }),
      { target: { value: 'zero_knowledge' } },
    );
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar' }));

    await waitFor(() => expect(calls.some((call) => call.method === 'PATCH')).toBe(true));
    expect(calls.find((call) => call.method === 'PATCH')?.body).toMatchObject({
      inherit_tenant_policy: false,
      encryption_mode: 'zero_knowledge',
      custody: { bring_your_own_key: true },
    });
  });

  it('reports a rejected repository patch without discarding the edited name', async () => {
    stubFetch({
      repositories: [repository()],
      override: (call) =>
        call.method === 'PATCH' ? jsonResponse({ error: 'Modo imutável' }, 409) : null,
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    const name = (await screen.findByLabelText('Nome', {
      selector: '#operations-repository-edit-name',
    })) as HTMLInputElement;
    fireEvent.change(name, { target: { value: 'Arquivo renomeado' } });
    const form = name.closest('form') as HTMLFormElement;
    fireEvent.click(within(form).getByLabelText(GDPR_ACK));
    fireEvent.click(within(form).getByRole('button', { name: 'Guardar' }));

    expect(await screen.findByText('Modo imutável')).toBeTruthy();
    expect(name.value).toBe('Arquivo renomeado');
  });
});

describe('ZkObjects', () => {
  it('lists opaque versions with their ciphertext size and opens one', async () => {
    const { view } = await encryptedObject('pacote de preservação');
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [view] });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    const row = (await screen.findByText('object-1')).closest('tr') as HTMLTableRowElement;
    const cells = within(row).getAllByRole('cell');
    expect(cells[1].textContent).toBe('1');
    expect(cells[2].textContent).toBe(String(view.manifest.ciphertext_len));

    fireEvent.click(within(row).getByRole('button', { name: 'Abrir' }));
    expect(await screen.findByRole('heading', { name: 'Objeto opaco' })).toBeTruthy();
  });

  it('shows the empty state when a zero-knowledge repository holds no objects yet', async () => {
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [] });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    expect(await screen.findByText('Ainda não existem objetos neste repositório.')).toBeTruthy();
  });

  it('surfaces a failed object listing', async () => {
    stubFetch({
      repositories: [ZK_REPOSITORY],
      override: (call) =>
        call.method === 'GET' && call.url.endsWith('/objects')
          ? jsonResponse({ error: 'Objetos indisponíveis' }, 503)
          : null,
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    expect(await screen.findByText('Objetos indisponíveis')).toBeTruthy();
  });

  it('refuses an unusable client key in the browser, before any upload is attempted', async () => {
    const calls = stubFetch({ repositories: [ZK_REPOSITORY], objects: [] });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    const fileInput = (await screen.findByLabelText('Pacote de preservação')) as HTMLInputElement;
    attachFile(fileInput, 'conteudo do arquivo');
    fireEvent.change(
      screen.getByLabelText('Chave BYOK de 32 bytes em base64', {
        selector: '#operations-zk-byok',
      }),
      { target: { value: bytesToBase64(new Uint8Array(31)) } },
    );
    expect(screen.getByRole('button', { name: 'Cifrar e carregar' }).hasAttribute('disabled')).toBe(
      false,
    );
    fireEvent.submit(fileInput.closest('form') as HTMLFormElement);

    expect(await screen.findByText('The client key must decode to exactly 32 bytes')).toBeTruthy();
    expect(calls.some((call) => call.url.endsWith('/uploads'))).toBe(false);
  });

  it('reports a rejected upload from the server', async () => {
    stubFetch({
      repositories: [ZK_REPOSITORY],
      objects: [],
      override: (call) =>
        call.url.endsWith('/uploads') ? jsonResponse({ error: 'Versão já existe' }, 409) : null,
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    const fileInput = (await screen.findByLabelText('Pacote de preservação')) as HTMLInputElement;
    attachFile(fileInput, 'conteudo do arquivo');
    fireEvent.change(screen.getByLabelText('ID imutável do objeto'), {
      target: { value: 'object-fixo' },
    });
    fireEvent.change(screen.getByLabelText('Versão'), { target: { value: '2' } });
    fireEvent.change(screen.getByLabelText('Rótulo público do custodiante'), {
      target: { value: 'custodiante-legal' },
    });
    fireEvent.change(
      screen.getByLabelText('Chave BYOK de 32 bytes em base64', {
        selector: '#operations-zk-byok',
      }),
      { target: { value: OBJECT_KEY } },
    );
    fireEvent.submit(fileInput.closest('form') as HTMLFormElement);

    expect(await screen.findByText('Versão já existe')).toBeTruthy();
  });

  it('encrypts locally and never sends the BYOK key or the plaintext to the API', async () => {
    const uploaded: { manifest?: OpaqueBlobManifest; ciphertext?: ArrayBuffer } = {};
    const calls = stubFetch({
      repositories: [ZK_REPOSITORY],
      objects: [],
      override: (call) => {
        if (call.url.endsWith('/uploads')) {
          uploaded.manifest = (call.body as { manifest: OpaqueBlobManifest }).manifest;
          return jsonResponse({
            upload_id: 'upload-1',
            repository_id: 'repo-1',
            object_id: 'object-9',
            version: 1,
            ciphertext_upload_url: '/v1/uploads/upload-1/ciphertext',
            created_at: '2026-07-16T12:00:00Z',
          });
        }
        if (call.url.endsWith('/uploads/upload-1/ciphertext')) {
          return jsonResponse({
            archive_id: 'archive-9',
            tenant_id: TENANT,
            manifest: uploaded.manifest,
            ciphertext_url: '/v1/opaque/object-9',
            committed_at: '2026-07-16T12:00:00Z',
          });
        }
        return null;
      },
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1']);

    const fileInput = (await screen.findByLabelText('Pacote de preservação')) as HTMLInputElement;
    attachFile(fileInput, 'segredo do arquivo');
    const keyField = screen.getByLabelText('Chave BYOK de 32 bytes em base64', {
      selector: '#operations-zk-byok',
    }) as HTMLInputElement;
    fireEvent.change(keyField, { target: { value: OBJECT_KEY } });
    fireEvent.submit(fileInput.closest('form') as HTMLFormElement);

    await waitFor(() => expect(uploaded.manifest).toBeDefined());
    const serialized = JSON.stringify(calls.map((call) => call.body));
    expect(serialized).not.toContain(OBJECT_KEY);
    expect(serialized).not.toContain('segredo do arquivo');
    expect(uploaded.manifest?.wrapped_keys[0]).toMatchObject({
      recipient_kind: 'bring_your_own_key',
      recipient_id: 'primary-custodian',
    });
    // A successful upload rotates the immutable object id and clears the client key.
    await waitFor(() => expect(keyField.value).toBe(''));
  });
});

describe('ZkObjectDetail downloads', () => {
  it('saves the opaque bytes once they match the immutable manifest', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [view], ciphertext });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    fireEvent.click(await screen.findByRole('button', { name: 'Transferir bytes cifrados' }));

    expect(await screen.findByText('Transferência cifrada iniciada.')).toBeTruthy();
    expect(saveFileMock.saveBlobAs).toHaveBeenCalledWith(
      expect.objectContaining({ filename: 'object-1-v1.zk.bin' }),
    );
  });

  it('refuses to save opaque bytes that do not match the manifest digest', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    const tampered = ciphertext.slice(0);
    new Uint8Array(tampered)[0] ^= 0xff;
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [view], ciphertext: tampered });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    fireEvent.click(await screen.findByRole('button', { name: 'Transferir bytes cifrados' }));

    expect(
      await screen.findByText('Os bytes transferidos não correspondem ao manifesto imutável.'),
    ).toBeTruthy();
    expect(saveFileMock.saveBlobAs).not.toHaveBeenCalled();
  });

  it('decrypts locally with the right key and clears it afterwards', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [view], ciphertext });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    const keyField = (await screen.findByLabelText('Chave BYOK de 32 bytes em base64', {
      selector: '#operations-object-byok',
    })) as HTMLInputElement;
    const decrypt = screen.getByRole('button', { name: 'Desencriptar e guardar ZIP' });
    expect(decrypt.hasAttribute('disabled')).toBe(true);

    fireEvent.change(keyField, { target: { value: OBJECT_KEY } });
    fireEvent.click(decrypt);

    expect(
      await screen.findByText('Pacote autenticado, desencriptado e preparado para guardar.'),
    ).toBeTruthy();
    expect(saveFileMock.saveBlobAs).toHaveBeenCalledWith(
      expect.objectContaining({ filename: 'object-1-v1.zip', contentType: 'application/zip' }),
    );
    await waitFor(() => expect(keyField.value).toBe(''));
  });

  it('reports a client key that is not a recipient of the object', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [view], ciphertext });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    fireEvent.change(
      await screen.findByLabelText('Chave BYOK de 32 bytes em base64', {
        selector: '#operations-object-byok',
      }),
      { target: { value: byok(99) } },
    );
    fireEvent.click(screen.getByRole('button', { name: 'Desencriptar e guardar ZIP' }));

    expect(
      await screen.findByText('This client key is not a recipient in the object manifest'),
    ).toBeTruthy();
    expect(saveFileMock.saveBlobAs).not.toHaveBeenCalled();
  });
});

describe('readability package', () => {
  it('offers only books belonging to entities of the current tenant', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    stubFetch({ repositories: [ZK_REPOSITORY], objects: [view], ciphertext });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    const books = (await screen.findByLabelText('Livro associado')) as HTMLSelectElement;
    await waitFor(() => expect(books.options.length).toBe(2));
    expect(Array.from(books.options, (option) => option.value)).toEqual(['', 'book-1']);
  });

  it('swaps to the portable-key fields and keeps the client key out of the request', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    const calls = stubFetch({
      repositories: [ZK_REPOSITORY],
      objects: [view],
      ciphertext,
      override: (call) =>
        call.url.endsWith('/readability-package')
          ? new Response(new Blob(['zip']), {
              headers: { 'Content-Type': 'application/zip' },
            })
          : null,
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    fireEvent.change(await screen.findByLabelText('Modo de entrega'), {
      target: { value: 'encrypted_archive_with_portable_key_package' },
    });
    expect(
      screen.queryByLabelText('Chave BYOK de 32 bytes em base64', {
        selector: '#operations-readability-byok',
      }),
    ).toBeNull();

    fireEvent.change(screen.getByLabelText('Livro associado'), { target: { value: 'book-1' } });
    fireEvent.change(screen.getByLabelText('Pacote de chave portátil JWE'), {
      target: { value: '  jwe-token  ' },
    });
    fireEvent.change(screen.getByLabelText('Instruções para o destinatário'), {
      target: { value: '  Entregar ao notário  ' },
    });
    fireEvent.change(screen.getByLabelText('Palavra-passe para confirmação'), {
      target: { value: 'palavra-passe' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar pacote de legibilidade' }));

    await waitFor(() =>
      expect(calls.some((call) => call.url.endsWith('/readability-package'))).toBe(true),
    );
    expect(calls.find((call) => call.url.endsWith('/readability-package'))?.body).toEqual({
      mode: 'encrypted_archive_with_portable_key_package',
      book_id: 'book-1',
      portable_key_package_jwe: 'jwe-token',
      recipient_instructions: 'Entregar ao notário',
      reauth: { password: 'palavra-passe' },
    });
    expect(
      await screen.findByText('Pacote de legibilidade criado e preparado para guardar.'),
    ).toBeTruthy();
  });

  it('sends a locally decrypted archive with its digest for the decrypted mode', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    const calls = stubFetch({
      repositories: [ZK_REPOSITORY],
      objects: [view],
      ciphertext,
      override: (call) =>
        call.url.endsWith('/readability-package')
          ? new Response(new Blob(['zip']), { headers: { 'Content-Type': 'application/zip' } })
          : null,
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    await screen.findByRole('option', { name: /book-1/ });
    fireEvent.change(screen.getByLabelText('Livro associado'), { target: { value: 'book-1' } });
    fireEvent.change(
      screen.getByLabelText('Chave BYOK de 32 bytes em base64', {
        selector: '#operations-readability-byok',
      }),
      { target: { value: OBJECT_KEY } },
    );
    fireEvent.change(screen.getByLabelText('Palavra-passe para confirmação'), {
      target: { value: 'palavra-passe' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar pacote de legibilidade' }));

    await waitFor(() =>
      expect(calls.some((call) => call.url.endsWith('/readability-package'))).toBe(true),
    );
    const body = calls.find((call) => call.url.endsWith('/readability-package'))?.body as Record<
      string,
      string
    >;
    expect(body.mode).toBe('client_decrypted_archive');
    // The archive travels as the decrypted plaintext, never as the client key.
    const archive = Uint8Array.from(atob(body.archive_base64), (char) => char.charCodeAt(0));
    expect(new TextDecoder().decode(archive)).toBe('pacote de preservação');
    expect(body.archive_sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(body)).not.toContain(OBJECT_KEY);
  });

  it('reports a rejected readability request', async () => {
    const { view, ciphertext } = await encryptedObject('pacote de preservação');
    stubFetch({
      repositories: [ZK_REPOSITORY],
      objects: [view],
      ciphertext,
      override: (call) =>
        call.url.endsWith('/readability-package')
          ? jsonResponse({ error: 'Reautenticação recusada' }, 401)
          : null,
    });
    renderRepositories(['/operacoes?view=repositories&repository=repo-1&object=object-1:1']);

    await screen.findByRole('option', { name: /book-1/ });
    fireEvent.change(screen.getByLabelText('Livro associado'), { target: { value: 'book-1' } });
    fireEvent.change(
      screen.getByLabelText('Chave BYOK de 32 bytes em base64', {
        selector: '#operations-readability-byok',
      }),
      { target: { value: OBJECT_KEY } },
    );
    fireEvent.change(screen.getByLabelText('Palavra-passe para confirmação'), {
      target: { value: 'errada' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar pacote de legibilidade' }));

    // The refusal is rendered by both the mutation's own error and the local action error.
    expect((await screen.findAllByText('Reautenticação recusada')).length).toBeGreaterThan(0);
  });
});

/**
 * Put a file on a file input. jsdom's `File` has no `arrayBuffer()` in this environment, so the
 * bytes are attached explicitly — the component reads them through that method before encrypting.
 */
function attachFile(input: HTMLInputElement, content: string) {
  const bytes = new TextEncoder().encode(content);
  const file = new File([bytes], 'pacote.zip', { type: 'application/zip' });
  Object.defineProperty(file, 'arrayBuffer', {
    value: async () => bytes.buffer,
  });
  Object.defineProperty(input, 'files', { value: [file], configurable: true });
  fireEvent.change(input);
}
