/**
 * Cache behaviour for the tenant-scoped hook families (company groups, group template libraries,
 * connector targets/jobs, opt-in zero-knowledge repositories), which had no unit coverage at all.
 *
 * Two things are worth stating up front, because they are what these tests actually pin:
 *
 *  - every list-writing `onSuccess` uses a `(current = [])` default so it works against a cold
 *    cache; each is exercised BOTH cold and warm, and the warm case asserts the row is replaced
 *    in place rather than duplicated;
 *  - `updateConnectorJobCaches` writes through `setQueriesData` on the prefix
 *    `['tenants', t, 'connector-jobs']`, which ALSO matches the single-job detail key
 *    `keys.connectorJob(t, jobId)`. The `Array.isArray(current.jobs)` guard is the only thing
 *    stopping a detail entry from being rewritten into a list DTO, so it gets its own test.
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api } from './client';
import {
  keys,
  useAppendGroupTemplateLibraryRevision,
  useArchiveCompanyGroup,
  useArchiveConnectorTarget,
  useArchiveGroupTemplateLibrary,
  useAssignEntityToGroup,
  useCancelConnectorJob,
  useCompanyGroup,
  useCompanyGroups,
  useConnectorJob,
  useConnectorJobs,
  useConnectorTargets,
  useCreateCompanyGroup,
  useCreateConnectorTarget,
  useCreateGroupTemplateLibrary,
  useCreateRepository,
  useCreateZkReadabilityPackage,
  useDeleteRepository,
  useDeleteTenantRepositoryPolicy,
  useGroupDashboard,
  useGroupTemplateLibraries,
  useGroupTemplateLibraryHistory,
  usePatchCompanyGroup,
  usePatchConnectorTarget,
  usePatchGroupTemplateLibrary,
  usePatchRepository,
  useProbeConnectorTarget,
  usePutTenantRepositoryPolicy,
  useRemoveEntityFromGroup,
  useRepositories,
  useRetryConnectorJob,
  useRunConnectorTarget,
  useTenantRepositoryPolicy,
  useUploadZkObject,
  useZkObjectVersions,
} from './hooks';

const TENANT = 'tenant-1';
const GROUP = 'group-1';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function harness() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return { qc, wrapper };
}

async function mutate(result: { current: { mutateAsync: unknown } }, value?: unknown) {
  await act(async () => {
    await (result.current.mutateAsync as (input: unknown) => Promise<unknown>)(value);
  });
}

function group(overrides: Record<string, unknown> = {}) {
  return { id: GROUP, tenant_id: TENANT, name: 'Grupo Encosto', ...overrides };
}

function library(overrides: Record<string, unknown> = {}) {
  return { id: 'lib-1', tenant_id: TENANT, group_id: GROUP, name: 'Modelos', ...overrides };
}

function job(overrides: Record<string, unknown> = {}) {
  return { id: 'job-1', tenant_id: TENANT, status: 'queued', ...overrides };
}

function repository(repositoryId = 'repo-1', overrides: Record<string, unknown> = {}) {
  return {
    policy: { tenant_id: TENANT, repository_id: repositoryId, mode: 'zero_knowledge' },
    ...overrides,
  };
}

describe('tenant-scoped queries stay disabled until every path segment is known', () => {
  it('does not fetch with a missing tenant, group, library or repository id', () => {
    const { wrapper } = harness();
    const spies = {
      listCompanyGroups: vi.spyOn(api, 'listCompanyGroups').mockResolvedValue([] as never),
      getCompanyGroup: vi.spyOn(api, 'getCompanyGroup').mockResolvedValue({} as never),
      getGroupDashboard: vi.spyOn(api, 'getGroupDashboard').mockResolvedValue({} as never),
      listGroupTemplateLibraries: vi
        .spyOn(api, 'listGroupTemplateLibraries')
        .mockResolvedValue([] as never),
      listGroupTemplateLibraryHistory: vi
        .spyOn(api, 'listGroupTemplateLibraryHistory')
        .mockResolvedValue([] as never),
      listConnectorTargets: vi.spyOn(api, 'listConnectorTargets').mockResolvedValue([] as never),
      getConnectorJob: vi.spyOn(api, 'getConnectorJob').mockResolvedValue({} as never),
      getTenantRepositoryPolicy: vi
        .spyOn(api, 'getTenantRepositoryPolicy')
        .mockResolvedValue({} as never),
      listRepositories: vi.spyOn(api, 'listRepositories').mockResolvedValue([] as never),
      listZkObjectVersions: vi.spyOn(api, 'listZkObjectVersions').mockResolvedValue([] as never),
    };

    renderHook(() => useCompanyGroups(''), { wrapper });
    renderHook(() => useCompanyGroup('', GROUP), { wrapper });
    renderHook(() => useCompanyGroup(TENANT, ''), { wrapper });
    renderHook(() => useGroupDashboard(TENANT, ''), { wrapper });
    renderHook(() => useGroupTemplateLibraries('', GROUP), { wrapper });
    renderHook(() => useGroupTemplateLibraryHistory(TENANT, GROUP, ''), { wrapper });
    renderHook(() => useGroupTemplateLibraryHistory(TENANT, '', 'lib-1'), { wrapper });
    renderHook(() => useConnectorTargets(''), { wrapper });
    renderHook(() => useConnectorJob(TENANT, ''), { wrapper });
    renderHook(() => useTenantRepositoryPolicy(''), { wrapper });
    renderHook(() => useRepositories(''), { wrapper });
    renderHook(() => useZkObjectVersions(TENANT, ''), { wrapper });

    for (const [name, spy] of Object.entries(spies)) {
      expect(`${name}: ${spy.mock.calls.length}`).toBe(`${name}: 0`);
    }
  });

  it('fetches once every segment is present, and lists jobs with the default empty filter', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'listCompanyGroups').mockResolvedValue([group()] as never);
    vi.spyOn(api, 'listConnectorJobs').mockResolvedValue({
      jobs: [job()],
      next_before_created_unix_millis: null,
    } as never);

    const groups = renderHook(() => useCompanyGroups(TENANT), { wrapper });
    const jobs = renderHook(() => useConnectorJobs(TENANT), { wrapper });

    await waitFor(() => expect(groups.result.current.data).toEqual([group()]));
    await waitFor(() => expect(jobs.result.current.data?.jobs).toEqual([job()]));
    expect(api.listConnectorJobs).toHaveBeenCalledWith(TENANT, {});
    // The default filter object is part of the cache key, so the list is addressable without it.
    expect(qc.getQueryData(keys.connectorJobs(TENANT))).toBeDefined();
  });
});

describe('company group caches', () => {
  it('appends a created group to a cold cache and to a warm one', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'createCompanyGroup').mockResolvedValue(group() as never);
    const create = renderHook(() => useCreateCompanyGroup(), { wrapper });

    // Cold: no list has been fetched yet — the `(current = [])` default must still produce a list.
    await mutate(create.result, { tenantId: TENANT, body: { name: 'Grupo Encosto' } });
    expect(qc.getQueryData(keys.companyGroups(TENANT))).toEqual([group()]);

    vi.spyOn(api, 'createCompanyGroup').mockResolvedValue(group({ id: 'group-2' }) as never);
    await mutate(create.result, { tenantId: TENANT, body: { name: 'Segundo' } });
    expect(
      (qc.getQueryData<{ id: string }[]>(keys.companyGroups(TENANT)) ?? []).map((g) => g.id),
    ).toEqual([GROUP, 'group-2']);
  });

  it('replaces only the patched group and refreshes its detail cache', async () => {
    const { qc, wrapper } = harness();
    const updated = group({ name: 'Grupo Renomeado' });
    vi.spyOn(api, 'patchCompanyGroup').mockResolvedValue(updated as never);
    qc.setQueryData(keys.companyGroups(TENANT), [group(), group({ id: 'group-2', name: 'Outro' })]);

    await mutate(renderHook(() => usePatchCompanyGroup(), { wrapper }).result, {
      tenantId: TENANT,
      groupId: GROUP,
      body: { name: 'Grupo Renomeado' },
    });

    const list = qc.getQueryData<{ id: string; name: string }[]>(keys.companyGroups(TENANT)) ?? [];
    expect(list).toHaveLength(2);
    expect(list[0].name).toBe('Grupo Renomeado');
    // The non-matching row is left exactly as it was.
    expect(list[1].name).toBe('Outro');
    expect(qc.getQueryData(keys.companyGroup(TENANT, GROUP))).toEqual(updated);
  });

  it('drops the detail cache of an archived group', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'archiveCompanyGroup').mockResolvedValue(undefined as never);
    qc.setQueryData(keys.companyGroup(TENANT, GROUP), group());

    await mutate(renderHook(() => useArchiveCompanyGroup(), { wrapper }).result, {
      tenantId: TENANT,
      groupId: GROUP,
    });

    expect(qc.getQueryData(keys.companyGroup(TENANT, GROUP))).toBeUndefined();
  });

  it('writes the returned entity back for both assign and remove', async () => {
    const { qc, wrapper } = harness();
    const assigned = { id: 'entity-1', name: 'Encosto Estratégico Lda', group_id: GROUP };
    const removed = { id: 'entity-1', name: 'Encosto Estratégico Lda', group_id: null };
    vi.spyOn(api, 'assignEntityToGroup').mockResolvedValue(assigned as never);
    vi.spyOn(api, 'removeEntityFromGroup').mockResolvedValue(removed as never);

    const variables = { tenantId: TENANT, groupId: GROUP, entityId: 'entity-1' };
    await mutate(renderHook(() => useAssignEntityToGroup(), { wrapper }).result, variables);
    expect(qc.getQueryData(keys.entity('entity-1'))).toEqual(assigned);

    await mutate(renderHook(() => useRemoveEntityFromGroup(), { wrapper }).result, variables);
    expect(qc.getQueryData(keys.entity('entity-1'))).toEqual(removed);
  });
});

describe('group template library caches', () => {
  it('appends cold and warm, and patches in place', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'createGroupTemplateLibrary').mockResolvedValue(library() as never);
    const create = renderHook(() => useCreateGroupTemplateLibrary(), { wrapper });
    const key = keys.groupTemplateLibraries(TENANT, GROUP);

    await mutate(create.result, { tenantId: TENANT, groupId: GROUP, body: { name: 'Modelos' } });
    expect(qc.getQueryData(key)).toEqual([library()]);

    vi.spyOn(api, 'createGroupTemplateLibrary').mockResolvedValue(
      library({ id: 'lib-2' }) as never,
    );
    await mutate(create.result, { tenantId: TENANT, groupId: GROUP, body: { name: 'Outros' } });
    expect((qc.getQueryData<{ id: string }[]>(key) ?? []).map((l) => l.id)).toEqual([
      'lib-1',
      'lib-2',
    ]);

    vi.spyOn(api, 'patchGroupTemplateLibrary').mockResolvedValue(
      library({ id: 'lib-2', name: 'Renomeado' }) as never,
    );
    await mutate(renderHook(() => usePatchGroupTemplateLibrary(), { wrapper }).result, {
      tenantId: TENANT,
      groupId: GROUP,
      libraryId: 'lib-2',
      body: { name: 'Renomeado' },
    });
    const list = qc.getQueryData<{ id: string; name: string }[]>(key) ?? [];
    expect(list).toHaveLength(2);
    expect(list.map((l) => l.name)).toEqual(['Modelos', 'Renomeado']);
  });

  it('invalidates the library list and its history when a revision is appended', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'appendGroupTemplateLibraryRevision').mockResolvedValue({
      tenant_id: TENANT,
      group_id: GROUP,
      library_id: 'lib-1',
      revision: 2,
    } as never);
    vi.spyOn(api, 'archiveGroupTemplateLibrary').mockResolvedValue(undefined as never);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    await mutate(renderHook(() => useAppendGroupTemplateLibraryRevision(), { wrapper }).result, {
      tenantId: TENANT,
      groupId: GROUP,
      libraryId: 'lib-1',
      body: {},
    });

    const invalidated = invalidate.mock.calls.map((call) => JSON.stringify(call[0]?.queryKey));
    expect(invalidated).toContain(JSON.stringify(keys.groupTemplateLibraries(TENANT, GROUP)));
    expect(invalidated).toContain(
      JSON.stringify(keys.groupTemplateLibraryHistory(TENANT, GROUP, 'lib-1')),
    );

    invalidate.mockClear();
    await mutate(renderHook(() => useArchiveGroupTemplateLibrary(), { wrapper }).result, {
      tenantId: TENANT,
      groupId: GROUP,
      libraryId: 'lib-1',
    });
    expect(invalidate.mock.calls.map((call) => JSON.stringify(call[0]?.queryKey))).toContain(
      JSON.stringify(keys.groupTemplateLibraries(TENANT, GROUP)),
    );
  });
});

describe('connector targets and durable jobs', () => {
  const target = { id: 'target-1', tenant_id: TENANT, kind: 'sftp', label: 'Arquivo' };

  it('appends a created target cold and warm, and patches only the matching row', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'createConnectorTarget').mockResolvedValue(target as never);
    const create = renderHook(() => useCreateConnectorTarget(), { wrapper });
    const key = keys.connectorTargets(TENANT);

    await mutate(create.result, { tenantId: TENANT, body: { kind: 'sftp' } });
    expect(qc.getQueryData(key)).toEqual([target]);

    vi.spyOn(api, 'createConnectorTarget').mockResolvedValue({
      ...target,
      id: 'target-2',
    } as never);
    await mutate(create.result, { tenantId: TENANT, body: { kind: 'sftp' } });

    vi.spyOn(api, 'patchConnectorTarget').mockResolvedValue({
      ...target,
      id: 'target-2',
      label: 'Arquivo secundário',
    } as never);
    await mutate(renderHook(() => usePatchConnectorTarget(), { wrapper }).result, {
      tenantId: TENANT,
      targetId: 'target-2',
      body: { label: 'Arquivo secundário' },
    });

    const list = qc.getQueryData<{ id: string; label: string }[]>(key) ?? [];
    expect(list.map((t) => t.label)).toEqual(['Arquivo', 'Arquivo secundário']);
  });

  it('does not touch caches when a target is only probed', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'probeConnectorTarget').mockResolvedValue({ reachable: true } as never);
    vi.spyOn(api, 'archiveConnectorTarget').mockResolvedValue(undefined as never);
    qc.setQueryData(keys.connectorTargets(TENANT), [target]);

    await mutate(renderHook(() => useProbeConnectorTarget(), { wrapper }).result, {
      tenantId: TENANT,
      targetId: 'target-1',
    });
    // A probe is a read-only reachability check: the cached target list survives it intact.
    expect(qc.getQueryData(keys.connectorTargets(TENANT))).toEqual([target]);

    const invalidate = vi.spyOn(qc, 'invalidateQueries');
    await mutate(renderHook(() => useArchiveConnectorTarget(), { wrapper }).result, {
      tenantId: TENANT,
      targetId: 'target-1',
    });
    expect(invalidate.mock.calls.map((call) => JSON.stringify(call[0]?.queryKey))).toContain(
      JSON.stringify(keys.connectorTargets(TENANT)),
    );
  });

  it('prepends a newly run job, preserving the existing page cursor', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'runConnectorTarget').mockResolvedValue(job({ id: 'job-new' }) as never);
    const run = renderHook(() => useRunConnectorTarget(), { wrapper });
    const listKey = keys.connectorJobs(TENANT);

    // Cold cache: the list is created with a null cursor rather than `undefined`.
    await mutate(run.result, { tenantId: TENANT, targetId: 'target-1', body: {} });
    expect(qc.getQueryData(listKey)).toEqual({
      jobs: [job({ id: 'job-new' })],
      next_before_created_unix_millis: null,
    });

    qc.setQueryData(listKey, {
      jobs: [job({ id: 'job-old' })],
      next_before_created_unix_millis: 1_700_000_000_000,
    });
    vi.spyOn(api, 'runConnectorTarget').mockResolvedValue(job({ id: 'job-newer' }) as never);
    await mutate(run.result, { tenantId: TENANT, targetId: 'target-1', body: {} });

    const list = qc.getQueryData<{
      jobs: { id: string }[];
      next_before_created_unix_millis: number | null;
    }>(listKey);
    // Newest first, and the pagination cursor is carried over rather than reset.
    expect(list?.jobs.map((j) => j.id)).toEqual(['job-newer', 'job-old']);
    expect(list?.next_before_created_unix_millis).toBe(1_700_000_000_000);
  });

  it('rewrites the job in the paged list and the detail cache, and leaves the detail DTO a job', async () => {
    const { qc, wrapper } = harness();
    const cancelled = job({ status: 'cancelled' });
    vi.spyOn(api, 'cancelConnectorJob').mockResolvedValue(cancelled as never);

    const listKey = keys.connectorJobs(TENANT, { limit: 25 });
    const detailKey = keys.connectorJob(TENANT, 'job-1');
    qc.setQueryData(listKey, {
      jobs: [job(), job({ id: 'job-2' })],
      next_before_created_unix_millis: null,
    });
    // The detail key shares the `['tenants', t, 'connector-jobs']` prefix that the list write
    // targets, so it is matched too — and it holds a bare job, not a `{ jobs: [...] }` DTO.
    qc.setQueryData(detailKey, job({ status: 'queued' }));

    await mutate(renderHook(() => useCancelConnectorJob(), { wrapper }).result, {
      tenantId: TENANT,
      jobId: 'job-1',
    });

    const list = qc.getQueryData<{ jobs: { id: string; status: string }[] }>(listKey);
    expect(list?.jobs.map((j) => j.status)).toEqual(['cancelled', 'queued']);
    // The guard held: the detail entry is still a job object, not a list DTO.
    expect(qc.getQueryData(detailKey)).toEqual(cancelled);
    expect(qc.getQueryData<{ jobs?: unknown }>(detailKey)?.jobs).toBeUndefined();
  });

  it('leaves an unrelated tenant’s job list untouched when a job is retried', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'retryConnectorJob').mockResolvedValue(job({ status: 'queued' }) as never);
    const otherTenantKey = keys.connectorJobs('tenant-2');
    const otherList = {
      jobs: [{ id: 'job-1', tenant_id: 'tenant-2', status: 'failed' }],
      next_before_created_unix_millis: null,
    };
    qc.setQueryData(otherTenantKey, otherList);

    await mutate(renderHook(() => useRetryConnectorJob(), { wrapper }).result, {
      tenantId: TENANT,
      jobId: 'job-1',
    });

    // Same job id, different tenant — the write is scoped by tenant, so this must not change.
    expect(qc.getQueryData(otherTenantKey)).toEqual(otherList);
  });
});

describe('zero-knowledge repository caches', () => {
  it('stores and removes the tenant repository policy', async () => {
    const { qc, wrapper } = harness();
    const policy = { tenant_id: TENANT, mode: 'zero_knowledge' };
    vi.spyOn(api, 'putTenantRepositoryPolicy').mockResolvedValue(policy as never);
    vi.spyOn(api, 'deleteTenantRepositoryPolicy').mockResolvedValue(undefined as never);

    await mutate(renderHook(() => usePutTenantRepositoryPolicy(), { wrapper }).result, {
      tenantId: TENANT,
      body: { mode: 'zero_knowledge' },
    });
    expect(qc.getQueryData(keys.tenantRepositoryPolicy(TENANT))).toEqual(policy);

    await mutate(renderHook(() => useDeleteTenantRepositoryPolicy(), { wrapper }).result, TENANT);
    expect(qc.getQueryData(keys.tenantRepositoryPolicy(TENANT))).toBeUndefined();
  });

  it('keys repository writes off the nested policy, not the top level', async () => {
    const { qc, wrapper } = harness();
    const key = keys.repositories(TENANT);
    vi.spyOn(api, 'createRepository').mockResolvedValue(repository('repo-1') as never);
    const create = renderHook(() => useCreateRepository(), { wrapper });

    await mutate(create.result, { tenantId: TENANT, body: {} });
    expect(qc.getQueryData(key)).toEqual([repository('repo-1')]);

    vi.spyOn(api, 'createRepository').mockResolvedValue(repository('repo-2') as never);
    await mutate(create.result, { tenantId: TENANT, body: {} });

    const patched = repository('repo-2', { label: 'Arquivo cifrado' });
    vi.spyOn(api, 'patchRepository').mockResolvedValue(patched as never);
    await mutate(renderHook(() => usePatchRepository(), { wrapper }).result, {
      tenantId: TENANT,
      repositoryId: 'repo-2',
      body: {},
    });

    const list = qc.getQueryData<ReturnType<typeof repository>[]>(key) ?? [];
    expect(list).toHaveLength(2);
    expect(list[0]).toEqual(repository('repo-1'));
    expect(list[1]).toEqual(patched);
  });

  it('invalidates the repository list when a repository is deleted', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'deleteRepository').mockResolvedValue(undefined as never);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    await mutate(renderHook(() => useDeleteRepository(), { wrapper }).result, {
      tenantId: TENANT,
      repositoryId: 'repo-1',
    });

    expect(invalidate.mock.calls.map((call) => JSON.stringify(call[0]?.queryKey))).toContain(
      JSON.stringify(keys.repositories(TENANT)),
    );
  });

  it('commits the ciphertext to the URL the upload registration handed back', async () => {
    const { qc, wrapper } = harness();
    const created = {
      tenant_id: TENANT,
      manifest: { associated_data: { repository_id: 'repo-1' } },
      version: 1,
    };
    vi.spyOn(api, 'createZkObjectUpload').mockResolvedValue({
      ciphertext_upload_url: '/v1/zk/upload/opaque-token',
    } as never);
    const commit = vi.spyOn(api, 'commitZkObjectCiphertext').mockResolvedValue(created as never);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    const ciphertext = new Uint8Array([1, 2, 3]).buffer;
    const manifest = { associated_data: { repository_id: 'repo-1' } };
    await mutate(renderHook(() => useUploadZkObject(), { wrapper }).result, {
      tenantId: TENANT,
      repositoryId: 'repo-1',
      manifest,
      ciphertext,
    });

    expect(api.createZkObjectUpload).toHaveBeenCalledWith(TENANT, 'repo-1', manifest);
    // The opaque URL is threaded from step one to step two — never reconstructed client-side.
    expect(commit).toHaveBeenCalledWith('/v1/zk/upload/opaque-token', ciphertext);
    // The object list is refreshed from the RESPONSE's repository id, not the request's.
    expect(invalidate.mock.calls.map((call) => JSON.stringify(call[0]?.queryKey))).toContain(
      JSON.stringify(keys.zkObjects(TENANT, 'repo-1')),
    );
  });

  it('records a readability package without disturbing the object caches', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'createZkReadabilityPackage').mockResolvedValue({ package_id: 'pkg-1' } as never);
    const objectsKey = keys.zkObjects(TENANT, 'repo-1');
    qc.setQueryData(objectsKey, [{ object_id: 'obj-1', version: 1 }]);

    await mutate(renderHook(() => useCreateZkReadabilityPackage(), { wrapper }).result, {
      tenantId: TENANT,
      repositoryId: 'repo-1',
      objectId: 'obj-1',
      version: 1,
      body: {},
    });

    expect(qc.getQueryData(objectsKey)).toEqual([{ object_id: 'obj-1', version: 1 }]);
    expect(api.createZkReadabilityPackage).toHaveBeenCalledWith(TENANT, 'repo-1', 'obj-1', 1, {});
  });
});
