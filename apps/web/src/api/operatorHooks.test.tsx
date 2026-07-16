import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import {
  keys,
  useCancelConnectorJob,
  useCompanyGroups,
  useCreateCompanyGroup,
  useUploadZkObject,
} from './hooks';
import type { ConnectorJobListView, OpaqueBlobManifest } from './types';

function harness() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return { qc, wrapper };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('tenant operator query hooks', () => {
  it('fails closed on an absent tenant and fetches the exact selected tenant once enabled', async () => {
    const { wrapper } = harness();
    const list = vi.spyOn(api, 'listCompanyGroups').mockResolvedValue([]);
    const { rerender } = renderHook(({ tenant }) => useCompanyGroups(tenant), {
      initialProps: { tenant: '' },
      wrapper,
    });
    expect(list).not.toHaveBeenCalled();
    rerender({ tenant: 'tenant-1' });
    await waitFor(() => expect(list).toHaveBeenCalledWith('tenant-1'));
  });

  it('writes a newly created group into its tenant cache and keeps other tenants isolated', async () => {
    const { qc, wrapper } = harness();
    qc.setQueryData(keys.companyGroups('tenant-2'), [{ id: 'other' }]);
    vi.spyOn(api, 'createCompanyGroup').mockResolvedValue({
      id: 'group-1',
      tenant_id: 'tenant-1',
      name: 'Holding',
      created_at: '2026-07-16T00:00:00Z',
      updated_at: '2026-07-16T00:00:00Z',
      member_count: 0,
      template_library_count: 0,
    });
    const hook = renderHook(() => useCreateCompanyGroup(), { wrapper });
    await act(async () => {
      await hook.result.current.mutateAsync({ tenantId: 'tenant-1', body: { name: 'Holding' } });
    });
    expect(qc.getQueryData(keys.companyGroups('tenant-1'))).toEqual([
      expect.objectContaining({ id: 'group-1', tenant_id: 'tenant-1' }),
    ]);
    expect(qc.getQueryData(keys.companyGroups('tenant-2'))).toEqual([{ id: 'other' }]);
  });

  it('registers a manifest before sending opaque bytes and refreshes the immutable object list', async () => {
    const { qc, wrapper } = harness();
    const manifest = {
      schema_version: 1,
      associated_data: { repository_id: 'repository-1', object_id: 'object-1', version: 1 },
      algorithm: 'aes256_gcm',
      nonce_base64: 'AAAAAAAAAAAAAAAA',
      ciphertext_sha256: 'a'.repeat(64),
      ciphertext_len: 3,
      encrypted_metadata: null,
      wrapped_keys: [],
      created_at: '2026-07-16T00:00:00Z',
    } satisfies OpaqueBlobManifest;
    const pending = vi.spyOn(api, 'createZkObjectUpload').mockResolvedValue({
      upload_id: 'upload-1',
      repository_id: 'repository-1',
      object_id: 'object-1',
      version: 1,
      ciphertext_upload_url: '/opaque-upload',
      created_at: '2026-07-16T00:00:00Z',
    });
    const commit = vi.spyOn(api, 'commitZkObjectCiphertext').mockResolvedValue({
      archive_id: 'archive-1',
      tenant_id: 'tenant-1',
      manifest,
      ciphertext_url: '/opaque-ciphertext',
      committed_at: '2026-07-16T00:00:00Z',
    });
    const invalidate = vi.spyOn(qc, 'invalidateQueries');
    const ciphertext = Uint8Array.from([1, 2, 3]).buffer;
    const hook = renderHook(() => useUploadZkObject(), { wrapper });
    await act(async () => {
      await hook.result.current.mutateAsync({
        tenantId: 'tenant-1',
        repositoryId: 'repository-1',
        manifest,
        ciphertext,
      });
    });
    expect(pending).toHaveBeenCalledWith('tenant-1', 'repository-1', manifest);
    expect(commit).toHaveBeenCalledWith('/opaque-upload', ciphertext);
    expect(pending.mock.invocationCallOrder[0]).toBeLessThan(commit.mock.invocationCallOrder[0]!);
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: keys.zkObjects('tenant-1', 'repository-1'),
    });
  });

  it('reconciles a cancelled durable job across detail and every paged job cache', async () => {
    const { qc, wrapper } = harness();
    const before = {
      id: 'job-1',
      tenant_id: 'tenant-1',
      target_id: 'target-1',
      repository_id: 'repository-1',
      purpose: 'sync',
      destination: 'records/a.pdf',
      content_type: 'application/pdf',
      source_sha256: 'a'.repeat(64),
      bytes: 3,
      created_unix_millis: 1,
      state: 'queued',
      attempt: 0,
      not_before_unix_millis: null,
      error_class: null,
      detail: 'queued',
      receipt: null,
    } as const;
    const after = { ...before, state: 'cancelled' as const, detail: 'cancelled' };
    qc.setQueryData<ConnectorJobListView>(keys.connectorJobs('tenant-1', { limit: 25 }), {
      jobs: [before],
      next_before_created_unix_millis: null,
    });
    vi.spyOn(api, 'cancelConnectorJob').mockResolvedValue(after);
    const hook = renderHook(() => useCancelConnectorJob(), { wrapper });
    await act(async () => {
      await hook.result.current.mutateAsync({ tenantId: 'tenant-1', jobId: 'job-1' });
    });
    expect(qc.getQueryData(keys.connectorJob('tenant-1', 'job-1'))).toEqual(after);
    expect(
      qc.getQueryData<ConnectorJobListView>(keys.connectorJobs('tenant-1', { limit: 25 }))?.jobs[0]
        ?.state,
    ).toBe('cancelled');
  });
});
