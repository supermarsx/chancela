import type { ReactNode } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';
import {
  keys,
  useDeleteTemplateVersion,
  useRenameTemplateVersion,
  useRestoreTemplateVersion,
  useTemplateVersions,
  useUpdateTemplate,
} from './hooks';

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

describe('template version-history hooks', () => {
  it('loads one template history under its stable query key', async () => {
    const response = { history_limit: 25, entries: [] };
    vi.spyOn(api, 'listTemplateVersions').mockResolvedValue(response);
    const { qc, wrapper } = harness();

    const hook = renderHook(() => useTemplateVersions('user-board/v1'), { wrapper });
    await waitFor(() => expect(hook.result.current.data).toEqual(response));

    expect(api.listTemplateVersions).toHaveBeenCalledWith('user-board/v1');
    expect(qc.getQueryData(keys.templateVersions('user-board/v1'))).toEqual(response);
  });

  it('forwards an optional friendly save name without changing unnamed callers', async () => {
    const update = vi.spyOn(api, 'updateTemplate').mockResolvedValue({} as never);
    const { wrapper } = harness();
    const hook = renderHook(() => useUpdateTemplate(), { wrapper });

    await act(async () => {
      await hook.result.current.mutateAsync({
        id: 'user-board/v1',
        rawJson: '{}',
        versionName: 'Before final vote',
      });
    });

    expect(update).toHaveBeenCalledWith('user-board/v1', '{}', 'Before final vote');
  });

  it('invalidates history after rename/delete and all template reads after restore', async () => {
    vi.spyOn(api, 'renameTemplateVersion').mockResolvedValue({} as never);
    vi.spyOn(api, 'deleteTemplateVersion').mockResolvedValue(undefined);
    vi.spyOn(api, 'restoreTemplateVersion').mockResolvedValue({} as never);
    const { qc, wrapper } = harness();
    const invalidate = vi.spyOn(qc, 'invalidateQueries').mockResolvedValue(undefined);
    const rename = renderHook(() => useRenameTemplateVersion('user-board/v1'), { wrapper });
    const remove = renderHook(() => useDeleteTemplateVersion('user-board/v1'), { wrapper });
    const restore = renderHook(() => useRestoreTemplateVersion('user-board/v1'), { wrapper });

    await act(async () => {
      await rename.result.current.mutateAsync({ versionId: 'v2', name: 'Friendly' });
      await remove.result.current.mutateAsync('v1');
      await restore.result.current.mutateAsync('v2');
    });

    expect(invalidate).toHaveBeenNthCalledWith(1, {
      queryKey: keys.templateVersions('user-board/v1'),
    });
    expect(invalidate).toHaveBeenNthCalledWith(2, {
      queryKey: keys.templateVersions('user-board/v1'),
    });
    expect(invalidate).toHaveBeenNthCalledWith(3, { queryKey: ['templates'] });
  });
});
