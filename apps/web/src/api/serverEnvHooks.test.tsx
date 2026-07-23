/**
 * t14-e5 — the server-env override client + hooks and the pane's private i18n resolver.
 *
 * Covers the two hooks (`useServerEnv` query, `useUpdateServerEnv` mutation) and the read/write
 * client functions they call, plus the restart-to-apply cache behaviour: the PUT seeds the cache from
 * the fresh response (so `restart_pending` is reflected without a refetch) and a `422` leaves the
 * cache untouched. Also checks the locale split of `serverEnvFallback` — pt-PT source, English
 * fallback for every other locale — the pattern the catalog spread would otherwise provide.
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api, ApiError } from './client';
import type { ServerEnvResponse } from './types';
import { keys, useServerEnv, useUpdateServerEnv } from './hooks';
import { i18nStore } from '../i18n/store';
import { serverEnvEnglish, serverEnvPtPT, useServerEnvT } from '../i18n/serverEnvFallback';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  i18nStore.setActiveLocale('pt-PT');
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

const RESPONSE: ServerEnvResponse = {
  vars: [
    {
      name: 'CHANCELA_LOG',
      group: 'logging',
      tier: 'A',
      editable: true,
      secret: false,
      boundary: false,
      narrow_only: false,
      acknowledgement_required: false,
      excluded_typed_slice: null,
      source: 'override',
      configured: true,
      effective_value: 'info',
      override_value: 'debug',
      default_value: 'info',
      restart_pending: true,
      validator: { kind: 'free_text', allowed: null },
    },
  ],
  restart_pending: true,
  overrides_path: '/var/lib/chancela/env-overrides.json',
  generated_at: '2026-07-22T10:15:00Z',
};

describe('server-env client + hooks', () => {
  it('reads the registry through GET /v1/platform/env', async () => {
    const { wrapper } = harness();
    const get = vi.spyOn(api, 'getServerEnv').mockResolvedValue(RESPONSE);

    const { result } = renderHook(() => useServerEnv(), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(get).toHaveBeenCalledTimes(1);
    expect(result.current.data?.restart_pending).toBe(true);
    expect(result.current.data?.vars[0]?.source).toBe('override');
  });

  it('sends the complete desired set + acknowledge and seeds the cache from the fresh response', async () => {
    const { qc, wrapper } = harness();
    const put = vi.spyOn(api, 'updateServerEnv').mockResolvedValue(RESPONSE);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    const { result } = renderHook(() => useUpdateServerEnv(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({
        overrides: { CHANCELA_LOG: 'debug' },
        acknowledge: [],
      });
    });

    expect(put).toHaveBeenCalledWith({ overrides: { CHANCELA_LOG: 'debug' }, acknowledge: [] });
    // The PUT response seeds the cache — the pane sees restart_pending with no refetch.
    expect(qc.getQueryData<ServerEnvResponse>(keys.serverEnv)?.restart_pending).toBe(true);
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['ledger'] });
  });

  it('surfaces a 422 as an ApiError and leaves the cache untouched', async () => {
    const { qc, wrapper } = harness();
    qc.setQueryData(keys.serverEnv, RESPONSE);
    vi.spyOn(api, 'updateServerEnv').mockRejectedValue(
      new ApiError(422, {
        error: 'acknowledgement required',
        field: 'CHANCELA_RATE_LIMIT_ENABLED',
      }),
    );

    const { result } = renderHook(() => useUpdateServerEnv(), { wrapper });
    await expect(
      act(async () => {
        await result.current.mutateAsync({
          overrides: { CHANCELA_RATE_LIMIT_ENABLED: 'false' },
          acknowledge: [],
        });
      }),
    ).rejects.toMatchObject({ status: 422 });

    // The failed write must not have mutated the authoritative cache.
    expect(qc.getQueryData<ServerEnvResponse>(keys.serverEnv)).toBe(RESPONSE);
  });
});

describe('server-env pane i18n resolver', () => {
  it('keeps the pt-PT source and English fallback in lockstep on keys', () => {
    expect(Object.keys(serverEnvEnglish).sort()).toEqual(Object.keys(serverEnvPtPT).sort());
  });

  it('serves pt-PT source copy and the English fallback for every other locale', () => {
    i18nStore.setActiveLocale('pt-PT');
    const pt = renderHook(() => useServerEnvT());
    expect(pt.result.current('settings.serverEnv.title')).toBe('Ambiente do servidor');
    cleanup();

    i18nStore.setActiveLocale('en-US');
    const en = renderHook(() => useServerEnvT());
    expect(en.result.current('settings.serverEnv.title')).toBe('Server environment');
  });

  it('interpolates placeholders like the catalog does', () => {
    i18nStore.setActiveLocale('en-US');
    const { result } = renderHook(() => useServerEnvT());
    expect(result.current('settings.serverEnv.overridesPath', { path: '/data/env.json' })).toBe(
      'Overrides are saved in /data/env.json, under the data directory.',
    );
  });
});
