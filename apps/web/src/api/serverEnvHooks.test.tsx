/**
 * t14-e5 — the server-env override client + hooks and the pane's private i18n resolver.
 *
 * Covers the two hooks (`useServerEnv` query, `useUpdateServerEnv` mutation) and the read/write
 * client functions they call, plus the restart-to-apply cache behaviour: the PUT seeds the cache from
 * the fresh response (so `restart_pending` is reflected without a refetch) and a `422` leaves the
 * cache untouched. Also guards the pane's copy contract: `settings.serverEnv.*` now lives in the
 * shared catalogs (the two-locale `serverEnvFallback` hatch is gone), so every shipped locale must
 * carry the whole key set and none may fall back to the English strings.
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api, ApiError } from './client';
import type { ServerEnvResponse } from './types';
import { keys, useServerEnv, useUpdateServerEnv } from './hooks';
import { i18nStore } from '../i18n/store';
import { enUS } from '../i18n/locales/en-US';
import { ptPT } from '../i18n/locales/pt-PT';
import { LOCALE_LOADERS, SHIPPED_LOCALES } from '../i18n/registry';
import type { Catalog, MessageKey } from '../i18n/types';

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
      external_reader: null,
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

const SERVER_ENV_PREFIX = 'settings.serverEnv.';

function serverEnvKeys(catalog: Record<string, string>): string[] {
  return Object.keys(catalog)
    .filter((key) => key.startsWith(SERVER_ENV_PREFIX))
    .sort();
}

describe('server-env pane copy', () => {
  const sourceKeys = serverEnvKeys(enUS);

  it('declares a non-trivial key set in the source catalog', () => {
    expect(sourceKeys.length).toBeGreaterThan(60);
  });

  it('carries the identical key set in every shipped locale', async () => {
    for (const locale of SHIPPED_LOCALES) {
      const catalog: Catalog =
        locale === 'en-US' ? enUS : locale === 'pt-PT' ? ptPT : await LOCALE_LOADERS[locale]!();
      expect(serverEnvKeys(catalog), `${locale} key set`).toEqual(sourceKeys);
    }
  }, 15_000);

  it('never falls back to the English strings in a non-English locale', async () => {
    // The bug this replaced: the pane resolved pt-PT or English and nothing else, so eleven
    // locales rendered it in English. Assert the *variance*, never a specific translated string.
    const probes = [
      'settings.serverEnv.title',
      'settings.serverEnv.intro',
      'settings.serverEnv.restart.title',
      'settings.serverEnv.readOnly.badge',
      'settings.serverEnv.externalReader.note',
      'settings.serverEnv.group.search',
    ] as const satisfies readonly MessageKey[];

    for (const locale of SHIPPED_LOCALES) {
      if (locale === 'en-US' || locale === 'en-GB') continue;
      const catalog: Catalog = locale === 'pt-PT' ? ptPT : await LOCALE_LOADERS[locale]!();
      for (const key of probes) {
        expect(catalog[key], `${locale} ${key} is untranslated English`).not.toBe(enUS[key]);
      }
    }
  }, 15_000);

  it('keeps the {path} placeholder in every locale', async () => {
    for (const locale of SHIPPED_LOCALES) {
      const catalog: Catalog =
        locale === 'en-US' ? enUS : locale === 'pt-PT' ? ptPT : await LOCALE_LOADERS[locale]!();
      expect(catalog['settings.serverEnv.overridesPath'], `${locale}`).toContain('{path}');
    }
  }, 15_000);
});
