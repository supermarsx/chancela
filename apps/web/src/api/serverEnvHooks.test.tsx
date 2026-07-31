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
import { SHIPPED_LOCALES } from '../i18n/registry';
import type { Catalog, MessageKey } from '../i18n/types';
import { daDK } from '../i18n/locales/da-DK';
import { deDE } from '../i18n/locales/de-DE';
import { enGB } from '../i18n/locales/en-GB';
import { esES } from '../i18n/locales/es-ES';
import { fiFI } from '../i18n/locales/fi-FI';
import { frFR } from '../i18n/locales/fr-FR';
import { itIT } from '../i18n/locales/it-IT';
import { nlNL } from '../i18n/locales/nl-NL';
import { plPL } from '../i18n/locales/pl-PL';
import { ptBR } from '../i18n/locales/pt-BR';
import { svFI } from '../i18n/locales/sv-FI';
import { svSE } from '../i18n/locales/sv-SE';

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

/**
 * Every shipped catalog, imported STATICALLY.
 *
 * These three specs used to resolve the 12 code-split locales at run time through
 * `LOCALE_LOADERS`, and that made a correctness gate into a load-dependent flake: the first of
 * them spent ~6s of its 15s budget with a warm cache and nothing else running, so under the full
 * suite — 250-odd files competing for transform and import — it timed out. `api/labels.test.ts`
 * and `i18n/catalogLeakGate.test.ts` hit exactly this and solved it exactly this way; the comment
 * in `labels.test.ts` is the record of it ("passed in isolation and timed out at 5s under the full
 * suite, which made a correctness gate into a load-dependent flake"). Static imports make these
 * synchronous, deterministic and effectively free, and the `15_000` budgets go with them.
 *
 * The `SHIPPED_LOCALES` cross-check below is what the loader map gave for free and must not be
 * lost: a locale added to the registry without a line here fails loudly instead of being silently
 * skipped by a loop that never visits it.
 */
const CATALOGS: Record<string, Catalog> = {
  'pt-PT': ptPT,
  'en-US': enUS,
  'en-GB': enGB,
  'pt-BR': ptBR,
  'da-DK': daDK,
  'de-DE': deDE,
  'es-ES': esES,
  'fi-FI': fiFI,
  'fr-FR': frFR,
  'it-IT': itIT,
  'nl-NL': nlNL,
  'pl-PL': plPL,
  'sv-FI': svFI,
  'sv-SE': svSE,
};

describe('server-env pane copy', () => {
  const sourceKeys = serverEnvKeys(enUS);

  it('declares a non-trivial key set in the source catalog', () => {
    expect(sourceKeys.length).toBeGreaterThan(60);
  });

  it('covers every shipped locale, so none is silently skipped', () => {
    // Non-vacuity for the three loops below: they iterate `SHIPPED_LOCALES` and read `CATALOGS`,
    // so a registry entry with no static import here would look up `undefined` rather than fail.
    expect(Object.keys(CATALOGS).sort()).toEqual([...SHIPPED_LOCALES].sort());
  });

  it('carries the identical key set in every shipped locale', () => {
    for (const locale of SHIPPED_LOCALES) {
      expect(serverEnvKeys(CATALOGS[locale]!), `${locale} key set`).toEqual(sourceKeys);
    }
  });

  it('never falls back to the English strings in a non-English locale', () => {
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
      const catalog = CATALOGS[locale]!;
      for (const key of probes) {
        expect(catalog[key], `${locale} ${key} is untranslated English`).not.toBe(enUS[key]);
      }
    }
  });

  it('keeps the {path} placeholder in every locale', () => {
    for (const locale of SHIPPED_LOCALES) {
      expect(CATALOGS[locale]!['settings.serverEnv.overridesPath'], `${locale}`).toContain(
        '{path}',
      );
    }
  });
});
