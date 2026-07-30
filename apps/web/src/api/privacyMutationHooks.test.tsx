/**
 * The cache contract of the privacy-register mutation hooks.
 *
 * Every surface that writes a privacy record mocks `api/hooks` wholesale, so these hooks' own
 * `onSuccess` bodies had never run. What they do is not incidental plumbing:
 *
 *  - each write seeds the register cache with the row the SERVER returned, so the list shows the
 *    stored record rather than the body that was posted (they differ: the server stamps ids and
 *    `updated_at`, and may normalise fields);
 *  - each write then invalidates its own register, so the seeded row is reconciled against a real
 *    read rather than trusted indefinitely;
 *  - and each write invalidates `['ledger']`, because every one of these appends a ledger event.
 *    A stale ledger after a compliance write is the one failure that matters here: the register
 *    would show the change and the evidence view would not.
 *
 * A create must APPEND rather than replace, and a patch must replace only the row it names — both
 * are asserted against a pre-seeded cache holding a neighbour that must survive.
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api } from './client';
import {
  keys,
  useCreatePrivacyBreachPlaybook,
  useCreatePrivacyDpia,
  useCreatePrivacyProcessor,
  useCreatePrivacyRetentionPolicy,
  useCreatePrivacyTransferControl,
  usePatchPrivacyDpia,
  usePatchPrivacyProcessor,
  usePatchPrivacyRetentionPolicy,
  usePutPrivacyDpiaTemplate,
  useResetPrivacyDpiaTemplate,
} from './hooks';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/**
 * The client as a plain method table. `api`'s per-method signatures make a `keyof`-indexed spy an
 * intractable union for the compiler; what these tests need from it is only "this named method was
 * called, and it resolved with the row the server would return".
 */
const apiMethods = api as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;

function harness() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const invalidated: unknown[][] = [];
  const original = qc.invalidateQueries.bind(qc);
  vi.spyOn(qc, 'invalidateQueries').mockImplementation((filters) => {
    invalidated.push((filters?.queryKey ?? []) as unknown[]);
    return original(filters);
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return { qc, wrapper, invalidated };
}

/** Whether a key with this prefix was invalidated. */
function invalidatedPrefix(invalidated: unknown[][], prefix: readonly unknown[]): boolean {
  return invalidated.some((key) => prefix.every((part, index) => key[index] === part));
}

async function run<Input>(
  result: { current: { mutateAsync: (input: Input) => Promise<unknown> } },
  input: Input,
) {
  await act(async () => {
    await result.current.mutateAsync(input);
  });
}

/** A stand-in register row: only `id` matters to the cache reducers under test. */
const row = <T,>(id: string, extra: Record<string, unknown> = {}) =>
  ({ id, ...extra }) as unknown as T;

/**
 * One table for the five append-on-create registers. Each entry names the hook, the client method
 * it calls, and the cache key it owns — nothing else differs between them, and spelling five
 * near-identical tests out by hand is how one of them ends up asserting the wrong key.
 */
const CREATE_HOOKS = [
  ['processor', useCreatePrivacyProcessor, 'createProcessorRecord', keys.privacyProcessors],
  ['DPIA', useCreatePrivacyDpia, 'createDpiaRecord', keys.privacyDpias],
  [
    'breach playbook',
    useCreatePrivacyBreachPlaybook,
    'createBreachPlaybook',
    keys.privacyBreachPlaybooks,
  ],
  [
    'transfer control',
    useCreatePrivacyTransferControl,
    'createTransferControl',
    keys.privacyTransferControls,
  ],
  [
    'retention policy',
    useCreatePrivacyRetentionPolicy,
    'createRetentionPolicy',
    keys.privacyRetentionPolicies,
  ],
] as const;

describe.each(CREATE_HOOKS)('creating a %s', (_name, hook, method, key) => {
  it('appends the row the SERVER returned and reconciles both the register and the ledger', async () => {
    const { qc, wrapper, invalidated } = harness();
    qc.setQueryData(key, [row('existing')]);
    const stored = row('stored', { name: 'normalizado pelo servidor' });
    const create = vi.spyOn(apiMethods, method).mockResolvedValue(stored);

    const { result } = renderHook(() => hook(), { wrapper });
    await run(result as never, { name: '  como foi escrito  ' } as never);

    // The neighbour survives, and the new row is the stored one — not the posted body.
    expect(qc.getQueryData(key)).toEqual([row('existing'), stored]);
    expect(create.mock.calls[0][0]).toEqual({ name: '  como foi escrito  ' });
    expect(invalidatedPrefix(invalidated, key)).toBe(true);
    // Every privacy write appends a ledger event; a register that refreshed without the ledger
    // would show a change the evidence view does not yet know about.
    expect(invalidatedPrefix(invalidated, ['ledger'])).toBe(true);
  });

  it('leaves the cache untouched when the write fails', async () => {
    const { qc, wrapper, invalidated } = harness();
    qc.setQueryData(key, [row('existing')]);
    vi.spyOn(apiMethods, method).mockRejectedValue(new Error('recusado'));

    const { result } = renderHook(() => hook(), { wrapper });
    await act(async () => {
      await (result.current as { mutateAsync: (input: unknown) => Promise<unknown> })
        .mutateAsync({})
        .catch(() => undefined);
    });

    // A refused write must not leave an optimistic row behind, and must not claim the ledger moved.
    expect(qc.getQueryData(key)).toEqual([row('existing')]);
    expect(invalidatedPrefix(invalidated, ['ledger'])).toBe(false);
  });
});

const PATCH_HOOKS = [
  ['processor', usePatchPrivacyProcessor, 'patchProcessorRecord', keys.privacyProcessors],
  ['DPIA', usePatchPrivacyDpia, 'patchDpiaRecord', keys.privacyDpias],
  [
    'retention policy',
    usePatchPrivacyRetentionPolicy,
    'patchRetentionPolicy',
    keys.privacyRetentionPolicies,
  ],
] as const;

describe.each(PATCH_HOOKS)('patching a %s', (_name, hook, method, key) => {
  it('replaces only the row it names, and refreshes the register and the ledger', async () => {
    const { qc, wrapper, invalidated } = harness();
    qc.setQueryData(key, [row('a', { status: 'draft' }), row('b', { status: 'draft' })]);
    const updated = row('b', { status: 'active' });
    vi.spyOn(apiMethods, method).mockResolvedValue(updated);

    const { result } = renderHook(() => hook(), { wrapper });
    await run(result as never, { id: 'b', body: { status: 'active' } } as never);

    expect(qc.getQueryData(key)).toEqual([row('a', { status: 'draft' }), updated]);
    expect(invalidatedPrefix(invalidated, key)).toBe(true);
    expect(invalidatedPrefix(invalidated, ['ledger'])).toBe(true);
  });

  it('adds nothing when the patched row is not in the cached list', async () => {
    const { qc, wrapper } = harness();
    qc.setQueryData(key, [row('a')]);
    vi.spyOn(apiMethods, method).mockResolvedValue(row('missing'));

    const { result } = renderHook(() => hook(), { wrapper });
    await run(result as never, { id: 'missing', body: {} } as never);

    // The invalidation that follows is what fetches it; inventing a row here would put a record
    // on screen at a position the server never gave it.
    expect(qc.getQueryData(key)).toEqual([row('a')]);
  });
});

describe('the DPIA guidance model', () => {
  it('serves the saved model straight from the write, then reconciles it', async () => {
    const { qc, wrapper, invalidated } = harness();
    const saved = row('privacy-dpia-guidance/v1', { source: 'operator', version: 2 });
    vi.spyOn(api, 'putDpiaTemplate').mockResolvedValue(saved as never);

    const { result } = renderHook(() => usePutPrivacyDpiaTemplate(), { wrapper });
    await run(result as never, { title: 'Modelo interno' } as never);

    expect(qc.getQueryData(keys.privacyDpiaTemplate)).toEqual(saved);
    expect(invalidatedPrefix(invalidated, keys.privacyDpiaTemplate)).toBe(true);
    expect(invalidatedPrefix(invalidated, ['ledger'])).toBe(true);
  });

  it('replaces the cached model with the SHIPPED one on reset, not with an empty value', async () => {
    const { qc, wrapper, invalidated } = harness();
    qc.setQueryData(keys.privacyDpiaTemplate, row('x', { source: 'operator' }));
    const shipped = row('privacy-dpia-guidance/v1', { source: 'shipped', version: 1 });
    vi.spyOn(api, 'resetDpiaTemplate').mockResolvedValue(shipped as never);

    const { result } = renderHook(() => useResetPrivacyDpiaTemplate(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync();
    });

    // Discarding an override does not leave the page with nothing: the shipped model is what it
    // falls back to, and the operator must see it immediately.
    expect(qc.getQueryData(keys.privacyDpiaTemplate)).toEqual(shipped);
    expect(invalidatedPrefix(invalidated, keys.privacyDpiaTemplate)).toBe(true);
    expect(invalidatedPrefix(invalidated, ['ledger'])).toBe(true);
  });
});
