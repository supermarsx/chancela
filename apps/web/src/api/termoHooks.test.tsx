/**
 * Client + React Query hook coverage for the two-phase termo de abertura flow (t23-e4). Asserts the
 * client hits the frozen routes with the right method/body, that the hooks keep the termo/book caches
 * authoritative, and — the load-bearing one — that the current fail-closed `409` from `open` surfaces
 * as an `ApiError` the UI can render honestly rather than being swallowed.
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiError, api } from './client';
import {
  keys,
  useAdvanceBookTermoAbertura,
  useBookTermoAbertura,
  useOpenBookFromTermo,
  usePatchBookTermoAbertura,
  useSignBookTermoAbertura,
} from './hooks';
import type { BookView, TermoInstrumentView } from './types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

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

const termo = (over: Partial<TermoInstrumentView> = {}): TermoInstrumentView => ({
  id: 'T1',
  book_id: 'B1',
  kind: 'Abertura',
  state: 'Draft',
  title: 'Termo de abertura',
  body: [],
  fields: {},
  signatories: [],
  completion_policy: 'AllRequired',
  completion: {
    policy: 'AllRequired',
    required_slot_count: 0,
    signed_required_slot_count: 0,
    threshold: 0,
    blocking_required_slot_ids: [],
    complete: false,
  },
  created_at: '2026-07-22T00:00:00Z',
  declared_signatories: [],
  ...over,
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('termo de abertura client', () => {
  it('hits the frozen two-phase routes with the right method and body', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse(termo())));
    vi.stubGlobal('fetch', fetchMock);

    await api.getBookTermoAbertura('B1');
    await api.patchBookTermoAbertura('B1', { purpose: 'Livro de atas' });
    await api.advanceBookTermoAbertura('B1');
    await api.signBookTermoAbertura('B1', { slot_id: 'S1' });
    await api.openBookFromTermo('B1');

    const calls = fetchMock.mock.calls;
    expect(calls[0][0]).toBe('/v1/books/B1/termo/abertura');
    expect(calls[0][1]?.method ?? 'GET').toBe('GET');

    expect(calls[1][0]).toBe('/v1/books/B1/termo/abertura');
    expect(calls[1][1].method).toBe('PATCH');
    expect(JSON.parse(calls[1][1].body)).toEqual({ purpose: 'Livro de atas' });

    expect(calls[2][0]).toBe('/v1/books/B1/termo/abertura/advance');
    expect(calls[2][1].method).toBe('POST');

    expect(calls[3][0]).toBe('/v1/books/B1/termo/abertura/sign');
    expect(JSON.parse(calls[3][1].body)).toEqual({ slot_id: 'S1' });

    expect(calls[4][0]).toBe('/v1/books/B1/termo/abertura/open');
    expect(calls[4][1].method).toBe('POST');
    // Empty body default is still a JSON POST (numbering/actor default server-side).
    expect(JSON.parse(calls[4][1].body)).toEqual({});
  });
});

describe('termo de abertura hooks', () => {
  it('does not fetch the draft until enabled and a book id is present', () => {
    const { wrapper } = harness();
    const spy = vi.spyOn(api, 'getBookTermoAbertura').mockResolvedValue(termo());
    renderHook(() => useBookTermoAbertura('', true), { wrapper });
    renderHook(() => useBookTermoAbertura('B1', false), { wrapper });
    expect(spy).not.toHaveBeenCalled();
  });

  it('writes the refreshed termo into the cache on patch/advance/sign', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'patchBookTermoAbertura').mockResolvedValue(termo({ title: 'Editado' }));
    vi.spyOn(api, 'advanceBookTermoAbertura').mockResolvedValue(termo({ state: 'Signing' }));
    vi.spyOn(api, 'signBookTermoAbertura').mockResolvedValue(
      termo({ state: 'Signing', signatories: [] }),
    );

    await mutate(renderHook(() => usePatchBookTermoAbertura('B1'), { wrapper }).result, {
      title: 'Editado',
    });
    expect(qc.getQueryData<TermoInstrumentView>(keys.bookTermoAbertura('B1'))?.title).toBe(
      'Editado',
    );

    await mutate(renderHook(() => useAdvanceBookTermoAbertura('B1'), { wrapper }).result);
    expect(qc.getQueryData<TermoInstrumentView>(keys.bookTermoAbertura('B1'))?.state).toBe(
      'Signing',
    );

    await mutate(renderHook(() => useSignBookTermoAbertura('B1'), { wrapper }).result, {
      slot_id: 'S1',
    });
    expect(api.signBookTermoAbertura).toHaveBeenCalledWith('B1', { slot_id: 'S1' });
  });

  it('moves the book and refetches on a successful open', async () => {
    const { qc, wrapper } = harness();
    const book = { id: 'B1', entity_id: 'E1', state: 'Open' } as BookView;
    vi.spyOn(api, 'openBookFromTermo').mockResolvedValue(book);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    await mutate(renderHook(() => useOpenBookFromTermo('B1'), { wrapper }).result);

    expect(qc.getQueryData<BookView>(keys.book('B1'))).toEqual(book);
    const invalidated = invalidate.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));
    expect(invalidated).toContain(JSON.stringify(['books']));
    expect(invalidated).toContain(JSON.stringify(keys.entity('E1')));
    expect(invalidated).toContain(JSON.stringify(keys.bookTermoAbertura('B1')));
    expect(invalidated).toContain(JSON.stringify(['ledger']));
  });

  it('surfaces the fail-closed 409 from open as an ApiError, never swallowed', async () => {
    const { wrapper } = harness();
    const conflict = new ApiError(409, {
      error: 'refusing to open the book: the termo de abertura is not cryptographically signed.',
    });
    vi.spyOn(api, 'openBookFromTermo').mockRejectedValue(conflict);

    const { result } = renderHook(() => useOpenBookFromTermo('B1'), { wrapper });
    await act(async () => {
      await expect(
        (result.current.mutateAsync as (v?: unknown) => Promise<unknown>)(undefined),
      ).rejects.toBeInstanceOf(ApiError);
    });
    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as ApiError).status).toBe(409);
    expect((result.current.error as ApiError).message).toContain('not cryptographically signed');
  });
});
