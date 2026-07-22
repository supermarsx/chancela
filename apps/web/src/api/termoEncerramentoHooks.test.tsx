/**
 * Client + React Query hook coverage for the two-phase termo de encerramento flow (t44-e4), the CLOSE
 * mirror of `termoHooks.test.tsx`. Asserts the client hits the frozen routes with the right
 * method/body (incl. the real-PAdES `sign/pkcs12` path), that the hooks keep the termo/book caches
 * authoritative, and — the load-bearing one — that BOTH fail-closed `409` causes from `close` (the
 * not-cryptographically-signed refusal and the stale-fact guard) surface as an `ApiError` the UI can
 * render honestly rather than being swallowed.
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ApiError, api } from './client';
import {
  keys,
  useAdvanceBookTermoEncerramento,
  useBookTermoEncerramento,
  useCloseBookFromTermo,
  usePatchBookTermoEncerramento,
  useSignBookTermoEncerramento,
  useSignBookTermoEncerramentoPkcs12,
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
  kind: 'Encerramento',
  state: 'Draft',
  title: 'Termo de encerramento',
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

describe('termo de encerramento client', () => {
  it('hits the frozen two-phase CLOSE routes with the right method and body', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(jsonResponse(termo())));
    vi.stubGlobal('fetch', fetchMock);

    await api.getBookTermoEncerramento('B1');
    await api.patchBookTermoEncerramento('B1', { closing_reason: { Other: { note: 'Fusão' } } });
    await api.advanceBookTermoEncerramento('B1');
    await api.signBookTermoEncerramento('B1', { slot_id: 'S1' });
    await api.signBookTermoEncerramentoPkcs12('B1', {
      slot_id: 'S1',
      pkcs12_base64: 'AAAA',
      passphrase: 'pw',
    });
    await api.closeBookFromTermo('B1');

    const calls = fetchMock.mock.calls;
    expect(calls[0][0]).toBe('/v1/books/B1/termo/encerramento');
    expect(calls[0][1]?.method ?? 'GET').toBe('GET');

    expect(calls[1][0]).toBe('/v1/books/B1/termo/encerramento');
    expect(calls[1][1].method).toBe('PATCH');
    expect(JSON.parse(calls[1][1].body)).toEqual({ closing_reason: { Other: { note: 'Fusão' } } });

    expect(calls[2][0]).toBe('/v1/books/B1/termo/encerramento/advance');
    expect(calls[2][1].method).toBe('POST');

    expect(calls[3][0]).toBe('/v1/books/B1/termo/encerramento/sign');
    expect(JSON.parse(calls[3][1].body)).toEqual({ slot_id: 'S1' });

    expect(calls[4][0]).toBe('/v1/books/B1/termo/encerramento/sign/pkcs12');
    expect(JSON.parse(calls[4][1].body)).toEqual({
      slot_id: 'S1',
      pkcs12_base64: 'AAAA',
      passphrase: 'pw',
    });

    expect(calls[5][0]).toBe('/v1/books/B1/termo/encerramento/close');
    expect(calls[5][1].method).toBe('POST');
    // Empty body default is still a JSON POST (actor defaults server-side).
    expect(JSON.parse(calls[5][1].body)).toEqual({});
  });
});

describe('termo de encerramento hooks', () => {
  it('does not fetch the draft until enabled and a book id is present', () => {
    const { wrapper } = harness();
    const spy = vi.spyOn(api, 'getBookTermoEncerramento').mockResolvedValue(termo());
    renderHook(() => useBookTermoEncerramento('', true), { wrapper });
    renderHook(() => useBookTermoEncerramento('B1', false), { wrapper });
    expect(spy).not.toHaveBeenCalled();
  });

  it('writes the refreshed termo into the cache on patch/advance/sign/pkcs12', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'patchBookTermoEncerramento').mockResolvedValue(termo({ title: 'Editado' }));
    vi.spyOn(api, 'advanceBookTermoEncerramento').mockResolvedValue(termo({ state: 'Signing' }));
    vi.spyOn(api, 'signBookTermoEncerramento').mockResolvedValue(termo({ state: 'Signing' }));
    vi.spyOn(api, 'signBookTermoEncerramentoPkcs12').mockResolvedValue(
      termo({ state: 'Signing', signatories: [] }),
    );

    await mutate(renderHook(() => usePatchBookTermoEncerramento('B1'), { wrapper }).result, {
      title: 'Editado',
    });
    expect(qc.getQueryData<TermoInstrumentView>(keys.bookTermoEncerramento('B1'))?.title).toBe(
      'Editado',
    );

    await mutate(renderHook(() => useAdvanceBookTermoEncerramento('B1'), { wrapper }).result);
    expect(qc.getQueryData<TermoInstrumentView>(keys.bookTermoEncerramento('B1'))?.state).toBe(
      'Signing',
    );

    await mutate(renderHook(() => useSignBookTermoEncerramento('B1'), { wrapper }).result, {
      slot_id: 'S1',
    });
    expect(api.signBookTermoEncerramento).toHaveBeenCalledWith('B1', { slot_id: 'S1' });

    await mutate(renderHook(() => useSignBookTermoEncerramentoPkcs12('B1'), { wrapper }).result, {
      slot_id: 'S1',
      pkcs12_base64: 'AAAA',
      passphrase: 'pw',
    });
    expect(api.signBookTermoEncerramentoPkcs12).toHaveBeenCalledWith('B1', {
      slot_id: 'S1',
      pkcs12_base64: 'AAAA',
      passphrase: 'pw',
    });
  });

  it('moves the book and refetches on a successful close', async () => {
    const { qc, wrapper } = harness();
    const book = { id: 'B1', entity_id: 'E1', state: 'Closed' } as BookView;
    vi.spyOn(api, 'closeBookFromTermo').mockResolvedValue(book);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    await mutate(renderHook(() => useCloseBookFromTermo('B1'), { wrapper }).result);

    expect(qc.getQueryData<BookView>(keys.book('B1'))).toEqual(book);
    const invalidated = invalidate.mock.calls.map((c) => JSON.stringify(c[0]?.queryKey));
    expect(invalidated).toContain(JSON.stringify(['books']));
    expect(invalidated).toContain(JSON.stringify(keys.entity('E1')));
    expect(invalidated).toContain(JSON.stringify(keys.bookTermoEncerramento('B1')));
    expect(invalidated).toContain(JSON.stringify(['ledger']));
  });

  it('surfaces the fail-closed 409 from close as an ApiError, never swallowed', async () => {
    const { wrapper } = harness();
    const conflict = new ApiError(409, {
      error: 'refusing to close the book: the termo is not cryptographically signed.',
    });
    vi.spyOn(api, 'closeBookFromTermo').mockRejectedValue(conflict);

    const { result } = renderHook(() => useCloseBookFromTermo('B1'), { wrapper });
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
