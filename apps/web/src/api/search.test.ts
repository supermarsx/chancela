import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';

function json(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('full-search API client', () => {
  it('serializes all friendly filters and the opaque cursor exactly once', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      json({
        page: {
          total: 0,
          offset: 100,
          limit: 25,
          has_more: false,
          hits: [],
          facets: { kind: {}, date: {}, entity: {}, book: {}, author: {}, law: {}, status: {} },
        },
        next_cursor: null,
        index: {},
      }),
    );

    await api.search({
      q: 'assembleia geral',
      kinds: ['act', 'law_article'],
      entity_id: 'entity-1',
      book_id: 'book-1',
      act_id: 'act-1',
      author: 'Amélia & Filhos',
      law: 'CSC 63.º',
      status: 'Draft',
      date_from: '2026-01-01',
      date_to: '2026-07-26',
      limit: 25,
      cursor: 'opaque+/=',
    });

    const url = new URL(String(fetchMock.mock.calls[0]?.[0]), 'http://test.invalid');
    expect(url.pathname).toBe('/v1/search');
    expect(Object.fromEntries(url.searchParams)).toEqual({
      q: 'assembleia geral',
      kind: 'act,law_article',
      entity_id: 'entity-1',
      book_id: 'book-1',
      act_id: 'act-1',
      author: 'Amélia & Filhos',
      law: 'CSC 63.º',
      status: 'Draft',
      date_from: '2026-01-01',
      date_to: '2026-07-26',
      limit: '25',
      cursor: 'opaque+/=',
    });
  });

  it('uses the dedicated status and command endpoints without request bodies', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async () => json({ phase: 'idle' }));

    await api.getSearchStatus();
    await api.rebuildSearchIndex();
    await api.pauseSearchIndex();
    await api.resumeSearchIndex();

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/v1/search/status',
      '/v1/search/rebuild',
      '/v1/search/pause',
      '/v1/search/resume',
    ]);
    expect(fetchMock.mock.calls.slice(1).map(([, init]) => init?.method)).toEqual([
      'POST',
      'POST',
      'POST',
    ]);
    expect(fetchMock.mock.calls.slice(1).map(([, init]) => init?.body)).toEqual([
      undefined,
      undefined,
      undefined,
    ]);
  });
});
