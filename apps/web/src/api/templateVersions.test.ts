import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from './client';

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('template version-history API contract', () => {
  it('encodes template/version ids and uses the approved methods and bodies', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ history_limit: 25, entries: [] }))
      .mockResolvedValueOnce(json({ id: 'save/1', name: 'Before vote' }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json({ id: 'template/1' }));
    vi.stubGlobal('fetch', fetchMock);

    await api.listTemplateVersions('template/1');
    await api.renameTemplateVersion('template/1', 'save/1', { name: 'Before vote' });
    await api.deleteTemplateVersion('template/1', 'save/1');
    await api.restoreTemplateVersion('template/1', 'save/1');

    expect(fetchMock.mock.calls).toEqual([
      ['/v1/templates/template%2F1/versions', expect.objectContaining({ headers: {} })],
      [
        '/v1/templates/template%2F1/versions/save%2F1',
        expect.objectContaining({
          method: 'PATCH',
          body: JSON.stringify({ name: 'Before vote' }),
        }),
      ],
      [
        '/v1/templates/template%2F1/versions/save%2F1',
        expect.objectContaining({ method: 'DELETE' }),
      ],
      [
        '/v1/templates/template%2F1/versions/save%2F1/restore',
        expect.objectContaining({ method: 'POST' }),
      ],
    ]);
    expect(fetchMock.mock.calls[3]?.[1]?.body).toBeUndefined();
  });

  it('adds an encoded version_name only when the caller supplies one', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(json({ id: 'template/1' })));
    vi.stubGlobal('fetch', fetchMock);

    await api.updateTemplate('template/1', '{}');
    await api.updateTemplate('template/1', '{}', 'Before & after');

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/v1/templates/template%2F1');
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      '/v1/templates/template%2F1?version_name=Before+%26+after',
    );
  });
});
