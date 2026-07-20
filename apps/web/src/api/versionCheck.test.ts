import { afterEach, describe, expect, it, vi } from 'vitest';
import { UI_VERSION, checkServerVersion } from './versionCheck';

/**
 * Unit tests for the boot-time server/UI version reconciliation. The module is a thin
 * wrapper over `api.health()` that logs a single console warning on skew and is otherwise
 * silent — so we drive it against a stubbed `fetch` and assert the console side effect.
 */
function healthResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('UI_VERSION', () => {
  it('exposes the inlined build version as a non-empty string', () => {
    expect(typeof UI_VERSION).toBe('string');
    expect(UI_VERSION.length).toBeGreaterThan(0);
  });
});

describe('checkServerVersion', () => {
  it('warns once when the server version differs from the UI build', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const serverVersion = `${UI_VERSION}-stale`;
    const fetchMock = vi
      .fn()
      .mockResolvedValue(healthResponse({ status: 'ok', version: serverVersion }));
    vi.stubGlobal('fetch', fetchMock);

    await checkServerVersion();

    // Probes the same-origin health endpoint through the api client.
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('/health');
    expect(warn).toHaveBeenCalledTimes(1);
    const message = String(warn.mock.calls[0][0]);
    expect(message).toContain(serverVersion);
    expect(message).toContain(UI_VERSION);
    expect(message).toContain('[Chancela]');
  });

  it('stays silent when the server version matches the UI build', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchMock = vi
      .fn()
      .mockResolvedValue(healthResponse({ status: 'ok', version: UI_VERSION }));
    vi.stubGlobal('fetch', fetchMock);

    await checkServerVersion();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
  });

  it('stays silent when the health payload carries no version', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchMock = vi.fn().mockResolvedValue(healthResponse({ status: 'ok' }));
    vi.stubGlobal('fetch', fetchMock);

    await checkServerVersion();

    expect(warn).not.toHaveBeenCalled();
  });

  it('treats an empty-string version as "no version" and stays silent', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchMock = vi.fn().mockResolvedValue(healthResponse({ status: 'ok', version: '' }));
    vi.stubGlobal('fetch', fetchMock);

    await checkServerVersion();

    expect(warn).not.toHaveBeenCalled();
  });

  it('swallows a failed health probe without throwing or warning', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchMock = vi.fn().mockRejectedValue(new Error('network down'));
    vi.stubGlobal('fetch', fetchMock);

    await expect(checkServerVersion()).resolves.toBeUndefined();
    expect(warn).not.toHaveBeenCalled();
  });

  it('swallows a non-2xx health response (typed ApiError) without warning', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const fetchMock = vi.fn().mockResolvedValue(healthResponse({ error: 'unavailable' }, 503));
    vi.stubGlobal('fetch', fetchMock);

    await expect(checkServerVersion()).resolves.toBeUndefined();
    expect(warn).not.toHaveBeenCalled();
  });
});
