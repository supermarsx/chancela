import { afterEach, describe, expect, it, vi } from 'vitest';

// The Tauri branch lazily `import('@tauri-apps/plugin-opener')`; stub it so the
// desktop path can be exercised under jsdom without the real IPC bridge.
const openUrl = vi.fn().mockResolvedValue(undefined);
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl }));

import { openExternal } from './openExternal';

const asRecord = window as unknown as Record<string, unknown>;

afterEach(() => {
  delete asRecord.__TAURI_INTERNALS__;
  vi.restoreAllMocks();
  openUrl.mockClear();
});

const URL_ = 'https://registo.example.pt/consulta/certidao';

describe('openExternal', () => {
  it('hands the URL to the opener plugin inside Tauri (no in-app window.open)', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    const winOpen = vi.spyOn(window, 'open').mockReturnValue(null);

    await openExternal(URL_);

    expect(openUrl).toHaveBeenCalledWith(URL_);
    expect(winOpen).not.toHaveBeenCalled();
  });

  it('falls back to a new tab in a plain browser (no Tauri)', async () => {
    expect('__TAURI_INTERNALS__' in window).toBe(false);
    const winOpen = vi.spyOn(window, 'open').mockReturnValue(null);

    await openExternal(URL_);

    expect(winOpen).toHaveBeenCalledWith(URL_, '_blank', 'noopener,noreferrer');
    expect(openUrl).not.toHaveBeenCalled();
  });

  it('falls back to window.open when the opener plugin throws inside Tauri', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    openUrl.mockRejectedValueOnce(new Error('ACL denied'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const winOpen = vi.spyOn(window, 'open').mockReturnValue(null);

    await openExternal(URL_);

    expect(openUrl).toHaveBeenCalledWith(URL_);
    expect(winOpen).toHaveBeenCalledWith(URL_, '_blank', 'noopener,noreferrer');
  });
});
