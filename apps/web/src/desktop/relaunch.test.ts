/**
 * Tests for the restart action (t26 crash recovery).
 *
 * The module's own header claims "an ordinary browser build and vitest never resolve it" of the
 * dynamic `import('@tauri-apps/plugin-process')`. That is a claim about *bundling*, not about
 * testability: `vi.mock` virtualises the specifier, so the desktop branch runs here like any other.
 *
 * The behaviour worth pinning is the difference between the two branches, not that they execute.
 * Reloading the document inside the desktop shell would restart the WebView and leave the wedged
 * embedded server process exactly as it was — the failure this action exists to recover from. So
 * inside Tauri the process plugin must be used *instead of* a reload; in a browser there is no
 * process, and a reload is the equivalent fresh start; and if the hand-off ever fails the button
 * must still do something rather than being dead.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

const relaunch = vi.fn().mockResolvedValue(undefined);
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch }));

import { relaunchApp } from './relaunch';

const asRecord = window as unknown as Record<string, unknown>;

/** Replace `window.location` with a spied stand-in — jsdom does not implement `reload()`. */
function stubReload() {
  const reload = vi.fn();
  Object.defineProperty(window, 'location', {
    value: { ...window.location, reload },
    writable: true,
    configurable: true,
  });
  return reload;
}

afterEach(() => {
  delete asRecord.__TAURI_INTERNALS__;
  relaunch.mockClear();
  relaunch.mockResolvedValue(undefined);
  vi.restoreAllMocks();
});

describe('relaunchApp', () => {
  it('tears down the process inside Tauri instead of reloading the document', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    const reload = stubReload();

    await relaunchApp();

    expect(relaunch).toHaveBeenCalledTimes(1);
    // A reload here would restart the WebView and leave the wedged server alive — the exact
    // failure a "restart" is meant to clear.
    expect(reload).not.toHaveBeenCalled();
  });

  it('reloads the document in a plain browser, without reaching for the process plugin', async () => {
    expect('__TAURI_INTERNALS__' in window).toBe(false);
    const reload = stubReload();

    await relaunchApp();

    expect(reload).toHaveBeenCalledTimes(1);
    expect(relaunch).not.toHaveBeenCalled();
  });

  it('falls back to a reload when the desktop hand-off fails, so the button is never dead', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    relaunch.mockRejectedValueOnce(new Error('plugin-process not in the ACL'));
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    const reload = stubReload();

    await relaunchApp();

    expect(relaunch).toHaveBeenCalledTimes(1);
    expect(reload).toHaveBeenCalledTimes(1);
    // And the failure is reported rather than swallowed — a silent downgrade from "restart the
    // process" to "reload the page" would look like the restart worked.
    expect(logged).toHaveBeenCalled();
  });

  it('never throws, so a caller can wire it straight to a click handler', async () => {
    asRecord.__TAURI_INTERNALS__ = {};
    relaunch.mockRejectedValueOnce(new Error('boom'));
    vi.spyOn(console, 'error').mockImplementation(() => {});
    stubReload();

    await expect(relaunchApp()).resolves.toBeUndefined();
  });
});
