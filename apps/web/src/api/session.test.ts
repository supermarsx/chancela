/**
 * Session-token persistence (t51).
 *
 * The complaint this answers: a page refresh silently signed the operator out and dropped them to
 * the permission-less system actor. The token now rides tab-scoped `sessionStorage`, so a reload
 * re-presents it — while a closed tab, a sign-out, and a token the server no longer honours all
 * still end the session.
 *
 * A reload is modelled by `vi.resetModules()` + a fresh dynamic import: that is exactly what a
 * refresh does to this module's state, and it is the only way to prove the restore path rather
 * than the setter that happens to still be in memory.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { clearSessionToken, getSessionToken, setSessionToken } from './session';

const STORAGE_KEY = 'chancela.session-token';

/** Re-import the module as a fresh instance — the module-state reset a page reload performs. */
async function afterReload() {
  vi.resetModules();
  return import('./session');
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
});

afterEach(() => {
  vi.resetModules();
  vi.unstubAllGlobals();
  clearSessionToken();
  window.sessionStorage.clear();
  window.localStorage.clear();
});

describe('session token persistence', () => {
  it('survives a reload and is never written to localStorage', async () => {
    setSessionToken('tok-refresh');
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBe('tok-refresh');
    // The one option ruled out up front: a bearer token must never outlive the browser session.
    expect(window.localStorage.getItem(STORAGE_KEY)).toBeNull();
    expect(JSON.stringify(window.localStorage)).not.toContain('tok-refresh');

    const reloaded = await afterReload();
    expect(reloaded.getSessionToken()).toBe('tok-refresh');
  });

  it('sign-out clears the persisted copy, so a reload does not resurrect it', async () => {
    setSessionToken('tok-signout');
    clearSessionToken();

    expect(getSessionToken()).toBeNull();
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();

    const reloaded = await afterReload();
    expect(reloaded.getSessionToken()).toBeNull();
  });

  it('fires the cleared listeners when the token is dropped, so the 401 path is unchanged', async () => {
    const {
      setSessionToken: set,
      clearSessionToken: clear,
      onSessionCleared,
    } = await afterReload();
    let fired = 0;
    const off = onSessionCleared(() => {
      fired += 1;
    });
    set('tok-listener');
    clear();
    off();
    expect(fired).toBe(1);
    expect(window.sessionStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it('ignores a blank persisted value rather than presenting an empty token', async () => {
    window.sessionStorage.setItem(STORAGE_KEY, '   ');
    const reloaded = await afterReload();
    expect(reloaded.getSessionToken()).toBeNull();
  });

  it('degrades to memory-only when storage is unavailable instead of failing to boot', async () => {
    const denied: Storage = {
      get length() {
        return 0;
      },
      clear: () => {
        throw new Error('denied');
      },
      getItem: () => {
        throw new Error('denied');
      },
      key: () => {
        throw new Error('denied');
      },
      removeItem: () => {
        throw new Error('denied');
      },
      setItem: () => {
        throw new Error('denied');
      },
    };
    vi.stubGlobal('sessionStorage', denied);

    const reloaded = await afterReload();
    expect(reloaded.getSessionToken()).toBeNull();
    // Setting still works for the life of this page load; only persistence is lost.
    expect(() => reloaded.setSessionToken('tok-denied')).not.toThrow();
    expect(reloaded.getSessionToken()).toBe('tok-denied');
    expect(() => reloaded.clearSessionToken()).not.toThrow();
    expect(reloaded.getSessionToken()).toBeNull();
  });
});
