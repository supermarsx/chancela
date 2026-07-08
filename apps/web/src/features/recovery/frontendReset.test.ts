import { afterEach, describe, expect, it, vi } from 'vitest';
import { QueryClient } from '@tanstack/react-query';
import { resetFrontend } from './frontendReset';
import { getSessionToken, setSessionToken } from '../../api/session';

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  sessionStorage.clear();
});

describe('resetFrontend (client-only reset)', () => {
  it('clears storage + session token + query cache and reloads, making NO server call', () => {
    // A stubbed fetch that fails the test if the client-only reset ever touches the network.
    const fetchSpy = vi.fn();
    vi.stubGlobal('fetch', fetchSpy);

    localStorage.setItem('chancela.safeMode', '1');
    sessionStorage.setItem('draft', 'x');
    setSessionToken('a-session-token');

    const qc = new QueryClient();
    qc.setQueryData(['some', 'cached', 'query'], { hello: 'world' });
    const clearSpy = vi.spyOn(qc, 'clear');
    const reload = vi.fn();

    resetFrontend(qc, reload);

    // Local + session storage cleared, in-memory token dropped, query cache cleared, reloaded.
    expect(localStorage.getItem('chancela.safeMode')).toBeNull();
    expect(sessionStorage.getItem('draft')).toBeNull();
    expect(getSessionToken()).toBeNull();
    expect(clearSpy).toHaveBeenCalledTimes(1);
    expect(reload).toHaveBeenCalledTimes(1);

    // The defining property of the frontend reset: it never contacts the server.
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
