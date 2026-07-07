import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { CurrentUserPicker } from './CurrentUserPicker';
import { clearSessionToken } from '../../api/session';
import type { UserView } from '../../api/types';

const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: false,
  has_attestation_key: false,
};

interface Recorded {
  url: string;
  method: string;
  session: string | null;
}

/**
 * A session-aware fetch stub. It records the `X-Chancela-Session` header seen on every
 * request and answers `GET /v1/session` from a mutable "logged-in" flag so the picker's
 * refetch reflects the sign-in/out just as the real in-memory server would.
 */
function sessionFetch(): { fn: typeof fetch; calls: Recorded[] } {
  const calls: Recorded[] = [];
  let signedIn = false;

  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const headers = (init?.headers ?? {}) as Record<string, string>;
    calls.push({ url, method, session: headers['X-Chancela-Session'] ?? null });

    const json = (body: unknown, status = 200) =>
      Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    if (url.includes('/v1/users')) return json([AMELIA]);
    if (url.includes('/v1/session')) {
      if (method === 'POST') {
        signedIn = true;
        return json({ token: 'tok-1', user: AMELIA });
      }
      if (method === 'DELETE') {
        signedIn = false;
        return json(undefined, 204);
      }
      return json({ user: signedIn ? AMELIA : null });
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;

  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clearSessionToken();
});

describe('CurrentUserPicker', () => {
  it('signs in, sends the session header on later requests, and signs out', async () => {
    const { fn, calls } = sessionFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<CurrentUserPicker />);

    // Signed out: the system actor is shown.
    expect(await screen.findByText('api')).toBeTruthy();

    // Open the picker and choose the user.
    fireEvent.click(screen.getByRole('button', { name: /api/i }));
    fireEvent.click(await screen.findByRole('menuitemradio', { name: /Amélia/ }));

    // The picker now reflects the active user.
    expect(await screen.findByText('Amélia Marques')).toBeTruthy();

    // A request made AFTER sign-in carries the session token — the POST that created
    // the session did not (the token did not yet exist), the refetched GET does.
    await waitFor(() => {
      const withHeader = calls.filter((c) => c.session === 'tok-1');
      expect(withHeader.some((c) => c.url.includes('/v1/session') && c.method === 'GET')).toBe(
        true,
      );
    });
    const post = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
    expect(post?.session).toBeNull();

    // Sign out clears the session; the picker falls back to the system actor.
    fireEvent.click(screen.getByRole('button', { name: /api|Amélia/i }));
    fireEvent.click(await screen.findByRole('button', { name: /terminar sessão/i }));

    await waitFor(() => expect(screen.getByText('api')).toBeTruthy());

    // The very last GET /v1/session (after sign-out) carries no session header.
    const sessionGets = calls.filter((c) => c.url.includes('/v1/session') && c.method === 'GET');
    expect(sessionGets[sessionGets.length - 1].session).toBeNull();
  });
});
