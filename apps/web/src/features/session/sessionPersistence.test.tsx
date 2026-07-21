/**
 * "Why do I have to log in again on every refresh?" — the end-to-end behaviour (t51).
 *
 * A reload used to drop the module-held token and land the operator on the sign-in screen as the
 * permission-less system actor. These tests pin the fixed behaviour through the real
 * {@link AuthGate} and the real `useSession` query, against a stub that behaves like the server:
 * `GET /v1/session` resolves the presented `X-Chancela-Session` header and answers
 * `200 { user: null, permissions: [] }` — NOT a 401 — for a token it no longer honours.
 *
 * A reload is modelled by unmounting and rendering again with a fresh QueryClient while the
 * browser's `sessionStorage` persists, which is what a refresh actually does.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';

import { renderWithProviders } from '../../test/utils';
import { AuthGate } from './AuthGate';
import { clearSessionToken, getSessionToken, setSessionToken } from '../../api/session';
import type { PermissionGrant, SessionRoster, UserView } from '../../api/types';

const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

const GRANTS: PermissionGrant[] = [
  { permission: 'entity.read', scope: { kind: 'global' }, source: 'role' },
  { permission: 'book.open', scope: { kind: 'global' }, source: 'role' },
];

const ROSTER: SessionRoster = { onboarding_required: false };

/**
 * A server-shaped stub whose live token set is mutable, so a test can revoke a session the way
 * `DELETE /v1/session` (or an idle/absolute expiry) does and watch the client stop presenting it.
 */
function serverStub(live: Set<string>) {
  const seenSessionHeaders: (string | null)[] = [];

  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const token = headers['X-Chancela-Session'] ?? null;

    const json = (body: unknown, status = 200) =>
      Promise.resolve(
        new Response(body === undefined ? null : JSON.stringify(body), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    if (url.includes('/v1/session/roster')) return json(ROSTER);
    if (url.includes('/v1/users')) {
      if (!token || !live.has(token)) return json({ error: 'sessão requerida' }, 401);
      return json([AMELIA]);
    }
    if (url.includes('/v1/session')) {
      if (method === 'DELETE') {
        if (token) live.delete(token);
        return json(undefined, 204);
      }
      seenSessionHeaders.push(token);
      return token && live.has(token)
        ? json({ user: AMELIA, permissions: GRANTS })
        : json({ user: null, permissions: [] });
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;

  return { fn, seenSessionHeaders };
}

function renderGate() {
  return renderWithProviders(
    <Routes>
      <Route path="/" element={<AuthGate>{<div>APP CHROME</div>}</AuthGate>} />
      <Route path="/welcome" element={<div>WIZARD</div>} />
    </Routes>,
    ['/'],
  );
}

beforeEach(() => {
  window.sessionStorage.clear();
  window.localStorage.clear();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clearSessionToken();
  window.sessionStorage.clear();
  window.localStorage.clear();
});

describe('session survives a refresh', () => {
  it('keeps the operator signed in with the same effective permissions', async () => {
    const live = new Set(['tok-live']);
    const { fn, seenSessionHeaders } = serverStub(live);
    vi.stubGlobal('fetch', fn);

    setSessionToken('tok-live');
    const first = renderGate();
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    first.unmount();

    // The refresh: fresh React tree and a fresh query cache; only the browser store carries over.
    expect(window.sessionStorage.getItem('chancela.session-token')).toBe('tok-live');
    renderGate();

    // Signed in again, with no sign-in form in between — and the SAME token presented, so the
    // server resolves the SAME user and the same grants (the permissions the gate's session read
    // carries, not a re-derived guess).
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    expect(screen.queryByText('Iniciar sessão')).toBeNull();
    expect(seenSessionHeaders.every((header) => header === 'tok-live')).toBe(true);
  });

  it('does not resurrect a session the server has revoked or expired', async () => {
    // A token in storage that the server no longer honours: it answers 200 {user:null}, so the
    // client's 401 path never fires and the token must be dropped explicitly.
    const { fn } = serverStub(new Set());
    vi.stubGlobal('fetch', fn);

    setSessionToken('tok-dead');
    renderGate();

    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
    // …and it is gone from storage, so it is not re-presented on every future reload.
    await waitFor(() => {
      expect(getSessionToken()).toBeNull();
    });
    expect(window.sessionStorage.getItem('chancela.session-token')).toBeNull();
  });

  it('ends decisively on sign-out: server-side revoked and storage cleared', async () => {
    const live = new Set(['tok-bye']);
    const { fn } = serverStub(live);
    vi.stubGlobal('fetch', fn);

    setSessionToken('tok-bye');
    const first = renderGate();
    expect(await screen.findByText('APP CHROME')).toBeTruthy();

    // What `useDeleteSession` does, in order: revoke server-side, then drop the client token.
    await fetch('/v1/session', {
      method: 'DELETE',
      headers: { 'X-Chancela-Session': 'tok-bye' },
    });
    clearSessionToken();
    first.unmount();

    expect(live.has('tok-bye')).toBe(false);
    expect(window.sessionStorage.getItem('chancela.session-token')).toBeNull();

    renderGate();
    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });
});
