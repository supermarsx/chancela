/**
 * AuthGate unit tests (plan t44 §3) — the gate's own branch table, complementing the
 * end-to-end sign-in flows in `session.test.tsx`. Here we exercise the four states the
 * gate resolves into directly:
 *
 *  - the quiet boot screen while the session/roster queries are still in flight;
 *  - the signed-in pass-through to the guarded children (checked first);
 *  - the fresh-install onboarding redirect and the signed-out sign-in surface;
 *  - the roster-fetch-failure retry screen, and that its retry re-drives the roster.
 *
 * The roster is the unauthenticated signed-out signal (never 401s), so the stubs model
 * `GET /v1/session` + `GET /v1/session/roster` without a session token.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { AuthGate } from './AuthGate';
import { clearSessionToken } from '../../api/session';

const AMELIA_ROSTER = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  has_secret: true,
};

const AMELIA_SESSION = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  language: 'auto',
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function renderGate() {
  return renderWithProviders(
    <Routes>
      <Route path="/" element={<AuthGate>{<div>APP CHROME</div>}</AuthGate>} />
      <Route path="/bem-vindo" element={<div>WIZARD</div>} />
    </Routes>,
    ['/'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clearSessionToken();
});

describe('AuthGate', () => {
  it('holds a quiet boot screen while the session/roster queries are still resolving', async () => {
    // Nothing settles → both queries stay pending → the gate shows the loading boot panel
    // instead of flashing sign-in.
    const fn = (() => new Promise<Response>(() => {})) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('A carregar…')).toBeTruthy();
    expect(screen.getByRole('status')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
    expect(screen.queryByText('Iniciar sessão')).toBeNull();
  });

  it('passes through to the guarded children when a user is signed in', async () => {
    // The signed-in branch is checked first: even a never-resolving roster must not bounce
    // the operator out of the app.
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/session/roster')) return new Promise<Response>(() => {});
      if (url.includes('/v1/session'))
        return Promise.resolve(jsonResponse({ user: AMELIA_SESSION }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    expect(screen.queryByText('Iniciar sessão')).toBeNull();
  });

  it('redirects a fresh install (onboarding_required) to the wizard', async () => {
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/session/roster'))
        return Promise.resolve(jsonResponse({ onboarding_required: true, users: [] }));
      if (url.includes('/v1/session')) return Promise.resolve(jsonResponse({ user: null }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('WIZARD')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('shows the sign-in surface when users exist but nobody is signed in', async () => {
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/session/roster'))
        return Promise.resolve(
          jsonResponse({ onboarding_required: false, users: [AMELIA_ROSTER] }),
        );
      if (url.includes('/v1/session')) return Promise.resolve(jsonResponse({ user: null }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    // The typed identifier field, NOT the roster — the sign-in screen never names the
    // instance's accounts to a signed-out visitor (t33).
    expect(screen.getByLabelText('Utilizador')).toBeTruthy();
    expect(screen.queryByText('Amélia Marques')).toBeNull();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('offers a retry when the roster fails to load, and the retry re-drives it into sign-in', async () => {
    // The roster is the authoritative signed-out signal; a failed load must offer a retry
    // rather than a dead app. First roster call 500s, the retry succeeds.
    let rosterCalls = 0;
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (url.includes('/v1/session/roster')) {
        rosterCalls += 1;
        if (rosterCalls === 1) return Promise.resolve(jsonResponse({ error: 'falhou' }, 500));
        return Promise.resolve(
          jsonResponse({ onboarding_required: false, users: [AMELIA_ROSTER] }),
        );
      }
      if (url.includes('/v1/session')) return Promise.resolve(jsonResponse({ user: null }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('Não foi possível carregar a sessão.')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Tentar novamente' }));

    // The successful refetch resolves the signed-out roster → the sign-in surface.
    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    expect(screen.getByLabelText('Utilizador')).toBeTruthy();
    expect(rosterCalls).toBeGreaterThanOrEqual(2);
  });
});
