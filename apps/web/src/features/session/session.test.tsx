/**
 * Sign-in + auth-gating tests (plan t44 §3). These exercise the REAL signed-out path via
 * the unauthenticated roster (`GET /v1/session/roster`) — the t43 audit found the old test
 * masked the signed-out `GET /v1/users` 401 by stubbing that endpoint unconditionally.
 * Here `GET /v1/users` is session-gated (401 without a header), the roster drives the
 * signed-out surfaces, and the picker is exercised only while signed in.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { AuthGate } from './AuthGate';
import { CurrentUserPicker } from './CurrentUserPicker';
import { clearSessionToken, setSessionToken } from '../../api/session';
import type { RosterUser, SessionRoster, UserView } from '../../api/types';

const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: false,
  has_attestation_key: false,
  has_recovery_phrase: false,
};
const BRUNO_ROSTER: RosterUser = {
  id: 'u2',
  username: 'bruno.dias',
  display_name: 'Bruno Dias',
  has_secret: true,
};
const BRUNO: UserView = {
  id: 'u2',
  username: 'bruno.dias',
  display_name: 'Bruno Dias',
  created_at: '2026-07-07T12:05:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
};

interface Recorded {
  url: string;
  method: string;
  session: string | null;
  body: Record<string, unknown> | null;
}

/**
 * A server-shaped stub. `GET /v1/session/roster` is unauthenticated; `GET /v1/session`
 * reflects a mutable "signed-in" flag; `POST /v1/session` mints a token (401 for the
 * wrong password); `GET /v1/users` is SESSION-GATED (401 without the header) — the honest
 * behaviour the old test masked.
 */
function serverStub(opts: {
  roster: SessionRoster;
  postUser?: UserView;
  wrongPassword?: string; // if the POST password equals this, answer 401
  users?: UserView[];
  startSignedIn?: boolean;
  // The user `POST /v1/users` returns when created unauthenticated — allowed ONLY while the
  // roster is empty (t41 bootstrap rule). Mirrors the real server: with users present a
  // signed-out create 401s "sessão requerida".
  bootstrapUser?: UserView;
}): { fn: typeof fetch; calls: Recorded[] } {
  const calls: Recorded[] = [];
  let signedIn = opts.startSignedIn ?? false;
  // A `startSignedIn` session begins as Amélia; a POST switches to `postUser`.
  let currentUser: UserView | null = opts.startSignedIn ? AMELIA : null;

  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    calls.push({ url, method, session: headers['X-Chancela-Session'] ?? null, body });

    const json = (b: unknown, status = 200) =>
      Promise.resolve(
        new Response(b === undefined ? '' : JSON.stringify(b), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    if (url.includes('/v1/session/roster')) return json(opts.roster);
    if (url.includes('/v1/users')) {
      // Bootstrap create: `POST /v1/users` is allowed unauthenticated ONLY while the roster
      // is empty; otherwise (like every signed-out mutation) it 401s.
      if (method === 'POST') {
        if (
          !headers['X-Chancela-Session'] &&
          opts.roster.users.length === 0 &&
          opts.bootstrapUser
        ) {
          return json(opts.bootstrapUser, 201);
        }
        if (!headers['X-Chancela-Session']) return json({ error: 'sessão requerida' }, 401);
        return json(opts.bootstrapUser ?? AMELIA, 201);
      }
      if (!headers['X-Chancela-Session']) return json({ error: 'sessão requerida' }, 401);
      return json(opts.users ?? [AMELIA]);
    }
    if (url.includes('/v1/session')) {
      if (method === 'POST') {
        if (opts.wrongPassword !== undefined && body?.password === opts.wrongPassword) {
          return json({ error: 'credenciais inválidas' }, 401);
        }
        signedIn = true;
        currentUser = opts.postUser ?? AMELIA;
        return json({ token: 'tok-1', user: currentUser });
      }
      if (method === 'DELETE') {
        signedIn = false;
        currentUser = null;
        return json(undefined, 204);
      }
      return json({ user: signedIn ? currentUser : null });
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;

  return { fn, calls };
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
  it('redirects a fresh install (onboarding_required) to the wizard', async () => {
    const { fn } = serverStub({ roster: { onboarding_required: true, users: [] } });
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('WIZARD')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('shows the sign-in surface when users exist but nobody is signed in', async () => {
    const { fn } = serverStub({
      roster: { onboarding_required: false, users: [{ ...AMELIA }, BRUNO_ROSTER] },
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    expect(screen.getByText('Amélia Marques')).toBeTruthy();
    expect(screen.getByText('Bruno Dias')).toBeTruthy();
    // The gated app chrome is NOT rendered while signed out.
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('a passwordless user signs in with one click and the app chrome appears', async () => {
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false, users: [{ ...AMELIA }] },
      postUser: AMELIA,
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    fireEvent.click(await screen.findByText('Amélia Marques'));

    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    const post = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
    expect(post?.body).toMatchObject({ user_id: 'u1' });
    // No password was sent for a passwordless user.
    expect(post?.body?.password).toBeUndefined();
  });

  it('prompts for a password on a has_secret user and rejects a wrong one (401)', async () => {
    const { fn } = serverStub({
      roster: { onboarding_required: false, users: [BRUNO_ROSTER] },
      postUser: BRUNO,
      wrongPassword: 'nope',
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    fireEvent.click(await screen.findByText('Bruno Dias'));
    // The password prompt appears (no immediate sign-in).
    const pw = await screen.findByLabelText('Palavra-passe');
    fireEvent.change(pw, { target: { value: 'nope' } });
    fireEvent.click(screen.getByRole('button', { name: 'Entrar' }));

    // A 401 renders the inline "wrong password" message, never a raw error / the app.
    expect(await screen.findByText('Palavra-passe incorreta.')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('a correct password signs the has_secret user in', async () => {
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false, users: [BRUNO_ROSTER] },
      postUser: BRUNO,
      wrongPassword: 'nope',
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    fireEvent.click(await screen.findByText('Bruno Dias'));
    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: 'correct-horse' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Entrar' }));

    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    const post = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
    expect(post?.body).toMatchObject({ user_id: 'u2', password: 'correct-horse' });
  });

  it('bootstrap: empty roster → create a user unauthenticated → passwordless sign-in lands in the app', async () => {
    const NEW: UserView = {
      id: 'u9',
      username: 'amelia.marques',
      display_name: 'Amélia Marques',
      created_at: '2026-07-08T09:00:00Z',
      active: true,
      has_secret: false,
      has_attestation_key: false,
      has_recovery_phrase: false,
    };
    const { fn, calls } = serverStub({
      // onboarding_required is false so the AuthGate shows SignIn (not the wizard); the roster
      // is empty, so SignIn offers the genuine bootstrap create.
      roster: { onboarding_required: false, users: [] },
      bootstrapUser: NEW,
      postUser: NEW,
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    // The empty-roster entry screen offers the create affordance (no dead-end).
    fireEvent.click(await screen.findByRole('button', { name: 'Criar novo utilizador' }));
    // Fill the reused UserCreateForm and submit with the bootstrap label.
    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar e entrar' }));

    // The passwordless bootstrap sign-in lands the new operator straight in the app.
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    // `POST /v1/users` went out with NO session header — a genuinely unauthenticated create.
    const postUser = calls.find((c) => c.url.includes('/v1/users') && c.method === 'POST');
    expect(postUser?.session).toBeNull();
    // …then the wizard's passwordless handshake (`POST /v1/session`, no password).
    const postSession = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
    expect(postSession?.body).toMatchObject({ user_id: 'u9' });
    expect(postSession?.body?.password).toBeUndefined();
  });

  it('roster present: "criar novo utilizador" routes back to sign-in — never a raw 401', async () => {
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false, users: [{ ...AMELIA }] },
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    fireEvent.click(await screen.findByRole('button', { name: 'Criar novo utilizador' }));

    // Honest copy explains a session is required — no faked create, no app chrome.
    expect(await screen.findByText('Iniciar sessão primeiro')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
    // Crucially: no signed-out `POST /v1/users` was attempted (it would 401).
    expect(calls.some((c) => c.url.includes('/v1/users') && c.method === 'POST')).toBe(false);

    // The operator is routed back to the sign-in roster, not left at a dead-end.
    fireEvent.click(screen.getByRole('button', { name: 'Voltar ao início de sessão' }));
    expect(await screen.findByText('Amélia Marques')).toBeTruthy();
  });
});

describe('CurrentUserPicker (signed in)', () => {
  it('switches to a has_secret user by prompting for the password', async () => {
    // Start signed in as Amélia; the roster/user list carries a password-protected Bruno.
    setSessionToken('tok-0');
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false, users: [{ ...AMELIA }, BRUNO_ROSTER] },
      users: [AMELIA, BRUNO],
      postUser: BRUNO,
      startSignedIn: true,
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<CurrentUserPicker />);

    // Signed in as Amélia.
    expect(await screen.findByText('Amélia Marques')).toBeTruthy();

    // Open the picker and choose Bruno (has a secret) → a password prompt appears inline.
    fireEvent.click(screen.getByTestId('session-trigger'));
    fireEvent.click(await screen.findByRole('menuitemradio', { name: /Bruno/ }));
    const pw = await screen.findByPlaceholderText('A sua palavra-passe');
    fireEvent.change(pw, { target: { value: 'hunter2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Entrar' }));

    await waitFor(() => {
      const post = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
      expect(post?.body).toMatchObject({ user_id: 'u2', password: 'hunter2' });
    });
    // The picker reflects the newly signed-in user.
    expect(await screen.findByText('Bruno Dias')).toBeTruthy();
  });
});
