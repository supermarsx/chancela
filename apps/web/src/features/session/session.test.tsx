/**
 * Sign-in + auth-gating tests (plan t44 §3, reworked by t33). These exercise the REAL
 * signed-out path via the unauthenticated roster (`GET /v1/session/roster`) — the t43 audit
 * found the old test masked the signed-out `GET /v1/users` 401 by stubbing that endpoint
 * unconditionally. Here `GET /v1/users` is session-gated (401 without a header) and the
 * picker is exercised only while signed in.
 *
 * t33 changed what the sign-in screen may show: the identifier is TYPED and no instance
 * user is ever rendered (rendering them was user enumeration). t33-e2 then closed the
 * endpoint itself — `GET /v1/session/roster` returns `{onboarding_required}` and nothing
 * else, and `POST /v1/session` accepts a `username` it resolves server-side. So the stub
 * below models the real thing: an unknown username and a wrong password come back as the
 * SAME opaque 401, and there is no list anywhere for the client to check against first.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { AuthGate } from './AuthGate';
import { CurrentUserPicker } from './CurrentUserPicker';
import { clearSessionToken, setSessionToken } from '../../api/session';
import { SignIn } from './SignIn';
import type { SessionRoster, UserView } from '../../api/types';

const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
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
 * A server-shaped stub. `GET /v1/session/roster` is unauthenticated and returns only
 * `onboarding_required`; `GET /v1/session` reflects a mutable "signed-in" flag;
 * `POST /v1/session` mints a token, answering the SAME opaque 401 for a wrong password and
 * for a username outside `knownUsernames`; `GET /v1/users` is SESSION-GATED (401 without
 * the header) — the honest behaviour the old test masked.
 */
function serverStub(opts: {
  roster: SessionRoster;
  postUser?: UserView;
  wrongPassword?: string; // if the POST password equals this, answer 401
  // Usernames `POST /v1/session` will resolve. Anything else is the same 401 a wrong
  // password gets — the server-side resolution t33-e2 introduced.
  knownUsernames?: string[];
  users?: UserView[];
  startSignedIn?: boolean;
  // The user `POST /v1/users` returns when created unauthenticated — allowed ONLY while no
  // user exists (t41 bootstrap rule). Mirrors the real server: with users present a
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
          opts.roster.onboarding_required &&
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
        if (typeof body?.password !== 'string' || body.password.length === 0) {
          return json({ error: 'palavra-passe obrigatória' }, 401);
        }
        // One opaque failure for both an unknown username and a wrong password: same
        // status, same wording. This is the property the server guarantees, so the stub
        // must not be more helpful than the real thing.
        const known = opts.knownUsernames ?? [BRUNO.username, AMELIA.username];
        const unknownUser = typeof body?.username === 'string' && !known.includes(body.username);
        if (
          unknownUser ||
          (opts.wrongPassword !== undefined && body?.password === opts.wrongPassword)
        ) {
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
  window.localStorage.clear();
});

/** Type an identifier + password into the sign-in form and submit it. */
async function typeSignIn(identifier: string, secret: string) {
  fireEvent.change(await screen.findByLabelText('Utilizador'), { target: { value: identifier } });
  fireEvent.change(screen.getByLabelText('Palavra-passe'), { target: { value: secret } });
  fireEvent.click(screen.getByRole('button', { name: 'Entrar' }));
}

describe('AuthGate', () => {
  it('redirects a fresh install (onboarding_required) to the wizard', async () => {
    const { fn } = serverStub({ roster: { onboarding_required: true } });
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('WIZARD')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('shows a TYPED sign-in form and never renders the instance roster', async () => {
    const { fn } = serverStub({
      roster: { onboarding_required: false },
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    // THE security property: no account on the instance is named to a signed-out visitor.
    expect(screen.queryByText('Amélia Marques')).toBeNull();
    expect(screen.queryByText('Bruno Dias')).toBeNull();
    expect(screen.queryByText('amelia.marques')).toBeNull();
    expect(screen.queryByText('bruno.dias')).toBeNull();
    // …and nothing on the screen offers a choice of users.
    expect(screen.queryAllByRole('listitem')).toHaveLength(0);
    expect(document.querySelectorAll('select')).toHaveLength(0);

    // The gated app chrome is NOT rendered while signed out.
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('the identifier is a real text input with the autofill attributes password managers need', async () => {
    const { fn } = serverStub({
      roster: { onboarding_required: false },
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    const user = (await screen.findByLabelText('Utilizador')) as HTMLInputElement;
    // Not a disguised <select>: a plain text input the operator types into.
    expect(user.tagName).toBe('INPUT');
    expect(user.type).toBe('text');
    expect(user.name).toBe('username');
    expect(user.getAttribute('autocomplete')).toBe('username');

    const pw = screen.getByLabelText('Palavra-passe') as HTMLInputElement;
    expect(pw.type).toBe('password');
    expect(pw.getAttribute('autocomplete')).toBe('current-password');

    // Typing works with no list of any kind present.
    fireEvent.change(user, { target: { value: 'bruno.dias' } });
    expect(user.value).toBe('bruno.dias');
  });

  it('a typed identifier + correct password signs in', async () => {
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false },
      postUser: BRUNO,
      wrongPassword: 'nope',
    });
    vi.stubGlobal('fetch', fn);

    renderGate();
    await typeSignIn('bruno.dias', 'correct-horse');

    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    const post = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
    // The IDENTIFIER goes to the server, not an id the client looked up locally — there is
    // no roster to look it up in any more.
    expect(post?.body).toEqual({ username: 'bruno.dias', password: 'correct-horse' });
  });

  it('a wrong password and an unknown identifier give the SAME message — no enumeration oracle', async () => {
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false },
      postUser: BRUNO,
      wrongPassword: 'nope',
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    // A real account with the wrong password → 401 → the generic inline message.
    await typeSignIn('bruno.dias', 'nope');
    expect(await screen.findByText('Utilizador ou palavra-passe incorretos.')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();

    // An account that does not exist → the same message, from the same server 401. t33-e2:
    // the request IS sent now (the client has no list to pre-check against), and that is the
    // point — the server answers identically either way, so the attempt is indistinguishable
    // on the wire as well as on screen.
    const before = calls.filter((c) => c.method === 'POST').length;
    await typeSignIn('nao.existe', 'whatever');
    expect(await screen.findByText('Utilizador ou palavra-passe incorretos.')).toBeTruthy();
    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(before + 1);
    expect(posts[posts.length - 1]?.body).toEqual({
      username: 'nao.existe',
      password: 'whatever',
    });
  });

  it('while the sign-in mutation is pending, the action is suppressed and a spinner shows', async () => {
    // A stub whose `POST /v1/session` never settles → the mutation stays pending, so the UI
    // holds in the in-flight state we assert on.
    const roster: SessionRoster = { onboarding_required: false };
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      const json = (b: unknown) =>
        Promise.resolve(
          new Response(JSON.stringify(b), { headers: { 'Content-Type': 'application/json' } }),
        );
      if (url.includes('/v1/session/roster')) return json(roster);
      if (url.includes('/v1/session') && method === 'POST') return new Promise<Response>(() => {});
      if (url.includes('/v1/session')) return json({ user: null });
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderGate();
    await typeSignIn('bruno.dias', 'correct-horse');

    // The pending spinner replaces the submit action.
    expect(await screen.findByRole('status')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Entrar' })).toBeNull();
  });

  it('bootstrap: no user yet → create one with a password → sign-in lands in the app', async () => {
    const NEW: UserView = {
      id: 'u9',
      username: 'amelia.marques',
      display_name: 'Amélia Marques',
      created_at: '2026-07-08T09:00:00Z',
      active: true,
      has_secret: true,
      has_attestation_key: false,
      has_recovery_phrase: false,
    };
    const { fn, calls } = serverStub({
      // t33-e2: "no user exists" is now `onboarding_required` alone — there is no `users: []`
      // to distinguish it from. Rendered directly rather than through the AuthGate, which
      // sends this state to the onboarding wizard; SignIn's bootstrap branch is the
      // no-dead-end fallback for anyone who reaches the sign-in screen anyway.
      roster: { onboarding_required: true },
      bootstrapUser: NEW,
      postUser: NEW,
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SignIn />);

    // The first-run entry screen offers the create affordance (no dead-end).
    fireEvent.click(await screen.findByRole('button', { name: 'Criar novo utilizador' }));
    // Fill the reused UserCreateForm and submit with the bootstrap label.
    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'Str0ng!Vault9' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar e entrar' }));

    // `POST /v1/users` went out with NO session header — a genuinely unauthenticated create.
    await waitFor(() => {
      const postUser = calls.find((c) => c.url.includes('/v1/users') && c.method === 'POST');
      expect(postUser?.session).toBeNull();
      expect(postUser?.body).toMatchObject({
        username: 'amelia.marques',
        password: 'Str0ng!Vault9',
      });
    });
    // …then the password sign-in handshake, which still uses `user_id`: the create response
    // just handed it over, so there is nothing to resolve and no identifier to guess.
    await waitFor(() => {
      const postSession = calls.find((c) => c.url.includes('/v1/session') && c.method === 'POST');
      expect(postSession?.body).toMatchObject({ user_id: 'u9', password: 'Str0ng!Vault9' });
    });
    expect(await screen.findByText('Primeiro utilizador criado. Sessão iniciada.')).toBeTruthy();
  });

  it('roster present: "criar novo utilizador" routes back to sign-in — never a raw 401', async () => {
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false },
    });
    vi.stubGlobal('fetch', fn);

    renderGate();

    fireEvent.click(await screen.findByRole('button', { name: 'Criar novo utilizador' }));

    // Honest copy explains a session is required — no faked create, no app chrome.
    expect(await screen.findByText('Iniciar sessão primeiro')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
    // Crucially: no signed-out `POST /v1/users` was attempted (it would 401).
    expect(calls.some((c) => c.url.includes('/v1/users') && c.method === 'POST')).toBe(false);

    // The operator is routed back to the typed sign-in form, not left at a dead-end.
    fireEvent.click(screen.getByRole('button', { name: 'Voltar ao início de sessão' }));
    expect(await screen.findByLabelText('Utilizador')).toBeTruthy();
  });
});

describe('SignIn — recently used identifiers (device-local)', () => {
  const ROSTER: SessionRoster = { onboarding_required: false };

  it('a SUCCESSFUL sign-in is remembered; a FAILED one is not', async () => {
    const { fn } = serverStub({ roster: ROSTER, postUser: BRUNO, wrongPassword: 'nope' });
    vi.stubGlobal('fetch', fn);

    renderGate();

    // Failure first: recording it would turn the list into an "is this a real username"
    // oracle for anyone with a minute at the keyboard.
    await typeSignIn('bruno.dias', 'nope');
    expect(await screen.findByText('Utilizador ou palavra-passe incorretos.')).toBeTruthy();
    expect(window.localStorage.getItem('chancela.signin.recentAccounts')).toBeNull();

    // …and an unknown identifier is likewise never remembered.
    await typeSignIn('nao.existe', 'whatever');
    expect(window.localStorage.getItem('chancela.signin.recentAccounts')).toBeNull();

    // Success is.
    await typeSignIn('bruno.dias', 'correct-horse');
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    const stored = JSON.parse(
      window.localStorage.getItem('chancela.signin.recentAccounts') ?? '[]',
    ) as { username: string }[];
    expect(stored.map((r) => r.username)).toEqual(['bruno.dias']);
  });

  it('the "guardar neste dispositivo" opt-out keeps a shared machine clean', async () => {
    const { fn } = serverStub({ roster: ROSTER, postUser: BRUNO });
    vi.stubGlobal('fetch', fn);

    renderGate();

    // On by default; the kiosk/shared case turns it off before signing in.
    const toggle = await screen.findByRole('switch', {
      name: 'Guardar este utilizador neste dispositivo',
    });
    expect((toggle as HTMLInputElement).checked).toBe(true);
    fireEvent.click(toggle);

    await typeSignIn('bruno.dias', 'correct-horse');
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    expect(window.localStorage.getItem('chancela.signin.recentAccounts')).toBeNull();
  });

  it('recents come from THIS device, not the roster, and clicking one fills the field', async () => {
    // A remembered identifier the roster does not contain: proof the list is local, and
    // proof the roster is not what populates it.
    window.localStorage.setItem(
      'chancela.signin.recentAccounts',
      JSON.stringify([
        { username: 'amelia.marques', displayName: 'Amélia Marques', lastUsedAt: 1000 },
      ]),
    );
    const { fn } = serverStub({ roster: ROSTER });
    vi.stubGlobal('fetch', fn);

    renderGate();

    expect(await screen.findByText('Utilizadores usados neste dispositivo')).toBeTruthy();
    // Bruno is on the roster but has never signed in here → he is not shown.
    expect(screen.queryByText('bruno.dias')).toBeNull();

    fireEvent.click(screen.getByText('amelia.marques'));
    expect((screen.getByLabelText('Utilizador') as HTMLInputElement).value).toBe('amelia.marques');
  });

  it('the ✕ is a labelled, keyboard-reachable button and its removal survives a reload', async () => {
    window.localStorage.setItem(
      'chancela.signin.recentAccounts',
      JSON.stringify([
        { username: 'amelia.marques', displayName: 'Amélia Marques', lastUsedAt: 2000 },
        { username: 'bruno.dias', displayName: 'Bruno Dias', lastUsedAt: 1000 },
      ]),
    );
    const { fn } = serverStub({ roster: ROSTER });
    vi.stubGlobal('fetch', fn);

    renderGate();

    const remove = await screen.findByRole('button', {
      name: 'Remover amelia.marques da lista',
    });
    // A real <button>: focusable by Tab, activated by Enter/Space, with a spoken name —
    // not an icon-only div.
    expect(remove.tagName).toBe('BUTTON');
    remove.focus();
    expect(document.activeElement).toBe(remove);

    fireEvent.click(remove);
    await waitFor(() => expect(screen.queryByText('amelia.marques')).toBeNull());
    expect(screen.getByText('bruno.dias')).toBeTruthy();

    // Reload (unmount + fresh mount reading storage again): it stays removed.
    cleanup();
    renderGate();
    expect(await screen.findByText('bruno.dias')).toBeTruthy();
    expect(screen.queryByText('amelia.marques')).toBeNull();
  });
});

describe('CurrentUserPicker (signed in)', () => {
  it('switches to a has_secret user by prompting for the password', async () => {
    // Start signed in as Amélia; the roster/user list carries a password-protected Bruno.
    setSessionToken('tok-0');
    const { fn, calls } = serverStub({
      roster: { onboarding_required: false },
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

  it('roving focus: Arrow keys, Home and End move focus among the menu items', async () => {
    // Signed in as Amélia, with a second active user (Bruno) to roam to.
    setSessionToken('tok-0');
    const { fn } = serverStub({
      roster: { onboarding_required: false },
      users: [AMELIA, BRUNO],
      startSignedIn: true,
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<CurrentUserPicker />);

    fireEvent.click(await screen.findByTestId('session-trigger'));

    const amelia = await screen.findByRole('menuitemradio', { name: /Amélia/ });
    const bruno = await screen.findByRole('menuitemradio', { name: /Bruno/ });

    // On open, focus lands on the currently-checked item (Amélia).
    await waitFor(() => expect(document.activeElement).toBe(amelia));

    // ArrowDown steps to the next item…
    fireEvent.keyDown(amelia, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(bruno);

    // …and wraps from the last back to the first.
    fireEvent.keyDown(bruno, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(amelia);

    // ArrowUp from the first wraps to the last.
    fireEvent.keyDown(amelia, { key: 'ArrowUp' });
    expect(document.activeElement).toBe(bruno);

    // Home jumps to the first, End jumps to the last.
    fireEvent.keyDown(bruno, { key: 'Home' });
    expect(document.activeElement).toBe(amelia);
    fireEvent.keyDown(amelia, { key: 'End' });
    expect(document.activeElement).toBe(bruno);
  });
});
