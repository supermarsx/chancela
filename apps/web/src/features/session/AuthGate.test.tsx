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
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
};

const PASSWORD_POLICY = {
  min_length: 8,
  require_lowercase: true,
  require_uppercase: false,
  require_digit: false,
  require_special: false,
  forbid_username: true,
  forbid_common: true,
  max_identical_run: 3,
  max_sequential_run: 4,
  allow_weak_passwords: false,
  rules: [{ code: 'length', requirement: 'Pelo menos 8 caracteres.' }],
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
      <Route path="/welcome" element={<div>WIZARD</div>} />
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

/**
 * The required-action wall (t21 Screen B). A walled session HAS a `user` AND a `required_action`
 * (the server 403s everything else), so `AuthGate` must intercept it before the app chrome and
 * render the matching wall. These drive the two walls end to end against fetch stubs that model the
 * server clearing the condition — the wall lifts by re-reading `GET /v1/session`, never a reload.
 *
 * The signed-in `session.data.user` is checked first, so the roster is stubbed but its resolution
 * is irrelevant to which wall renders — the same reason the pass-through test lets it hang.
 */
describe('AuthGate — required-action wall (t21)', () => {
  /**
   * A fetch stub that reports the session as `walled` (a `required_action`) until the underlying
   * condition is satisfied — a successful set-secret or a confirmed factor — after which it reports
   * a plain signed-in session and the wall lifts. Signing out flips it to `{user:null}` (the token
   * is gone), so the gate falls back to the sign-in surface.
   */
  function wallFetch(action: 'change_password' | 'enrol_two_factor') {
    const state = { cleared: false, signedOut: false };
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/session/roster')) {
        return Promise.resolve(
          jsonResponse({ onboarding_required: false, users: [AMELIA_ROSTER] }),
        );
      }
      if (url.includes('/v1/session/password-policy')) {
        return Promise.resolve(jsonResponse(PASSWORD_POLICY));
      }
      if (url.includes('/v1/session')) {
        if (method === 'DELETE') {
          state.signedOut = true;
          return Promise.resolve(jsonResponse({}));
        }
        if (state.signedOut) return Promise.resolve(jsonResponse({ user: null }));
        return Promise.resolve(
          jsonResponse(
            state.cleared
              ? { user: AMELIA_SESSION }
              : { user: AMELIA_SESSION, required_action: action },
          ),
        );
      }
      if (url.includes('/secret')) {
        state.cleared = true;
        return Promise.resolve(jsonResponse({ ...AMELIA_SESSION, has_secret: true }));
      }
      if (url.includes('/two-factor/totp/enrol')) {
        return Promise.resolve(
          jsonResponse({
            secret: 'JBSWY3DPEHPK3PXP',
            provisioning_uri: 'otpauth://totp/x',
            confirmed: false,
          }),
        );
      }
      if (url.includes('/two-factor/totp/confirm')) {
        state.cleared = true;
        return Promise.resolve(
          jsonResponse({ backup_codes: ['aaaa-bbbb', 'cccc-dddd'], backup_codes_remaining: 2 }),
        );
      }
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch;
    return { fn, state };
  }

  it('renders the change-password wall instead of the app when required_action=change_password', async () => {
    vi.stubGlobal('fetch', wallFetch('change_password').fn);
    renderGate();

    expect(await screen.findByText('Defina a sua palavra-passe')).toBeTruthy();
    expect(screen.getByLabelText('Palavra-passe atual')).toBeTruthy();
    // The requirements are shown for guidance (the server enforces them); they arrive with the
    // async policy read, so await them.
    expect(await screen.findByText('Pelo menos 8 caracteres.')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('renders the enrol-2FA wall instead of the app when required_action=enrol_two_factor', async () => {
    vi.stubGlobal('fetch', wallFetch('enrol_two_factor').fn);
    renderGate();

    expect(await screen.findByText('Ative a verificação em dois passos')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
  });

  it('lifts the change-password wall into the app once the new password is set', async () => {
    vi.stubGlobal('fetch', wallFetch('change_password').fn);
    renderGate();

    await screen.findByText('Defina a sua palavra-passe');
    fireEvent.change(screen.getByLabelText('Palavra-passe atual'), {
      target: { value: 'temp-Password-1' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'a-strong-new-secret' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar a nova palavra-passe'), {
      target: { value: 'a-strong-new-secret' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar a palavra-passe' }));

    // The server cleared force_password_change; the wall re-reads the session and lifts.
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
    expect(screen.queryByText('Defina a sua palavra-passe')).toBeNull();
  });

  it('rejects a wrong current password inline and keeps the wall (never a sign-out)', async () => {
    // The set-secret 401 is a credential proof: the client leaves the token alone, so the wall
    // stays mounted and the reject is a field-level message, not an eject to sign-in.
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/session/roster'))
        return Promise.resolve(
          jsonResponse({ onboarding_required: false, users: [AMELIA_ROSTER] }),
        );
      if (url.includes('/v1/session/password-policy'))
        return Promise.resolve(jsonResponse(PASSWORD_POLICY));
      if (url.includes('/v1/session'))
        return Promise.resolve(
          jsonResponse({ user: AMELIA_SESSION, required_action: 'change_password' }),
        );
      if (url.includes('/secret'))
        return Promise.resolve(jsonResponse({ error: 'credenciais inválidas' }, 401));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);
    renderGate();

    await screen.findByText('Defina a sua palavra-passe');
    fireEvent.change(screen.getByLabelText('Palavra-passe atual'), {
      target: { value: 'wrong-current' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'a-strong-new-secret' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar a nova palavra-passe'), {
      target: { value: 'a-strong-new-secret' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar a palavra-passe' }));

    expect(await screen.findByText('Palavra-passe atual incorreta.')).toBeTruthy();
    expect(screen.getByText('Defina a sua palavra-passe')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
    expect(screen.queryByText('Iniciar sessão')).toBeNull();
  });

  it('flags mismatched new passwords inline and does not submit', async () => {
    vi.stubGlobal('fetch', wallFetch('change_password').fn);
    renderGate();

    await screen.findByText('Defina a sua palavra-passe');
    // Everything is filled, so the only thing holding the submit back is the mismatch itself.
    fireEvent.change(screen.getByLabelText('Palavra-passe atual'), {
      target: { value: 'temp-Password-1' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'a-strong-new-secret' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar a nova palavra-passe'), {
      target: { value: 'a-different-secret' },
    });

    expect(await screen.findByText('As palavras-passe não coincidem.')).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: 'Guardar a palavra-passe' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('runs the enrol-2FA flow to backup codes, then lifts the wall on "Concluir"', async () => {
    vi.stubGlobal('fetch', wallFetch('enrol_two_factor').fn);
    renderGate();

    await screen.findByText('Ative a verificação em dois passos');
    fireEvent.click(screen.getByRole('button', { name: 'Ativar' }));

    // The QR + manual secret appear; enter a code and confirm.
    expect(await screen.findByText('JBSWY3DPEHPK3PXP')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Código da aplicação de autenticação'), {
      target: { value: '123456' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Ativar' }));

    // Backup codes are shown once, still inside the wall, and dismissing them lifts it.
    expect(await screen.findByText('Códigos de recuperação')).toBeTruthy();
    expect(screen.getByText('aaaa-bbbb')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Concluir' }));
    expect(await screen.findByText('APP CHROME')).toBeTruthy();
  });

  it('rejects a wrong activation code inline and keeps the enrol wall mounted', async () => {
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/session/roster'))
        return Promise.resolve(
          jsonResponse({ onboarding_required: false, users: [AMELIA_ROSTER] }),
        );
      if (url.includes('/v1/session'))
        return Promise.resolve(
          jsonResponse({ user: AMELIA_SESSION, required_action: 'enrol_two_factor' }),
        );
      if (url.includes('/two-factor/totp/enrol'))
        return Promise.resolve(
          jsonResponse({
            secret: 'JBSWY3DPEHPK3PXP',
            provisioning_uri: 'otpauth://totp/x',
            confirmed: false,
          }),
        );
      if (url.includes('/two-factor/totp/confirm'))
        return Promise.resolve(jsonResponse({ error: 'código inválido' }, 401));
      return Promise.reject(new Error(`no stub for ${method} ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);
    renderGate();

    await screen.findByText('Ative a verificação em dois passos');
    fireEvent.click(screen.getByRole('button', { name: 'Ativar' }));
    await screen.findByText('JBSWY3DPEHPK3PXP');
    fireEvent.change(screen.getByLabelText('Código da aplicação de autenticação'), {
      target: { value: '000000' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Ativar' }));

    expect(await screen.findByText('Código incorreto. Tente novamente.')).toBeTruthy();
    // Still mid-enrolment (the code field is still there), not ejected to sign-in.
    expect(screen.getByLabelText('Código da aplicação de autenticação')).toBeTruthy();
    expect(screen.queryByText('APP CHROME')).toBeNull();
    expect(screen.queryByText('Iniciar sessão')).toBeNull();
  });

  it('offers a sign-out escape that drops the walled session back to sign-in', async () => {
    vi.stubGlobal('fetch', wallFetch('change_password').fn);
    renderGate();

    await screen.findByText('Defina a sua palavra-passe');
    fireEvent.click(screen.getByRole('button', { name: 'Terminar sessão' }));

    expect(await screen.findByText('Iniciar sessão')).toBeTruthy();
    expect(screen.queryByText('Defina a sua palavra-passe')).toBeNull();
  });
});
