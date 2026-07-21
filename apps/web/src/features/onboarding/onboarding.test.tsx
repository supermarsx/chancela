/**
 * Onboarding wizard tests (plan t44 §3.2): the frozen step flow and that finishing marks
 * onboarding complete + lands the now-signed-in operator in the app. The wizard sequences
 * its backend calls around the auth gating: bootstrap create with password → password sign-in
 * → then the session-gated recovery/settings writes.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';
import { OnboardingWizard } from './OnboardingWizard';
import { clearSessionToken } from '../../api/session';
import { DEFAULT_SETTINGS, type UserView } from '../../api/types';

const USER: UserView = {
  id: 'u1',
  username: 'operador',
  display_name: 'Operador',
  created_at: '2026-07-08T09:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  language: 'auto',
  role_assignments: [],
};

const STRONG_PASSWORD = 'Str0ng!Vault9';
const RECOVERY_PHRASE = 'ABCD1234-EFGH5678-JKMN9012-PQRS3456';
const PASSWORD_POLICY = {
  min_length: 10,
  require_lowercase: true,
  require_uppercase: true,
  require_digit: true,
  require_special: true,
  forbid_username: true,
  forbid_common: true,
  max_identical_run: 4,
  max_sequential_run: 5,
  allow_weak_passwords: false,
  rules: [
    { code: 'length', requirement: 'pelo menos 10 caracteres' },
    { code: 'lowercase', requirement: 'pelo menos uma letra minúscula' },
    { code: 'uppercase', requirement: 'pelo menos uma letra maiúscula' },
    { code: 'digit', requirement: 'pelo menos um algarismo' },
    { code: 'special', requirement: 'pelo menos um caractere especial' },
    { code: 'not_username', requirement: 'não pode conter o nome de utilizador' },
    { code: 'not_common', requirement: 'não pode ser uma palavra-passe comum' },
    { code: 'no_repeats', requirement: 'sem 4 ou mais caracteres iguais seguidos' },
    { code: 'no_sequential', requirement: 'sem 5 ou mais caracteres consecutivos seguidos' },
  ],
};

interface Recorded {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function wizardStub(): { fn: typeof fetch; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    calls.push({ url, method, body });
    const json = (b: unknown, status = 200) =>
      Promise.resolve(
        new Response(JSON.stringify(b), {
          status,
          headers: { 'Content-Type': 'application/json' },
        }),
      );

    if (url.includes('/v1/session/roster')) return json({ onboarding_required: true, users: [] });
    if (url.includes('/v1/session/password-policy')) return json(PASSWORD_POLICY);
    if (url.includes('/v1/settings')) {
      if (method === 'PUT') return json(body);
      return json(DEFAULT_SETTINGS);
    }
    if (url.endsWith('/v1/users') && method === 'POST') return json(USER, 201);
    if (url.includes('/v1/users/u1/recovery'))
      return json({
        ...USER,
        has_secret: true,
        has_recovery_phrase: true,
        language: 'auto',
        role_assignments: [],
        recovery_phrase: RECOVERY_PHRASE,
      });
    if (url.includes('/v1/session') && method === 'POST') {
      if (body?.password !== STRONG_PASSWORD) return json({ error: 'credenciais inválidas' }, 401);
      return json({ token: 'tok', user: USER });
    }
    if (url.includes('/v1/session')) return json({ user: null });
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function renderWizard() {
  return renderWithProviders(
    <Routes>
      <Route path="/welcome" element={<OnboardingWizard />} />
      <Route path="/" element={<div>APP HOME</div>} />
    </Routes>,
    ['/welcome'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clearSessionToken();
});

describe('OnboardingWizard', () => {
  it('walks welcome → org → user → password → recovery → finish and marks onboarding complete', async () => {
    const { fn, calls } = wizardStub();
    vi.stubGlobal('fetch', fn);

    renderWizard();

    // Welcome → Org
    fireEvent.click(await screen.findByRole('button', { name: 'Começar' }));

    // Org → User
    fireEvent.change(await screen.findByLabelText('Nome da organização'), {
      target: { value: 'Acme, S.A.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    // User → Password (no backend create until the password is submitted)
    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'operador' },
    });
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'operador@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    // Password → (bootstrap create + password sign-in) → Recovery phrase
    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: STRONG_PASSWORD },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: STRONG_PASSWORD },
    });
    expect(await screen.findByText('As palavras-passe coincidem.')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    // Recovery phrase → generate → finish
    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase de recuperação' }));
    expect(await screen.findByText(RECOVERY_PHRASE)).toBeTruthy();
    fireEvent.click(await screen.findByRole('button', { name: 'Entrar no Chancela' }));

    // Landed in the app.
    expect(await screen.findByText('APP HOME')).toBeTruthy();

    // The backend calls happened in the gating-correct order.
    const path = (c: Recorded) => `${c.method} ${new URL(c.url, 'http://x').pathname}`;
    const seq = calls.map(path);
    expect(seq).toContain('POST /v1/users');
    expect(seq).toContain('POST /v1/session');
    expect(seq).toContain('POST /v1/users/u1/recovery');
    expect(seq).not.toContain('POST /v1/users/u1/secret');
    // create user precedes sign-in, which precedes the session-gated recovery write.
    expect(seq.indexOf('POST /v1/users')).toBeLessThan(seq.indexOf('POST /v1/session'));
    expect(seq.indexOf('POST /v1/session')).toBeLessThan(seq.indexOf('POST /v1/users/u1/recovery'));
    const createdUser = calls.find((c) => c.method === 'POST' && c.url.endsWith('/v1/users'));
    expect(createdUser?.body).toMatchObject({
      username: 'operador',
      email: 'operador@example.pt',
      password: STRONG_PASSWORD,
    });
    const session = calls.find((c) => c.method === 'POST' && c.url.includes('/v1/session'));
    expect(session?.body).toMatchObject({ user_id: 'u1', password: STRONG_PASSWORD });
    const recovery = calls.find((c) => c.url.includes('/v1/users/u1/recovery'));
    expect(recovery?.body).toMatchObject({ current_password: STRONG_PASSWORD });

    // Finish PUT marks onboarding complete and carries the org name.
    const put = calls.find((c) => c.method === 'PUT' && c.url.includes('/v1/settings'));
    expect(put?.body).toMatchObject({
      organization: { name: 'Acme, S.A.' },
      onboarding: { completed: true },
    });
  });

  it('finishes onboarding with a blank organisation (org is optional, t73)', async () => {
    const { fn, calls } = wizardStub();
    vi.stubGlobal('fetch', fn);

    renderWizard();

    fireEvent.click(await screen.findByRole('button', { name: 'Começar' }));

    // Org step: leave the field blank — "Seguinte" must be enabled and advance anyway.
    const next = await screen.findByRole('button', { name: 'Seguinte' });
    expect(next.hasAttribute('disabled')).toBe(false);
    fireEvent.click(next);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'operador' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: STRONG_PASSWORD },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: STRONG_PASSWORD },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase de recuperação' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Entrar no Chancela' }));

    expect(await screen.findByText('APP HOME')).toBeTruthy();

    // The finish PUT still marks onboarding complete; the org falls back to the settings
    // default (`null`) rather than blocking completion.
    const put = calls.find((c) => c.method === 'PUT' && c.url.includes('/v1/settings'));
    expect(put?.body).toMatchObject({ onboarding: { completed: true } });
    expect((put?.body as { organization: { name: unknown } }).organization.name).toBeNull();
  });

  it('does not expose a password skip path and blocks weak passwords before the server', async () => {
    const { fn, calls } = wizardStub();
    vi.stubGlobal('fetch', fn);

    renderWizard();

    fireEvent.click(await screen.findByRole('button', { name: 'Começar' }));
    fireEvent.change(await screen.findByLabelText('Nome da organização'), {
      target: { value: 'Acme' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));
    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'operador' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    await screen.findByText('Palavra-passe obrigatória');
    expect(screen.queryByRole('button', { name: 'Ignorar' })).toBeNull();

    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'password123' },
    });

    expect(screen.getByText('As palavras-passe coincidem.')).toBeTruthy();
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Seguinte' }).hasAttribute('disabled')).toBe(true),
    );
    expect(calls.some((c) => c.method === 'POST' && c.url.endsWith('/v1/users'))).toBe(false);
    expect(calls.some((c) => c.method === 'POST' && c.url.includes('/v1/session'))).toBe(false);
  });
});

describe('OnboardingWizard entrance guard', () => {
  it('redirects to the app when onboarding is not required', async () => {
    const fn = ((input: RequestInfo | URL) => {
      const url = typeof input === 'string' ? input : input.toString();
      const json = (b: unknown) =>
        Promise.resolve(
          new Response(JSON.stringify(b), { headers: { 'Content-Type': 'application/json' } }),
        );
      if (url.includes('/v1/session/roster'))
        return json({
          onboarding_required: false,
          users: [{ id: 'u1', username: 'operador', display_name: 'Operador', has_secret: false }],
        });
      if (url.includes('/v1/session/password-policy')) return json(PASSWORD_POLICY);
      if (url.includes('/v1/settings')) return json(DEFAULT_SETTINGS);
      if (url.includes('/v1/session')) return json({ user: null });
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWizard();

    expect(await screen.findByText('APP HOME')).toBeTruthy();
  });
});
