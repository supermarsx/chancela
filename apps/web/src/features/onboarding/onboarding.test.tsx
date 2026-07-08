/**
 * Onboarding wizard tests (plan t44 §3.2): the frozen step flow and that finishing marks
 * onboarding complete + lands the now-signed-in operator in the app. The wizard sequences
 * its backend calls around the t41 gating: bootstrap create → passwordless sign-in → then
 * the session-gated secret / key / settings writes.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen } from '@testing-library/react';
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
  has_secret: false,
  has_attestation_key: false,
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
    if (url.includes('/v1/settings')) {
      if (method === 'PUT') return json(body);
      return json(DEFAULT_SETTINGS);
    }
    if (url.endsWith('/v1/users') && method === 'POST') return json(USER, 201);
    if (url.includes('/v1/users/u1/secret')) return json({ ...USER, has_secret: true });
    if (url.includes('/v1/users/u1/attestation-key'))
      return json({ ...USER, has_secret: true, has_attestation_key: true });
    if (url.includes('/v1/session') && method === 'POST') return json({ token: 'tok', user: USER });
    if (url.includes('/v1/session')) return json({ user: null });
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function renderWizard() {
  return renderWithProviders(
    <Routes>
      <Route path="/bem-vindo" element={<OnboardingWizard />} />
      <Route path="/" element={<div>APP HOME</div>} />
    </Routes>,
    ['/bem-vindo'],
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clearSessionToken();
});

describe('OnboardingWizard', () => {
  it('walks welcome → org → user → password → key → finish and marks onboarding complete', async () => {
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

    // User → (create + passwordless sign-in) → Password
    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'operador' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    // Password → (set secret) → Key
    fireEvent.change(await screen.findByLabelText('Palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Seguinte' }));

    // Key → generate → finish
    fireEvent.click(await screen.findByRole('button', { name: 'Gerar chave de auditoria' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Entrar no Chancela' }));

    // Landed in the app.
    expect(await screen.findByText('APP HOME')).toBeTruthy();

    // The backend calls happened in the gating-correct order.
    const path = (c: Recorded) => `${c.method} ${new URL(c.url, 'http://x').pathname}`;
    const seq = calls.map(path);
    expect(seq).toContain('POST /v1/users');
    expect(seq).toContain('POST /v1/session');
    expect(seq).toContain('POST /v1/users/u1/secret');
    expect(seq).toContain('POST /v1/users/u1/attestation-key');
    // create user precedes sign-in precedes the session-gated secret write.
    expect(seq.indexOf('POST /v1/users')).toBeLessThan(seq.indexOf('POST /v1/session'));
    expect(seq.indexOf('POST /v1/session')).toBeLessThan(seq.indexOf('POST /v1/users/u1/secret'));

    // Finish PUT marks onboarding complete and carries the org name.
    const put = calls.find((c) => c.method === 'PUT' && c.url.includes('/v1/settings'));
    expect(put?.body).toMatchObject({
      organization: { name: 'Acme, S.A.' },
      onboarding: { completed: true },
    });
  });

  it('skips the optional password and still completes onboarding', async () => {
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

    // Password step → skip.
    fireEvent.click(await screen.findByRole('button', { name: 'Ignorar' }));

    expect(await screen.findByText('APP HOME')).toBeTruthy();
    // No secret / key writes on the skip path.
    expect(calls.some((c) => c.url.includes('/secret'))).toBe(false);
    const put = calls.find((c) => c.method === 'PUT' && c.url.includes('/v1/settings'));
    expect(put?.body).toMatchObject({ onboarding: { completed: true } });
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
      if (url.includes('/v1/settings')) return json(DEFAULT_SETTINGS);
      if (url.includes('/v1/session')) return json({ user: null });
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWizard();

    expect(await screen.findByText('APP HOME')).toBeTruthy();
  });
});
