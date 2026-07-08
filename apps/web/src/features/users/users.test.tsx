import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { UsersPage } from './UsersPage';
import { isValidUsername, usernameError } from './username';
import type { UserView } from '../../api/types';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

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
  body: Record<string, unknown> | null;
}

function recordingFetch(responder: (r: Recorded) => Response): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    const rec = { url, method, body };
    calls.push(rec);
    return Promise.resolve(responder(rec));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('username validation', () => {
  it('accepts a lowercase slug and rejects uppercase/spaces/overlong', () => {
    expect(isValidUsername('amelia.marques')).toBe(true);
    expect(isValidUsername('m.ari-ana_1')).toBe(true);
    expect(isValidUsername('Amelia')).toBe(false);
    expect(isValidUsername('with space')).toBe(false);
    expect(isValidUsername('a'.repeat(65))).toBe(false);
    // An empty field is "incomplete", not an error message.
    expect(usernameError('')).toBeNull();
    expect(usernameError('Amelia')).toMatch(/minúsculas/);
  });
});

describe('UsersPage', () => {
  it('lists users with their state', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('Amélia Marques')).toBeTruthy();
    expect(screen.getByText('Ativo')).toBeTruthy();
  });

  it('renders a client-side validation error for an invalid username and disables submit', async () => {
    const { fn } = recordingFetch(() => jsonResponse([]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    const input = await screen.findByLabelText('Nome de utilizador');
    fireEvent.change(input, { target: { value: 'Amelia' } });

    expect(await screen.findByText(/minúsculas/)).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: /criar utilizador/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('creates a user with a valid slug and sends the username', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'POST' ? jsonResponse(AMELIA, 201) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(screen.getByLabelText('Nome a apresentar (opcional)'), {
      target: { value: 'Amélia Marques' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.url).toContain('/v1/users');
    expect(post?.body).toMatchObject({
      username: 'amelia.marques',
      display_name: 'Amélia Marques',
    });
    // A success toast confirms the create (t44 retrofit-b).
    expect(await screen.findByText('Utilizador criado.')).toBeTruthy();
  });

  it('surfaces a duplicate-username 409 inline against the field', async () => {
    const { fn } = recordingFetch((r) =>
      r.method === 'POST'
        ? jsonResponse({ error: 'username already exists' }, 409)
        : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    // The 409 message shows inline against the field and in the error toast (R7).
    expect((await screen.findAllByText(/already exists/)).length).toBeGreaterThanOrEqual(1);
  });

  it('toggles a user active/inactive via PATCH', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'PATCH' ? jsonResponse({ ...AMELIA, active: false }) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    fireEvent.click(await screen.findByRole('button', { name: /desativar/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.url).toContain('/v1/users/u1');
    expect(patch?.body).toMatchObject({ active: false });
    // Deactivating fires the distinct deactivated toast (t44 retrofit-b).
    expect(await screen.findByText('Utilizador desativado.')).toBeTruthy();
  });
});

const BRUNO: UserView = {
  id: 'u2',
  username: 'bruno.dias',
  display_name: 'Bruno Dias',
  created_at: '2026-07-07T12:05:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
};

describe('UserAccessManager (per-row password + audit key)', () => {
  it('sets a sign-in password via POST /v1/users/{id}/secret', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.includes('/secret') && r.method === 'POST'
        ? jsonResponse({ ...AMELIA, has_secret: true })
        : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    // Expand the row's access manager.
    fireEvent.click(await screen.findByRole('button', { name: /Acesso e auditoria/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'Definir palavra-passe' }));

    fireEvent.change(await screen.findByLabelText('Nova palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.url).toContain('/v1/users/u1/secret');
    expect(post?.body).toMatchObject({ password: 'password123' });
  });

  it('blocks mismatched passwords before hitting the server', async () => {
    const { fn, calls } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    fireEvent.click(await screen.findByRole('button', { name: /Acesso e auditoria/ }));
    fireEvent.click(await screen.findByRole('button', { name: 'Definir palavra-passe' }));
    fireEvent.change(await screen.findByLabelText('Nova palavra-passe'), {
      target: { value: 'password123' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'different1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    expect(await screen.findByText('As palavras-passe não coincidem.')).toBeTruthy();
    expect(calls.some((c) => c.url.includes('/secret'))).toBe(false);
  });

  it('generates an audit key for a user that already has a password', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.includes('/attestation-key') && r.method === 'POST'
        ? jsonResponse({
            ...BRUNO,
            has_attestation_key: true,
            attestation_key_fingerprint: 'ab'.repeat(16),
          })
        : jsonResponse([BRUNO]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersPage />, ['/utilizadores']);

    fireEvent.click(await screen.findByRole('button', { name: /Acesso e auditoria/ }));
    fireEvent.change(await screen.findByLabelText('Palavra-passe atual'), {
      target: { value: 'current-pw' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Gerar chave' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/attestation-key') && c.method === 'POST')).toBe(
        true,
      ),
    );
    const post = calls.find((c) => c.url.includes('/attestation-key') && c.method === 'POST');
    expect(post?.url).toContain('/v1/users/u2/attestation-key');
    expect(post?.body).toMatchObject({ current_password: 'current-pw' });
  });
});
