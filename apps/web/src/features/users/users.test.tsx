import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes, useLocation } from 'react-router-dom';
import { renderWithProviders } from '../../test/utils';

const saveFileMock = vi.hoisted(() => ({
  saveBlobAs: vi.fn(),
  saveBlobResultMessage: vi.fn(
    (result: { filename: string }) =>
      `Transferência iniciada pelo navegador: ${result.filename}. A pasta é definida pelo browser.`,
  ),
}));

vi.mock('../../desktop/saveFile', () => saveFileMock);

import { LegacyNewUserRedirect, LegacyUserRedirect, LegacyUsersRedirect } from '../../app/router';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import { UsersList } from './UserListPage';
import { NewUserPanel } from './NewUserPage';
import { EditUserPanel } from './EditUserPage';
import { isValidUsername, usernameError } from './username';
import type { DsrRequestView, DsrRequestType, UserView } from '../../api/types';

/** Render the edit screen at a real `:id` path so `useParams` resolves the user id. */
function renderEditAt(id: string) {
  return renderWithProviders(
    <Routes>
      <Route path="/configuracoes" element={<EditUserPanel id={id} />} />
    </Routes>,
    [`/configuracoes?sec=utilizadores&user=${id}`],
  );
}

function LocationProbe() {
  const location = useLocation();
  return (
    <output aria-label="location">
      {`${location.pathname}${location.search}${location.hash}`}
    </output>
  );
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error);
    reader.readAsText(blob);
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
  has_recovery_phrase: false,
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
  saveFileMock.saveBlobAs.mockReset();
  saveFileMock.saveBlobResultMessage.mockClear();
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

describe('UsersList (Configurações → Utilizadores)', () => {
  it('lists users with their state', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersList />, ['/configuracoes?sec=utilizadores']);

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    expect(screen.getByText('Amélia Marques')).toBeTruthy();
    expect(screen.getByText('Ativo')).toBeTruthy();
  });

  it('exposes icon-only row actions via their accessible names', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersList />, ['/configuracoes?sec=utilizadores']);

    // Each row action is an icon-only button whose accessible name comes from its tooltip
    // label (t50 W1 IconButton) — no visible text label, no native title.
    expect(await screen.findByRole('button', { name: 'Editar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Desativar' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Acesso e auditoria' })).toBeTruthy();
  });

  it('navigates list actions within the settings users section', async () => {
    const { fn } = recordingFetch(() => jsonResponse([AMELIA]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <Routes>
        <Route
          path="/configuracoes"
          element={
            <>
              <UsersList />
              <LocationProbe />
            </>
          }
        />
      </Routes>,
      ['/configuracoes?sec=utilizadores'],
    );

    const novo = await screen.findByRole('link', { name: /novo utilizador/i });
    expect(novo.getAttribute('href')).toBe('/configuracoes?sec=utilizadores&user=novo');

    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    fireEvent.click(await screen.findByRole('button', { name: 'Editar' }));
    expect(screen.getByLabelText('location').textContent).toBe(
      '/configuracoes?sec=utilizadores&user=u1',
    );

    fireEvent.click(screen.getByRole('button', { name: 'Acesso e auditoria' }));
    expect(screen.getByLabelText('location').textContent).toBe(
      '/configuracoes?sec=utilizadores&user=u1#acesso',
    );
  });

  it('toggles a user active/inactive via PATCH', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'PATCH' ? jsonResponse({ ...AMELIA, active: false }) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<UsersList />, ['/configuracoes?sec=utilizadores']);

    fireEvent.click(await screen.findByRole('button', { name: 'Desativar' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.url).toContain('/v1/users/u1');
    expect(patch?.body).toMatchObject({ active: false });
    // Deactivating fires the distinct deactivated toast (t44 retrofit-b).
    expect(await screen.findByText('Utilizador desativado.')).toBeTruthy();
  });
});

describe('NewUserPanel (Configurações → Utilizadores → novo)', () => {
  it('renders a client-side validation error for an invalid username and disables submit', async () => {
    const { fn } = recordingFetch(() => jsonResponse([]));
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPanel />, ['/configuracoes?sec=utilizadores&user=novo']);

    const input = await screen.findByLabelText('Nome de utilizador');
    fireEvent.change(input, { target: { value: 'Amelia' } });

    expect(await screen.findByText(/minúsculas/)).toBeTruthy();
    expect(
      (screen.getByRole('button', { name: /criar utilizador/i }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it('creates a user with a valid slug and sends identity email fields', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'POST' ? jsonResponse(AMELIA, 201) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPanel />, ['/configuracoes?sec=utilizadores&user=novo']);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.change(screen.getByLabelText('Nome a apresentar (opcional)'), {
      target: { value: 'Amélia Marques' },
    });
    fireEvent.change(screen.getByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const post = calls.find((c) => c.method === 'POST');
    expect(post?.url).toContain('/v1/users');
    expect(post?.body).toMatchObject({
      username: 'amelia.marques',
      display_name: 'Amélia Marques',
      email: 'amelia@example.pt',
    });
    // A success toast confirms the create (t44 retrofit-b) — it fires as the page navigates
    // to the new user's edit screen (ToastProvider is above the router).
    expect(await screen.findByText('Utilizador criado.')).toBeTruthy();
  });

  it('surfaces a duplicate-username 409 inline against the field', async () => {
    const { fn } = recordingFetch((r) =>
      r.method === 'POST'
        ? jsonResponse({ error: 'username already exists' }, 409)
        : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<NewUserPanel />, ['/configuracoes?sec=utilizadores&user=novo']);

    fireEvent.change(await screen.findByLabelText('Nome de utilizador'), {
      target: { value: 'amelia.marques' },
    });
    fireEvent.click(screen.getByRole('button', { name: /criar utilizador/i }));

    // The 409 message shows inline against the field and in the error toast (R7).
    expect((await screen.findAllByText(/already exists/)).length).toBeGreaterThanOrEqual(1);
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
  has_recovery_phrase: false,
};

describe('EditUserPanel (Configurações → Utilizadores → user) — identity + access manager', () => {
  it('renders identity and resolves a cold deep link via GET /v1/users/{id}', async () => {
    // Empty list cache → the edit screen falls back to the single-user read.
    const user = { ...AMELIA, email: 'amelia@example.pt' };
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(user) : jsonResponse([]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    // The immutable username and display name show as form values in the inline panel.
    expect(await screen.findByDisplayValue('amelia.marques')).toBeTruthy();
    expect(screen.getByDisplayValue('Amélia Marques')).toBeTruthy();
    expect(screen.getByDisplayValue('amelia@example.pt')).toBeTruthy();
    expect(calls.some((c) => c.url.endsWith('/v1/users/u1'))).toBe(true);
  });

  it('updates a user email via PATCH /v1/users/{id}', async () => {
    const user = { ...AMELIA, email: 'amelia@example.pt' };
    const { fn, calls } = recordingFetch((r) =>
      r.method === 'PATCH'
        ? jsonResponse({ ...user, email: 'amelia.legal@example.pt' })
        : r.url.endsWith('/v1/users/u1')
          ? jsonResponse(user)
          : jsonResponse([user]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    fireEvent.change(await screen.findByLabelText('E-mail (opcional)'), {
      target: { value: 'amelia.legal@example.pt' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar nome' }));

    await waitFor(() => expect(calls.some((c) => c.method === 'PATCH')).toBe(true));
    const patch = calls.find((c) => c.method === 'PATCH');
    expect(patch?.url).toContain('/v1/users/u1');
    expect(patch?.body).toMatchObject({ email: 'amelia.legal@example.pt' });
  });

  it('sets a sign-in password via POST /v1/users/{id}/secret', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.includes('/secret') && r.method === 'POST'
        ? jsonResponse({ ...AMELIA, has_secret: true })
        : r.url.endsWith('/v1/users/u1')
          ? jsonResponse(AMELIA)
          : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

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
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(AMELIA) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

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
        : r.url.endsWith('/v1/users/u2')
          ? jsonResponse(BRUNO)
          : jsonResponse([BRUNO]),
    );
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2');

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

  it('downloads the DSR/privacy JSON export without rendering its contents', async () => {
    saveFileMock.saveBlobAs.mockResolvedValue({
      kind: 'browser-download',
      filename: 'chancela-dsr-user-amelia.marques.json',
      contentType: 'application/json',
      bytes: 82,
    });
    const exportPayload = {
      user: { id: 'u1', username: 'amelia.marques' },
      audit_marker: 'opaque-internal-value',
    };
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/privacy/users/u1/export')) {
        return jsonResponse(exportPayload);
      }
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests')) return jsonResponse([]);
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    fireEvent.click(await screen.findByRole('button', { name: 'Descarregar exportação DSR' }));

    await waitFor(() => expect(saveFileMock.saveBlobAs).toHaveBeenCalledTimes(1));
    const saved = saveFileMock.saveBlobAs.mock.calls[0][0] as {
      blob: Blob;
      filename: string;
      contentType: string;
      filters: { name: string; extensions: string[] }[];
    };
    expect(saved.filename).toBe('chancela-dsr-user-amelia.marques.json');
    expect(saved.blob).toBeInstanceOf(Blob);
    expect(saved.blob.type).toBe('application/json');
    expect(saved.contentType).toBe('application/json');
    expect(saved.filters).toEqual([{ name: 'JSON', extensions: ['json'] }]);
    expect(await blobText(saved.blob)).toBe(JSON.stringify(exportPayload, null, 2));
    expect(calls).toContainEqual({
      url: '/v1/privacy/users/u1/export',
      method: 'GET',
      body: null,
    });
    expect(screen.queryByText('opaque-internal-value')).toBeNull();
    expect(saveFileMock.saveBlobResultMessage).toHaveBeenCalledWith({
      kind: 'browser-download',
      filename: 'chancela-dsr-user-amelia.marques.json',
      contentType: 'application/json',
      bytes: 82,
    });
    expect(
      await screen.findByText(
        'Transferência iniciada pelo navegador: chancela-dsr-user-amelia.marques.json. A pasta é definida pelo browser.',
      ),
    ).toBeTruthy();
  });

  it('lists, creates, and completes DSR lifecycle requests', async () => {
    const pending: DsrRequestView = {
      id: 'dsr-1',
      subject_user_id: 'u1',
      request_type: 'export',
      status: 'pending',
      created_at: '2026-07-08T09:00:00Z',
      created_by: 'operator',
    };
    let dsrRequests: DsrRequestView[] = [pending];
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests') && r.method === 'GET') {
        return jsonResponse(dsrRequests);
      }
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests') && r.method === 'POST') {
        const created: DsrRequestView = {
          id: 'dsr-2',
          subject_user_id: 'u1',
          request_type: r.body?.request_type as DsrRequestType,
          status: 'pending',
          created_at: '2026-07-08T10:00:00Z',
          created_by: 'operator',
        };
        dsrRequests = [...dsrRequests, created];
        return jsonResponse(created, 201);
      }
      if (r.url.endsWith('/v1/privacy/users/u1/dsr-requests/dsr-1/complete')) {
        const completed: DsrRequestView = {
          ...pending,
          status: 'completed',
          completed_at: '2026-07-08T11:00:00Z',
          completed_by: 'operator',
        };
        dsrRequests = [completed, ...dsrRequests.slice(1)];
        return jsonResponse(completed);
      }
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    expect(await screen.findByText('Pedidos DSR / privacidade')).toBeTruthy();
    expect(await screen.findByText('Exportação')).toBeTruthy();
    expect(screen.getByText('Pendente')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Tipo de pedido'), {
      target: { value: 'erasure' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Criar pedido DSR' }));

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url.endsWith('/v1/privacy/users/u1/dsr-requests') &&
            c.method === 'POST' &&
            c.body?.request_type === 'erasure',
        ),
      ).toBe(true),
    );
    expect((await screen.findAllByText('Apagamento')).length).toBeGreaterThanOrEqual(2);
    expect(await screen.findByText('Pedido DSR criado.')).toBeTruthy();

    fireEvent.click(screen.getAllByRole('button', { name: 'Marcar concluído' })[0]);

    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url.endsWith('/v1/privacy/users/u1/dsr-requests/dsr-1/complete') &&
            c.method === 'POST' &&
            c.body === null,
        ),
      ).toBe(true),
    );
    expect((await screen.findAllByText('Concluído')).length).toBeGreaterThanOrEqual(2);
    expect(await screen.findByText('Pedido DSR marcado como concluído.')).toBeTruthy();
  });

  it('omits the DSR lifecycle surface for users without user.manage', async () => {
    const { fn, calls } = recordingFetch((r) =>
      r.url.endsWith('/v1/users/u1') ? jsonResponse(AMELIA) : jsonResponse([AMELIA]),
    );
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'user.manage')}
      >
        <Routes>
          <Route path="/configuracoes" element={<EditUserPanel id="u1" />} />
        </Routes>
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=utilizadores&user=u1'],
    );

    expect(await screen.findByDisplayValue('amelia.marques')).toBeTruthy();
    expect(screen.queryByText('Pedidos DSR / privacidade')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Criar pedido DSR' })).toBeNull();
    expect(calls.some((c) => c.url.includes('/v1/privacy/'))).toBe(false);
  });
});

describe('legacy /utilizadores routes', () => {
  it('redirects /utilizadores to the settings users section', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/utilizadores" element={<LegacyUsersRedirect />} />
        <Route path="/configuracoes" element={<LocationProbe />} />
      </Routes>,
      ['/utilizadores'],
    );

    expect((await screen.findByLabelText('location')).textContent).toBe(
      '/configuracoes?sec=utilizadores',
    );
  });

  it('redirects /utilizadores/novo to the settings create state', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/utilizadores/novo" element={<LegacyNewUserRedirect />} />
        <Route path="/configuracoes" element={<LocationProbe />} />
      </Routes>,
      ['/utilizadores/novo#convite'],
    );

    expect((await screen.findByLabelText('location')).textContent).toBe(
      '/configuracoes?sec=utilizadores&user=novo#convite',
    );
  });

  it('redirects /utilizadores/:id and preserves #acesso', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/utilizadores/:id" element={<LegacyUserRedirect />} />
        <Route path="/configuracoes" element={<LocationProbe />} />
      </Routes>,
      ['/utilizadores/u1#acesso'],
    );

    expect((await screen.findByLabelText('location')).textContent).toBe(
      '/configuracoes?sec=utilizadores&user=u1#acesso',
    );
  });

  it('redirects legacy edit-style user links to the canonical settings user state', async () => {
    renderWithProviders(
      <Routes>
        <Route path="/utilizadores/:id/editar" element={<LegacyUserRedirect />} />
        <Route path="/configuracoes" element={<LocationProbe />} />
      </Routes>,
      ['/utilizadores/u1/editar'],
    );

    expect((await screen.findByLabelText('location')).textContent).toBe(
      '/configuracoes?sec=utilizadores&user=u1',
    );
  });
});

// The signed-in operator, a DIFFERENT user from the one being edited — makes every edit of
// BRUNO/AMELIA a cross-user op (t51).
const OPERATOR: UserView = {
  id: 'u9',
  username: 'operator',
  display_name: 'Operador',
  created_at: '2026-07-07T12:10:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
};

describe('EditUserPanel — cross-user password change proof + 403 (t51)', () => {
  it('self-service change shows the plain current-password field, not the cross-user proof', async () => {
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: BRUNO }); // editing yourself
      if (r.url.includes('/secret') && r.method === 'POST') return jsonResponse({ ...BRUNO });
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    // Self-service keeps the plain "Palavra-passe atual" field and shows NO proof selector.
    // (The password form's current field precedes the key block's, so [0] is the change field.)
    expect((await screen.findAllByLabelText('Palavra-passe atual')).length).toBeGreaterThanOrEqual(
      1,
    );
    expect(screen.queryByText('Prova de autorização')).toBeNull();

    fireEvent.change(screen.getAllByLabelText('Palavra-passe atual')[0], {
      target: { value: 'current-pw' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.body).toMatchObject({ password: 'newpassword1', current_password: 'current-pw' });
    expect(post?.body).not.toHaveProperty('recovery_phrase');
  });

  it('cross-user change collects the target current password and sends it as the proof', async () => {
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: OPERATOR });
      if (r.url.includes('/secret') && r.method === 'POST') return jsonResponse({ ...BRUNO });
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    // Cross-user: the proof selector + the target's current-password field are shown.
    expect(await screen.findByText('Prova de autorização')).toBeTruthy();
    // The proof value field (password block) precedes the key block's current field → [0].
    fireEvent.change((await screen.findAllByLabelText('Palavra-passe atual do utilizador'))[0], {
      target: { value: 'target-current' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.body).toMatchObject({
      password: 'newpassword1',
      current_password: 'target-current',
    });
    expect(post?.body).not.toHaveProperty('recovery_phrase');
  });

  it('cross-user change can authorize with a recovery phrase instead', async () => {
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: OPERATOR });
      if (r.url.includes('/secret') && r.method === 'POST') return jsonResponse({ ...BRUNO });
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    // Switch the proof kind to a recovery phrase.
    fireEvent.change(await screen.findByLabelText('Prova de autorização'), {
      target: { value: 'recovery' },
    });
    fireEvent.change(screen.getByLabelText('Frase de recuperação do utilizador'), {
      target: { value: 'ABCD1234-EFGH5678' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/secret') && c.method === 'POST')).toBe(true),
    );
    const post = calls.find((c) => c.url.includes('/secret') && c.method === 'POST');
    expect(post?.body).toMatchObject({
      password: 'newpassword1',
      recovery_phrase: 'ABCD1234-EFGH5678',
    });
    expect(post?.body).not.toHaveProperty('current_password');
  });

  it('renders a 403 refusal inline + toast and keeps the field retryable', async () => {
    const serverMsg = 'não autorizado a alterar as credenciais de outro utilizador';
    const { fn } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: OPERATOR });
      if (r.url.includes('/secret') && r.method === 'POST')
        return jsonResponse({ error: serverMsg }, 403);
      if (r.url.endsWith('/v1/users/u2')) return jsonResponse(BRUNO);
      return jsonResponse([BRUNO]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u2');

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    fireEvent.change((await screen.findAllByLabelText('Palavra-passe atual do utilizador'))[0], {
      target: { value: 'wrong' },
    });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'newpassword1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    // Honest inline refusal (distinct from the toast) + the field stays present/editable.
    expect(await screen.findByText(/Não autorizado — precisa da palavra-passe atual/)).toBeTruthy();
    expect(
      screen.getAllByLabelText('Palavra-passe atual do utilizador').length,
    ).toBeGreaterThanOrEqual(1);
    // The server's PT 403 message surfaces via the error toast.
    expect(await screen.findByText(new RegExp(serverMsg))).toBeTruthy();
  });

  it('issues a recovery phrase, shows it once, then clears it on dismissal', async () => {
    const phrase = 'ABCD1234-EFGH5678-JKMN9012-PQRS3456';
    const { fn, calls } = recordingFetch((r) => {
      if (r.url.endsWith('/v1/session')) return jsonResponse({ user: AMELIA }); // self, no secret
      if (r.url.includes('/recovery') && r.method === 'POST')
        return jsonResponse({ ...AMELIA, has_recovery_phrase: true, recovery_phrase: phrase });
      if (r.url.endsWith('/v1/users/u1')) return jsonResponse(AMELIA);
      return jsonResponse([AMELIA]);
    });
    vi.stubGlobal('fetch', fn);

    renderEditAt('u1');

    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase de recuperação' }));
    // Self + passwordless → no proof needed; just submit.
    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase' }));

    // The phrase is shown exactly once, prominently.
    expect(await screen.findByText(phrase)).toBeTruthy();
    await waitFor(() =>
      expect(calls.some((c) => c.url.includes('/recovery') && c.method === 'POST')).toBe(true),
    );

    // Dismiss → the phrase is gone from the UI (never retrievable again).
    fireEvent.click(screen.getByRole('button', { name: 'Concluído' }));
    await waitFor(() => expect(screen.queryByText(phrase)).toBeNull());
  });
});
