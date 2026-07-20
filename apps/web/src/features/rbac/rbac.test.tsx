/**
 * t64-E6 RBAC management UI: the permission-matrix editor (subset honesty), role create,
 * scoped role assignment, the last-Owner-removal 409, scoped delegation grant + revoke, and
 * the disable-with-explanation gating of the mutating affordances.
 *
 * The server is the REAL guard — these tests assert the UI reflects it honestly (never
 * implies an escalation the server would reject) and wires the frozen E4 endpoints.
 */
import { afterEach, describe, it, expect, vi } from 'vitest';
import { cleanup, render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import type { ReactElement } from 'react';
import { makeClient } from '../../test/utils';
import { ToastProvider } from '../../ui';
import {
  ALLOW_ALL_PERMISSIONS,
  StaticPermissionsProvider,
  type PermissionsContextValue,
} from '../session/permissions';
import type { PermissionGrant, UserView } from '../../api/types';
import { PermissionMatrix } from './PermissionMatrix';
import { FuncoesSection } from './FuncoesSection';
import { RoleAssignmentManager } from './RoleAssignmentManager';
import { DelegacoesSection } from './DelegacoesSection';

afterEach(() => cleanup());

// --- fetch mock (method + substring aware, captures calls) ----------------------

interface Handler {
  method?: string;
  match: string;
  status?: number;
  body?: unknown;
}

function mockFetch(handlers: Handler[]) {
  const calls: { url: string; method: string; body: unknown }[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = (init?.method ?? 'GET').toUpperCase();
    let body: unknown;
    try {
      body = init?.body ? JSON.parse(init.body as string) : undefined;
    } catch {
      body = init?.body;
    }
    calls.push({ url, method, body });
    const hit = handlers.find(
      (h) => (h.method ?? 'GET').toUpperCase() === method && url.includes(h.match),
    );
    const status = hit?.status ?? 200;
    // Unmatched GETs default to an empty array (the common list shape) so incidental queries
    // never reject; endpoints whose shape matters are always stubbed explicitly.
    const payload = hit ? hit.body : [];
    return Promise.resolve(
      new Response(status === 204 ? '' : JSON.stringify(payload ?? null), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as typeof fetch;
  return { fn, calls };
}

function renderRbac(
  ui: ReactElement,
  permissions: PermissionsContextValue = ALLOW_ALL_PERMISSIONS,
) {
  return render(
    <QueryClientProvider client={makeClient()}>
      <ToastProvider>
        <StaticPermissionsProvider value={permissions}>
          <MemoryRouter>{ui}</MemoryRouter>
        </StaticPermissionsProvider>
      </ToastProvider>
    </QueryClientProvider>,
  );
}

const CATALOG = {
  permissions: [
    { permission: 'entity.read', meta: false },
    { permission: 'entity.create', meta: false },
    { permission: 'book.open', meta: false },
    { permission: 'role.manage', meta: true },
    { permission: 'delegation.grant', meta: true },
  ],
};

const grant = (permission: string, source: 'role' | 'delegation' = 'role'): PermissionGrant => ({
  permission,
  scope: { kind: 'global' },
  source,
});

/** A permissions value from an explicit predicate + optional grant list. */
function value(
  can: (p: string) => boolean,
  grants: PermissionGrant[] = [],
): PermissionsContextValue {
  return { can, canAny: can, grants, ready: true };
}

const USER: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-01-01',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
};

// --- Subset honesty (permission-matrix editor) ----------------------------------

describe('PermissionMatrix — subset honesty', () => {
  function checkboxFor(permission: string): HTMLInputElement {
    const code = screen.getByText(permission);
    const label = code.closest('label')!;
    return label.querySelector('input')! as HTMLInputElement;
  }

  it('a permission the actor does not hold is unselectable (disabled)', () => {
    // The actor holds entity.read only; book.open is outside their grants.
    renderRbac(
      <PermissionMatrix catalog={CATALOG.permissions} selected={new Set()} onChange={() => {}} />,
      value((p) => p === 'entity.read'),
    );
    expect(checkboxFor('entity.read').disabled).toBe(false);
    expect(checkboxFor('book.open').disabled).toBe(true);
    expect(checkboxFor('book.open').getAttribute('aria-disabled')).toBe('true');
    // The honest explanation is reachable (the W1 tooltip bubble is always mounted).
    expect(screen.getAllByText('Não possui esta permissão').length).toBeGreaterThan(0);
  });

  it('an Owner (all perms) can tick everything', () => {
    const changes: Set<string>[] = [];
    renderRbac(
      <PermissionMatrix
        catalog={CATALOG.permissions}
        selected={new Set()}
        onChange={(s) => changes.push(s)}
      />,
      ALLOW_ALL_PERMISSIONS,
    );
    expect(checkboxFor('role.manage').disabled).toBe(false);
    fireEvent.click(checkboxFor('role.manage'));
    expect(changes.at(-1)?.has('role.manage')).toBe(true);
  });
});

// --- Roles view -----------------------------------------------------------------

describe('FuncoesSection — role create + gating', () => {
  it('an Owner creates a role within their permissions (POST /v1/roles)', async () => {
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/roles', body: [] },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'POST',
        match: '/v1/roles',
        body: { id: 'r9', name: 'Gestor', permissions: ['entity.read'], protected: false },
      },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(<FuncoesSection />);
    fireEvent.click(await screen.findByRole('button', { name: 'Nova função' }));

    fireEvent.change(screen.getByLabelText('Nome da função'), {
      target: { value: 'Gestor de Encosto Estratégico Lda' },
    });
    // Tick a held permission in the matrix.
    fireEvent.click(screen.getByText('entity.read').closest('label')!.querySelector('input')!);
    fireEvent.click(screen.getByRole('button', { name: 'Criar função' }));

    await waitFor(() => {
      const post = calls.find((c) => c.method === 'POST' && c.url.includes('/v1/roles'));
      expect(post).toBeTruthy();
      expect(post!.body).toEqual({
        name: 'Gestor de Encosto Estratégico Lda',
        permissions: ['entity.read'],
      });
    });
    vi.unstubAllGlobals();
  });

  // The matrix is a checkbox group, not one control, so it used to carry a `<label for="">`
  // — an orphan label naming nothing. It must be a named group instead.
  it('names the permission matrix as a group instead of orphaning its label', async () => {
    const { fn } = mockFetch([
      { method: 'GET', match: '/v1/roles', body: [] },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(<FuncoesSection />);
    fireEvent.click(await screen.findByRole('button', { name: 'Nova função' }));

    const group = screen.getByRole('group', { name: 'Permissões' });
    expect(group.contains(screen.getByText('entity.read'))).toBe(true);
    expect(document.querySelectorAll('label[for=""]')).toHaveLength(0);

    vi.unstubAllGlobals();
  });

  it('a non-role.manage user sees the create affordance disabled-with-explanation', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/roles',
        body: [{ id: 'owner', name: 'Proprietário', permissions: [], protected: true }],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
    ]);
    vi.stubGlobal('fetch', fn);

    // Holds reads but NOT role.manage.
    renderRbac(
      <FuncoesSection />,
      value((p) => p !== 'role.manage'),
    );

    const btn = await screen.findByRole('button', { name: 'Nova função' });
    expect(btn.getAttribute('aria-disabled')).toBe('true');
    // The honest read-only note is shown.
    expect(screen.getByText(/role\.manage/)).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('shows seeded role drift as a manual-review status', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/roles',
        body: [
          {
            id: 'platform-admin',
            name: 'Platform Administrator',
            permissions: ['role.manage'],
            protected: false,
            seeded_role_drift: {
              missing_default_permissions: ['platform.logs.write'],
              requires_manual_review: true,
            },
          },
        ],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(<FuncoesSection />);

    const row = (await screen.findByText('Platform Administrator')).closest('tr')!;
    expect(within(row).getByText('Revisão manual')).toBeTruthy();
    expect(within(row).getByText(/Defaults em falta: platform\.logs\.write/)).toBeTruthy();
    expect(within(row).queryByText(/corrigid|automatic/i)).toBeNull();
    vi.unstubAllGlobals();
  });

  it('applies seeded role drift only after explicit admin review action', async () => {
    const { fn, calls } = mockFetch([
      {
        method: 'GET',
        match: '/v1/roles/platform-admin/seeded-drift-reconciliation',
        body: {
          role_id: 'platform-admin',
          role_name: 'Platform Administrator',
          current_permissions: ['role.manage'],
          missing_default_permissions: ['platform.logs.write'],
          proposed_permissions: ['role.manage', 'platform.logs.write'],
          applied_permissions: [],
          applied: false,
          requires_manual_review: true,
        },
      },
      {
        method: 'GET',
        match: '/v1/roles',
        body: [
          {
            id: 'platform-admin',
            name: 'Platform Administrator',
            permissions: ['role.manage'],
            protected: false,
            seeded_role_drift: {
              missing_default_permissions: ['platform.logs.write'],
              requires_manual_review: true,
            },
          },
        ],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'POST',
        match: '/v1/roles/platform-admin/seeded-drift-reconciliation',
        body: {
          role_id: 'platform-admin',
          role_name: 'Platform Administrator',
          current_permissions: ['role.manage', 'platform.logs.write'],
          missing_default_permissions: [],
          proposed_permissions: ['role.manage', 'platform.logs.write'],
          applied_permissions: ['platform.logs.write'],
          applied: true,
          requires_manual_review: false,
        },
      },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(<FuncoesSection />);

    const row = (await screen.findByText('Platform Administrator')).closest('tr')!;
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    fireEvent.click(within(row).getByRole('button', { name: 'Rever defaults' }));
    await waitFor(() => {
      const proposal = calls.find((c) =>
        c.url.includes('/v1/roles/platform-admin/seeded-drift-reconciliation'),
      );
      expect(proposal).toBeTruthy();
      expect(proposal!.method).toBe('GET');
    });
    expect(await within(row).findByText(/Adicionar só: platform\.logs\.write/)).toBeTruthy();
    fireEvent.click(within(row).getByRole('button', { name: 'Aplicar defaults em falta' }));

    await waitFor(() => {
      const post = calls.find(
        (c) =>
          c.method === 'POST' &&
          c.url.includes('/v1/roles/platform-admin/seeded-drift-reconciliation'),
      );
      expect(post).toBeTruthy();
      expect(post!.body).toEqual({});
    });
    expect(await screen.findByText(/Reconciliação aplicada: platform\.logs\.write/)).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('disables seeded role drift reconciliation without role.manage', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/roles',
        body: [
          {
            id: 'platform-admin',
            name: 'Platform Administrator',
            permissions: ['entity.read'],
            protected: false,
            seeded_role_drift: {
              missing_default_permissions: ['platform.logs.write'],
              requires_manual_review: true,
            },
          },
        ],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(
      <FuncoesSection />,
      value((p) => p !== 'role.manage'),
    );

    const row = (await screen.findByText('Platform Administrator')).closest('tr')!;
    const review = within(row).getByRole('button', { name: 'Rever defaults' });
    expect(review.getAttribute('aria-disabled')).toBe('true');
    vi.unstubAllGlobals();
  });
});

// --- Scoped role assignment -----------------------------------------------------

describe('RoleAssignmentManager — scoped assignment + last-Owner 409', () => {
  it('assigns a role scoped to an entity (POST /v1/users/{id}/roles)', async () => {
    const { fn, calls } = mockFetch([
      {
        method: 'GET',
        match: '/v1/roles',
        body: [{ id: 'r1', name: 'Gestor', permissions: ['book.open'], protected: false }],
      },
      {
        method: 'GET',
        match: '/v1/entities',
        body: [{ id: 'E1', name: 'Encosto Estratégico Lda' }],
      },
      { method: 'GET', match: '/v1/books', body: [] },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'admin' }, permissions: [] } },
      {
        method: 'POST',
        match: '/v1/users/u1/roles',
        body: [{ role_id: 'r1', scope: { kind: 'entity', id: 'E1' } }],
      },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(<RoleAssignmentManager user={USER} />);

    // Pick the Entity scope; the picker auto-selects the only entity (E1).
    fireEvent.change(await screen.findByLabelText('Âmbito'), { target: { value: 'entity' } });
    fireEvent.click(screen.getByRole('button', { name: 'Atribuir' }));

    await waitFor(() => {
      const post = calls.find((c) => c.method === 'POST' && c.url.includes('/v1/users/u1/roles'));
      expect(post).toBeTruthy();
      expect(post!.body).toEqual({ role_id: 'r1', scope: { kind: 'entity', id: 'E1' } });
    });
    // The returned assignment renders in the table (scoped away from the role-picker option).
    expect(within(await screen.findByRole('table')).getByText('Gestor')).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('the last-Owner removal 409 renders honestly and keeps the row', async () => {
    const { fn, calls } = mockFetch([
      {
        method: 'GET',
        match: '/v1/roles',
        body: [{ id: 'owner', name: 'Proprietário', permissions: [], protected: true }],
      },
      { method: 'GET', match: '/v1/entities', body: [] },
      { method: 'GET', match: '/v1/books', body: [] },
      // Editing one's OWN account (session user === edited user) → the manager seeds from here.
      {
        method: 'GET',
        match: '/v1/session/permissions',
        body: {
          user_id: 'u1',
          username: 'amelia.marques',
          role_assignments: [{ role_id: 'owner', scope: { kind: 'global' } }],
          permissions: [],
        },
      },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'u1' }, permissions: [] } },
      {
        method: 'DELETE',
        match: '/v1/users/u1/roles',
        status: 409,
        body: { error: 'não pode remover o último Proprietário' },
      },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(<RoleAssignmentManager user={USER} />);

    // The seeded Owner@global assignment shows with a Remover action.
    fireEvent.click(await screen.findByRole('button', { name: 'Remover' }));

    // The server's honest 409 message surfaces (toast), and the row remains.
    expect(await screen.findByText(/último Proprietário/)).toBeTruthy();
    expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/users/u1/roles'))).toBe(
      true,
    );
    // The assignment row (scoped away from the role-picker option) is still present.
    expect(within(screen.getByRole('table')).getByText('Proprietário')).toBeTruthy();
    vi.unstubAllGlobals();
  });
});

// --- Scoped delegation ----------------------------------------------------------

describe('DelegacoesSection — grant a held permission, revoke it', () => {
  it('grants a role-held non-meta permission (POST /v1/delegations)', async () => {
    const startsAtInput = '2026-01-01T09:30';
    const expectedStartsAt = new Date(startsAtInput).toISOString();
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [] },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'GET',
        match: '/v1/users',
        body: [
          {
            id: 'u2',
            username: 'joao.silva',
            display_name: 'João Silva',
            active: true,
            has_secret: true,
            has_attestation_key: false,
            has_recovery_phrase: false,
            created_at: '2026-01-01',
          },
        ],
      },
      { method: 'GET', match: '/v1/entities', body: [] },
      { method: 'GET', match: '/v1/books', body: [] },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'me' }, permissions: [] } },
      {
        method: 'POST',
        match: '/v1/delegations',
        body: {
          id: 'd1',
          from: 'me',
          to: 'u2',
          permission: 'entity.read',
          scope: { kind: 'global' },
          granted_at: '2026-07-08T00:00:00Z',
          starts_at: expectedStartsAt,
          legal_basis: 'Ata interna R-72',
          revoked: false,
        },
      },
    ]);
    vi.stubGlobal('fetch', fn);

    // The current user holds entity.read VIA A ROLE (so it is delegable); role.manage is meta.
    renderRbac(
      <DelegacoesSection />,
      value(() => true, [grant('entity.read', 'role'), grant('role.manage', 'role')]),
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Nova delegação' }));
    // The delegable permission picker is a multi-select offering entity.read (non-meta,
    // role-sourced) — NOT the meta role.manage.
    // Wait for the catalog to resolve so the meta filter (role.manage excluded) has applied.
    await waitFor(() => {
      const group = screen.getByRole('group', { name: 'Permissão' });
      expect(within(group).getByText('entity.read')).toBeTruthy();
      expect(within(group).queryByText('role.manage')).toBeNull();
    });
    // Nothing is pre-selected: delegating is an explicit act, never a default.
    const boxes = () =>
      within(screen.getByRole('group', { name: 'Permissão' })).getAllByRole('checkbox');
    expect(boxes().every((b) => !(b as HTMLInputElement).checked)).toBe(true);
    fireEvent.click(boxes()[0]);

    fireEvent.change(screen.getByLabelText('Início (opcional)'), {
      target: { value: startsAtInput },
    });
    fireEvent.change(screen.getByLabelText('Base/evidência local'), {
      target: { value: '  Ata interna R-72  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Conceder' }));
    await waitFor(() => {
      const post = calls.find((c) => c.method === 'POST' && c.url.includes('/v1/delegations'));
      expect(post).toBeTruthy();
      expect(post!.body).toMatchObject({
        to: 'u2',
        permissions: ['entity.read'],
        scope: { kind: 'global' },
        starts_at: expectedStartsAt,
        legal_basis: 'Ata interna R-72',
      });
    });
    vi.unstubAllGlobals();
  });

  it('grants SEVERAL permissions in one delegation, sharing one scope and lifetime', async () => {
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [] },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'GET',
        match: '/v1/users',
        body: [
          {
            id: 'u2',
            username: 'joao.silva',
            display_name: 'João Silva',
            active: true,
            has_secret: true,
            has_attestation_key: false,
            has_recovery_phrase: false,
            created_at: '2026-01-01',
          },
        ],
      },
      { method: 'GET', match: '/v1/entities', body: [] },
      { method: 'GET', match: '/v1/books', body: [] },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'me' }, permissions: [] } },
      {
        method: 'POST',
        match: '/v1/delegations',
        body: {
          id: 'd1',
          from: 'me',
          to: 'u2',
          permission: 'book.open',
          permissions: ['book.open', 'entity.read'],
          scope: { kind: 'global' },
          granted_at: '2026-07-08T00:00:00Z',
          starts_at: '2026-07-08T00:00:00Z',
          legal_basis: 'Ata interna R-73',
          revoked: false,
        },
      },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(
      <DelegacoesSection />,
      value(() => true, [
        grant('entity.read', 'role'),
        grant('book.open', 'role'),
        grant('role.manage', 'role'),
      ]),
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Nova delegação' }));
    await waitFor(() => {
      const group = screen.getByRole('group', { name: 'Permissão' });
      expect(within(group).getByText('book.open')).toBeTruthy();
    });
    // "Selecionar tudo" ticks every DELEGABLE verb — the meta role.manage is not among them, so
    // the picker can never assemble a batch the server would have to refuse.
    fireEvent.click(screen.getByRole('button', { name: 'Selecionar tudo' }));
    fireEvent.change(screen.getByLabelText('Base/evidência local'), {
      target: { value: 'Ata interna R-73' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Conceder' }));

    await waitFor(() => {
      const post = calls.find((c) => c.method === 'POST' && c.url.includes('/v1/delegations'));
      expect(post).toBeTruthy();
      // One request, one delegation, both verbs — sharing the scope and legal basis.
      expect(post!.body).toMatchObject({
        to: 'u2',
        permissions: ['book.open', 'entity.read'],
        scope: { kind: 'global' },
        legal_basis: 'Ata interna R-73',
      });
      expect((post!.body as { permissions: string[] }).permissions).not.toContain('role.manage');
    });
    vi.unstubAllGlobals();
  });

  it('lists every permission a delegation carries, and legacy single-permission rows', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/delegations',
        body: [
          {
            id: 'd1',
            from: 'me',
            to: 'u2',
            permission: 'entity.read',
            permissions: ['entity.read', 'book.open'],
            scope: { kind: 'global' },
            granted_at: '2026-07-08T00:00:00Z',
            starts_at: '2026-07-08T00:00:00Z',
            legal_basis: 'Ata interna R-74',
            revoked: false,
          },
        ],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'GET',
        match: '/v1/users',
        body: [
          {
            id: 'u2',
            username: 'joao.silva',
            display_name: 'João Silva',
            active: true,
            has_secret: true,
            has_attestation_key: false,
            has_recovery_phrase: false,
            created_at: '2026-01-01',
          },
        ],
      },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'me' }, permissions: [] } },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(
      <DelegacoesSection />,
      value(() => true, [grant('entity.read', 'role'), grant('book.open', 'role')]),
    );

    // Both verbs appear in the SAME row — they are one delegation, revoked as one unit.
    const row = (await screen.findByText('entity.read')).closest('tr')!;
    expect(within(row).getByText('book.open')).toBeTruthy();
    expect(within(row).getAllByRole('button', { name: 'Revogar' })).toHaveLength(1);
    vi.unstubAllGlobals();
  });

  it('lists starts_at and legal basis, with a missing legacy marker', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/delegations',
        body: [
          {
            id: 'd1',
            from: 'me',
            to: 'u2',
            permission: 'entity.read',
            scope: { kind: 'global' },
            granted_at: '2026-07-08T00:00:00Z',
            starts_at: '2026-07-08T00:00:00Z',
            legal_basis: 'Ata interna R-72',
            revoked: false,
          },
          {
            id: 'd2',
            from: 'me',
            to: 'u2',
            permission: 'book.open',
            scope: { kind: 'global' },
            granted_at: '2026-07-07T00:00:00Z',
            starts_at: '1970-01-01T00:00:00Z',
            revoked: false,
          },
        ],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'GET',
        match: '/v1/users',
        body: [
          {
            id: 'u2',
            username: 'joao.silva',
            display_name: 'João Silva',
            active: true,
            has_secret: true,
            has_attestation_key: false,
            has_recovery_phrase: false,
            created_at: '2026-01-01',
          },
        ],
      },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'me' }, permissions: [] } },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(
      <DelegacoesSection />,
      value(() => true, [grant('entity.read', 'role'), grant('book.open', 'role')]),
    );

    const currentRow = (await screen.findByText('entity.read')).closest('tr')!;
    expect(within(currentRow).getByText('2026-07-08T00:00:00Z')).toBeTruthy();
    expect(within(currentRow).getByText('Ata interna R-72')).toBeTruthy();

    const legacyRow = (await screen.findByText('book.open')).closest('tr')!;
    expect(within(legacyRow).getByText('1970-01-01T00:00:00Z')).toBeTruthy();
    expect(within(legacyRow).getByText('Em falta (legado)')).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('the grantor revokes their own delegation (DELETE /v1/delegations/{id})', async () => {
    const { fn, calls } = mockFetch([
      {
        method: 'GET',
        match: '/v1/delegations',
        body: [
          {
            id: 'd1',
            from: 'me',
            to: 'u2',
            permission: 'entity.read',
            scope: { kind: 'global' },
            granted_at: '2026-07-08T00:00:00Z',
            starts_at: '2026-07-08T00:00:00Z',
            legal_basis: 'Ata interna R-72',
            revoked: false,
          },
        ],
      },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
      {
        method: 'GET',
        match: '/v1/users',
        body: [
          {
            id: 'u2',
            username: 'joao.silva',
            display_name: 'João Silva',
            active: true,
            has_secret: true,
            has_attestation_key: false,
            has_recovery_phrase: false,
            created_at: '2026-01-01',
          },
        ],
      },
      { method: 'GET', match: '/v1/entities', body: [] },
      { method: 'GET', match: '/v1/books', body: [] },
      { method: 'GET', match: '/v1/session', body: { user: { id: 'me' }, permissions: [] } },
      { method: 'DELETE', match: '/v1/delegations/d1', status: 204, body: null },
    ]);
    vi.stubGlobal('fetch', fn);

    renderRbac(
      <DelegacoesSection />,
      value(() => true, [grant('entity.read', 'role')]),
    );

    const row = (await screen.findByText('entity.read')).closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: 'Revogar' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/delegations/d1'))).toBe(
        true,
      );
    });
    vi.unstubAllGlobals();
  });
});
