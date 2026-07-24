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
import { formatTimestamp } from '../../format';
import { makeClient } from '../../test/utils';
import { ToastProvider } from '../../ui';
import {
  ALLOW_ALL_PERMISSIONS,
  StaticPermissionsProvider,
  type PermissionsContextValue,
} from '../session/permissions';
import type { PermissionGrant, UserView } from '../../api/types';
import { PermissionMatrix } from './PermissionMatrix';
import { RolesSection } from './RolesSection';
import { RoleAssignmentManager } from './RoleAssignmentManager';
import { DelegationsSection } from './DelegationsSection';

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
      // A 204 must be constructed with a null body — `new Response('', { status: 204 })` throws
      // "Invalid response status code", which would arrive at the caller as a request failure
      // rather than as the success the endpoint actually returns.
      new Response(status === 204 ? null : JSON.stringify(payload ?? null), {
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
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
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

describe('RolesSection — role create + gating', () => {
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

    renderRbac(<RolesSection />);
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

    renderRbac(<RolesSection />);
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
      <RolesSection />,
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

    renderRbac(<RolesSection />);

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

    renderRbac(<RolesSection />);

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
      <RolesSection />,
      value((p) => p !== 'role.manage'),
    );

    const row = (await screen.findByText('Platform Administrator')).closest('tr')!;
    const review = within(row).getByRole('button', { name: 'Rever defaults' });
    expect(review.getAttribute('aria-disabled')).toBe('true');
    vi.unstubAllGlobals();
  });
});

// --- The roles half of "delegate a função" (tg4) ---------------------------------
//
// A delegation conveys *the live contents of the função*, expanded against the current catalog at
// every authorization decision (t44). So the role editor is not a cosmetic screen: whatever it
// PATCHes becomes, immediately, the authority every live delegation of that função conveys. These
// pin the ways that editor could silently convey the wrong set.

describe('RolesSection — editing and deleting a função', () => {
  const ROLE = {
    id: 'r7',
    name: 'Secretário',
    permissions: ['entity.read', 'book.open'],
    protected: false,
  };

  function stubRoles(extra: Handler[] = [], roles: unknown[] = [ROLE]) {
    const { fn, calls } = mockFetch([
      ...extra,
      { method: 'GET', match: '/v1/roles', body: roles },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
    ]);
    vi.stubGlobal('fetch', fn);
    return calls;
  }

  it('opens the editor pre-ticked with what the função already carries, and PATCHes the whole set', async () => {
    const calls = stubRoles([
      { method: 'PATCH', match: '/v1/roles/r7', body: { ...ROLE, permissions: ['entity.read'] } },
    ]);
    renderRbac(<RolesSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Editar' }));
    expect(screen.getByRole('heading', { name: 'Editar função' })).toBeTruthy();
    // The name and the current permission set are prefilled. An editor that opened empty would
    // strip a função's whole authority — and with it every live delegation of that função — the
    // moment an operator renamed it.
    expect((screen.getByLabelText('Nome da função') as HTMLInputElement).value).toBe('Secretário');
    const box = (p: string) =>
      screen.getByText(p).closest('label')!.querySelector('input')! as HTMLInputElement;
    expect(box('entity.read').checked).toBe(true);
    expect(box('book.open').checked).toBe(true);
    expect(box('entity.create').checked).toBe(false);

    // Untick one and save: the PATCH carries the full resulting set, not a delta.
    fireEvent.click(box('book.open'));
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    await waitFor(() => {
      const patch = calls.find((c) => c.method === 'PATCH');
      expect(patch, 'a PATCH was issued').toBeTruthy();
      expect(patch!.url).toContain('/v1/roles/r7');
      expect(patch!.body).toEqual({ name: 'Secretário', permissions: ['entity.read'] });
    });
    // And the editor closes back to the list rather than leaving a stale draft on screen.
    expect(await screen.findByRole('button', { name: 'Editar' })).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('trims the name and refuses to save a blank one', async () => {
    const calls = stubRoles([{ method: 'PATCH', match: '/v1/roles/r7', body: ROLE }]);
    renderRbac(<RolesSection />);
    fireEvent.click(await screen.findByRole('button', { name: 'Editar' }));

    const name = screen.getByLabelText('Nome da função');
    fireEvent.change(name, { target: { value: '   ' } });
    expect(
      (screen.getByRole('button', { name: 'Guardar' }) as HTMLButtonElement).disabled,
      'a whitespace-only name is not a name',
    ).toBe(true);

    fireEvent.change(name, { target: { value: '  Secretário-Geral  ' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));
    await waitFor(() => {
      const patch = calls.find((c) => c.method === 'PATCH');
      expect(patch!.body).toMatchObject({ name: 'Secretário-Geral' });
    });
    vi.unstubAllGlobals();
  });

  it('cancelling the editor discards the draft instead of writing it', async () => {
    const calls = stubRoles();
    renderRbac(<RolesSection />);
    fireEvent.click(await screen.findByRole('button', { name: 'Editar' }));

    fireEvent.change(screen.getByLabelText('Nome da função'), { target: { value: 'Outra coisa' } });
    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));

    expect(await screen.findByText('Secretário')).toBeTruthy();
    expect(calls.some((c) => c.method !== 'GET')).toBe(false);
    // Reopening starts from the stored role again, not from the abandoned draft.
    fireEvent.click(screen.getByRole('button', { name: 'Editar' }));
    expect((screen.getByLabelText('Nome da função') as HTMLInputElement).value).toBe('Secretário');
    vi.unstubAllGlobals();
  });

  it('deleting a função takes two deliberate steps, and cancelling writes nothing', async () => {
    const calls = stubRoles([{ method: 'DELETE', match: '/v1/roles/r7', status: 204 }]);
    renderRbac(<RolesSection />);

    // The first click only arms the confirmation — deleting a função silently drops the authority
    // of every delegation of it, so a single misclick must not do it.
    fireEvent.click(await screen.findByRole('button', { name: 'Eliminar' }));
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Cancelar' }));
    expect(calls.some((c) => c.method === 'DELETE')).toBe(false);
    expect(screen.getByRole('button', { name: 'Eliminar' })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Eliminar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar eliminação' }));
    await waitFor(() => {
      const del = calls.find((c) => c.method === 'DELETE');
      expect(del).toBeTruthy();
      expect(del!.url).toContain('/v1/roles/r7');
    });
    expect(await screen.findByText('Função eliminada')).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('a refused delete surfaces the server’s reason and disarms the confirmation', async () => {
    // The server is the real guard. When it refuses, the UI must say so rather than leaving the
    // row looking half-deleted with the confirm still armed.
    const calls = stubRoles([
      {
        method: 'DELETE',
        match: '/v1/roles/r7',
        status: 409,
        body: { error: 'A função está atribuída a utilizadores.' },
      },
    ]);
    renderRbac(<RolesSection />);

    fireEvent.click(await screen.findByRole('button', { name: 'Eliminar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar eliminação' }));

    expect(await screen.findByText(/A função está atribuída a utilizadores\./)).toBeTruthy();
    await waitFor(() => expect(calls.filter((c) => c.method === 'DELETE')).toHaveLength(1));
    expect(await screen.findByRole('button', { name: 'Eliminar' })).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Confirmar eliminação' })).toBeNull();
    // The row is still there — nothing was removed optimistically.
    expect(screen.getByText('Secretário')).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('a protected função is read-only: no edit, no delete, but its authority is still shown', async () => {
    stubRoles(
      [],
      [
        {
          id: 'owner',
          name: 'Proprietário',
          permissions: ['entity.read', 'role.manage'],
          protected: true,
        },
      ],
    );
    renderRbac(<RolesSection />);

    const row = (await screen.findByText('Proprietário')).closest('tr')!;
    expect(within(row).getByText('Protegida')).toBeTruthy();
    expect(within(row).getByText('Só de leitura')).toBeTruthy();
    // Not merely disabled — not offered. The server 403s any such write, and offering a control
    // that cannot work is the dishonest option.
    expect(within(row).queryByRole('button', { name: 'Editar' })).toBeNull();
    expect(within(row).queryByRole('button', { name: 'Eliminar' })).toBeNull();
    // The set it carries is still visible, so an operator can see what Owner means.
    expect(within(row).getByText('2 permissões')).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('offers an empty state rather than a headed table with no rows', async () => {
    stubRoles([], []);
    renderRbac(<RolesSection />);

    expect(await screen.findByText('Sem funções')).toBeTruthy();
    expect(screen.getByText('Crie uma função para agrupar permissões.')).toBeTruthy();
    expect(document.querySelector('table')).toBeNull();
    vi.unstubAllGlobals();
  });

  it('says a função is current when it has no seeded drift, and offers no review control', async () => {
    stubRoles(
      [],
      [
        {
          ...ROLE,
          seeded_role_drift: { missing_default_permissions: [], requires_manual_review: false },
        },
      ],
    );
    renderRbac(<RolesSection />);

    const row = (await screen.findByText('Secretário')).closest('tr')!;
    expect(within(row).getByText('Atual')).toBeTruthy();
    expect(within(row).queryByText('Revisão manual')).toBeNull();
    expect(within(row).queryByRole('button', { name: 'Rever defaults' })).toBeNull();
    vi.unstubAllGlobals();
  });

  it('a review that finds nothing missing says so instead of offering an empty apply', async () => {
    // The drift flag comes from the list response and can be stale. The proposal is re-read live,
    // and an "apply" over an empty set would be a write that changes nothing while looking like
    // a reconciliation happened.
    const calls = stubRoles(
      [
        {
          method: 'GET',
          match: '/v1/roles/r7/seeded-drift-reconciliation',
          body: {
            role_id: 'r7',
            role_name: 'Secretário',
            current_permissions: ['entity.read'],
            missing_default_permissions: [],
            proposed_permissions: ['entity.read'],
            applied_permissions: [],
            applied: false,
            requires_manual_review: false,
          },
        },
      ],
      [
        {
          ...ROLE,
          seeded_role_drift: {
            missing_default_permissions: ['book.open'],
            requires_manual_review: true,
          },
        },
      ],
    );
    renderRbac(<RolesSection />);

    const row = (await screen.findByText('Secretário')).closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: 'Rever defaults' }));

    expect(await screen.findByText('A função já não tem defaults semeados em falta')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Aplicar defaults em falta' })).toBeNull();
    expect(calls.some((c) => c.method === 'POST')).toBe(false);
    vi.unstubAllGlobals();
  });

  it('surfaces a failed role list rather than rendering an empty catalog', async () => {
    // An empty table and a broken endpoint look identical to an operator; conflating them would
    // let someone conclude a função was deleted when the server simply did not answer.
    const { fn } = mockFetch([
      { method: 'GET', match: '/v1/roles', status: 503, body: { error: 'catálogo indisponível' } },
      { method: 'GET', match: '/v1/permissions', body: CATALOG },
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<RolesSection />);

    expect(await screen.findByText(/catálogo indisponível/)).toBeTruthy();
    expect(screen.queryByText('Sem funções')).toBeNull();
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

describe('DelegationsSection — hand over a função, suspend it, revoke it', () => {
  /** The catalog the picker reads: one fully-held função, one above the ceiling, one meta-laden. */
  const ROLES = [
    {
      id: 'r-sec',
      name: 'Secretário',
      permissions: ['entity.read', 'book.open'],
      protected: false,
    },
    {
      id: 'r-fat',
      name: 'Auxiliar Júnior',
      permissions: ['entity.read', 'entity.create'],
      protected: false,
    },
    {
      id: 'r-meta',
      name: 'Gestor de Acessos',
      permissions: ['entity.read', 'role.manage'],
      protected: false,
    },
  ];

  const GRANTEES = [
    {
      id: 'u2',
      username: 'joao.silva',
      display_name: 'João Silva',
      active: true,
      has_secret: true,
      has_attestation_key: false,
      has_recovery_phrase: false,
      has_totp: false,
      two_factor_required: false,
      language: 'auto',
      role_assignments: [],
      created_at: '2026-01-01',
    },
  ];

  /** A role-shaped delegation row as the server renders it. */
  function delegation(over: Record<string, unknown> = {}) {
    return {
      id: 'd1',
      from: 'me',
      to: 'u2',
      roles: [
        { id: 'r-sec', name: 'Secretário', permissions: ['entity.read', 'book.open'], known: true },
      ],
      permissions: ['entity.read', 'book.open'],
      scope: { kind: 'global' },
      granted_at: '2026-07-08T00:00:00Z',
      starts_at: '2026-07-08T00:00:00Z',
      legal_basis: 'Ata interna R-72',
      revoked: false,
      suspended: false,
      ...over,
    };
  }

  const BASE = [
    { method: 'GET', match: '/v1/permissions', body: CATALOG },
    { method: 'GET', match: '/v1/roles', body: ROLES },
    { method: 'GET', match: '/v1/users', body: GRANTEES },
    { method: 'GET', match: '/v1/entities', body: [] },
    { method: 'GET', match: '/v1/books', body: [] },
    { method: 'GET', match: '/v1/session', body: { user: { id: 'me' }, permissions: [] } },
  ];

  // The grantor holds entity.read + book.open via a role, and the meta role.manage too. So
  // "Secretário" is delegable; "Auxiliar Júnior" is not (entity.create is above their ceiling);
  // "Gestor de Acessos" is not (it carries a meta verb — never delegable, whoever you are).
  const GRANTOR = () =>
    value(
      () => true,
      [grant('entity.read', 'role'), grant('book.open', 'role'), grant('role.manage', 'role')],
    );

  it('offers only funções the grantor fully holds, and shows what each one carries', async () => {
    const { fn } = mockFetch([{ method: 'GET', match: '/v1/delegations', body: [] }, ...BASE]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    fireEvent.click(await screen.findByRole('button', { name: 'Nova delegação' }));
    const group = () => screen.getByRole('group', { name: 'Funções a delegar' });
    await waitFor(() => {
      expect(within(group()).getByText('Secretário')).toBeTruthy();
    });
    // A função carrying authority the grantor lacks is not offered…
    expect(within(group()).queryByText('Auxiliar Júnior')).toBeNull();
    // …nor is one carrying a meta-permission, even though the grantor holds that verb.
    expect(within(group()).queryByText('Gestor de Acessos')).toBeNull();
    // The authority the função hands over is inspectable before you hand it over.
    expect(within(group()).getByText('entity.read')).toBeTruthy();
    expect(within(group()).getByText('book.open')).toBeTruthy();
    // Nothing is pre-selected: delegating is an explicit act, never a default.
    expect(
      within(group())
        .getAllByRole('checkbox')
        .every((b) => !(b as HTMLInputElement).checked),
    ).toBe(true);
    vi.unstubAllGlobals();
  });

  it('grants a FUNÇÃO — the request carries role ids, never a permission list', async () => {
    const startsAtInput = '2026-01-01T09:30';
    const expectedStartsAt = new Date(startsAtInput).toISOString();
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [] },
      ...BASE,
      { method: 'POST', match: '/v1/delegations', body: delegation() },
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    fireEvent.click(await screen.findByRole('button', { name: 'Nova delegação' }));
    await waitFor(() => {
      expect(
        screen.getByRole('group', { name: 'Funções a delegar' }).querySelectorAll('input').length,
      ).toBe(1);
    });
    fireEvent.click(
      within(screen.getByRole('group', { name: 'Funções a delegar' })).getAllByRole('checkbox')[0],
    );
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
      // One authorising act: one função set, one scope, one lifetime, one legal basis.
      expect(post!.body).toMatchObject({
        to: 'u2',
        roles: ['r-sec'],
        scope: { kind: 'global' },
        starts_at: expectedStartsAt,
        legal_basis: 'Ata interna R-72',
      });
      // The retired permission-shaped fields are never sent.
      expect(post!.body).not.toHaveProperty('permissions');
      expect(post!.body).not.toHaveProperty('permission');
    });
    vi.unstubAllGlobals();
  });

  it('lists each função by name with the authority it carries, in one revocable row', async () => {
    const { fn } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [delegation()] },
      ...BASE,
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    const row = (await screen.findByRole('cell', { name: /Secretário/ })).closest('tr')!;
    // The função is named for a human, and its current contents are shown alongside.
    expect(within(row).getByText('entity.read')).toBeTruthy();
    expect(within(row).getByText('book.open')).toBeTruthy();
    // One delegation, one Revogar control — the funções travel and are withdrawn together.
    expect(within(row).getAllByRole('button', { name: 'Revogar' })).toHaveLength(1);
    vi.unstubAllGlobals();
  });

  it('renders a legacy permission-shaped row and a função removed from the catalog', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/delegations',
        body: [
          // A pre-t44 record: no funções, its verbs carried directly. Still resolves server-side.
          {
            id: 'd-legacy',
            from: 'me',
            to: 'u2',
            roles: [],
            permission: 'entity.read',
            permissions: ['entity.read'],
            scope: { kind: 'global' },
            granted_at: '2026-07-07T00:00:00Z',
            starts_at: '1970-01-01T00:00:00Z',
            revoked: false,
            suspended: false,
          },
          // A função that has left the catalog: named honestly, carrying nothing.
          delegation({
            id: 'd-gone',
            roles: [{ id: 'r-gone', name: 'r-gone', permissions: [], known: false }],
            permissions: [],
          }),
        ],
      },
      ...BASE,
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    const legacyRow = (await screen.findByText('entity.read')).closest('tr')!;
    // The start of a delegation renders through the shared evidentiary formatter, not as the
    // raw wire string. Asserting the `datetime` attribute rather than the visible text pins the
    // exact instant AND survives a formatting change — the visible form is locale- and
    // zone-dependent, the attribute is neither.
    const startsAt = within(legacyRow).getByText(formatTimestamp('1970-01-01T00:00:00Z'));
    expect(startsAt.getAttribute('datetime')).toBe('1970-01-01T00:00:00Z');
    expect(within(legacyRow).getByText('Em falta (legado)')).toBeTruthy();
    // Named honestly in the row (and in the função filter, hence *All*).
    expect(screen.getAllByText('Função removida do catálogo').length).toBeGreaterThan(0);
    vi.unstubAllGlobals();
  });

  it('suspends and resumes a delegation (POST /v1/delegations/{id}/{suspend,resume})', async () => {
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [delegation()] },
      ...BASE,
      {
        method: 'POST',
        match: '/v1/delegations/d1/suspend',
        body: delegation({ suspended: true }),
      },
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    const row = (await screen.findByRole('cell', { name: /Secretário/ })).closest('tr')!;
    expect(within(row).getByText('Ativa')).toBeTruthy();
    fireEvent.click(within(row).getByRole('button', { name: 'Suspender' }));
    await waitFor(() => {
      expect(
        calls.some((c) => c.method === 'POST' && c.url.includes('/v1/delegations/d1/suspend')),
      ).toBe(true);
    });
    vi.unstubAllGlobals();
  });

  it('shows a suspended delegation as suspended, still listed, with a resume control', async () => {
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [delegation({ suspended: true })] },
      ...BASE,
      { method: 'POST', match: '/v1/delegations/d1/resume', body: delegation() },
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    // A suspended delegation is NOT hidden: it conveys nothing because the server stops it where
    // authority resolves, and the row says so honestly.
    const row = (await screen.findByRole('cell', { name: /Secretário/ })).closest('tr')!;
    expect(within(row).getByText('Suspensa')).toBeTruthy();
    fireEvent.click(within(row).getByRole('button', { name: 'Retomar' }));
    await waitFor(() => {
      expect(
        calls.some((c) => c.method === 'POST' && c.url.includes('/v1/delegations/d1/resume')),
      ).toBe(true);
    });
    vi.unstubAllGlobals();
  });

  it('filters the list by status, função, delegante, delegado and âmbito', async () => {
    const { fn } = mockFetch([
      {
        method: 'GET',
        match: '/v1/delegations',
        body: [
          delegation(),
          delegation({
            id: 'd2',
            to: 'me',
            from: 'u2',
            suspended: true,
            scope: { kind: 'entity', id: 'e1' },
            roles: [
              { id: 'r-fat', name: 'Auxiliar Júnior', permissions: ['entity.create'], known: true },
            ],
            permissions: ['entity.create'],
          }),
        ],
      },
      ...BASE,
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    await screen.findByRole('cell', { name: /Secretário/ });
    expect(screen.getByRole('cell', { name: /Auxiliar Júnior/ })).toBeTruthy();

    // Status: only the suspended one survives.
    fireEvent.change(screen.getByLabelText('Estado'), { target: { value: 'suspended' } });
    expect(screen.queryByRole('cell', { name: /Secretário/ })).toBeNull();
    expect(screen.getByRole('cell', { name: /Auxiliar Júnior/ })).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Estado'), { target: { value: '' } });

    // Função.
    fireEvent.change(screen.getByLabelText('Função'), { target: { value: 'r-sec' } });
    expect(screen.getByRole('cell', { name: /Secretário/ })).toBeTruthy();
    expect(screen.queryByRole('cell', { name: /Auxiliar Júnior/ })).toBeNull();
    fireEvent.change(screen.getByLabelText('Função'), { target: { value: '' } });

    // Delegante / delegado.
    fireEvent.change(screen.getByLabelText('De'), { target: { value: 'u2' } });
    expect(screen.queryByRole('cell', { name: /Secretário/ })).toBeNull();
    fireEvent.change(screen.getByLabelText('De'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Para'), { target: { value: 'u2' } });
    expect(screen.queryByRole('cell', { name: /Auxiliar Júnior/ })).toBeNull();
    fireEvent.change(screen.getByLabelText('Para'), { target: { value: '' } });

    // Âmbito — and a filter that matches nothing says so rather than showing an empty table.
    const scopeSelect = screen.getByLabelText('Âmbito') as HTMLSelectElement;
    const entityOption = [...scopeSelect.options].find((o) => o.value.includes('entity'))!;
    fireEvent.change(scopeSelect, { target: { value: entityOption.value } });
    expect(screen.queryByRole('cell', { name: /Secretário/ })).toBeNull();
    fireEvent.change(screen.getByLabelText('Estado'), { target: { value: 'revoked' } });
    expect(screen.getByText('Nenhuma delegação corresponde aos filtros.')).toBeTruthy();
    vi.unstubAllGlobals();
  });

  it('the grantor revokes their own delegation (DELETE /v1/delegations/{id})', async () => {
    const { fn, calls } = mockFetch([
      { method: 'GET', match: '/v1/delegations', body: [delegation()] },
      ...BASE,
      { method: 'DELETE', match: '/v1/delegations/d1', status: 204, body: null },
    ]);
    vi.stubGlobal('fetch', fn);
    renderRbac(<DelegationsSection />, GRANTOR());

    const row = (await screen.findByRole('cell', { name: /Secretário/ })).closest('tr')!;
    fireEvent.click(within(row).getByRole('button', { name: 'Revogar' }));
    await waitFor(() => {
      expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/delegations/d1'))).toBe(
        true,
      );
    });
    vi.unstubAllGlobals();
  });
});
