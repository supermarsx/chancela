/**
 * Route-stubbed browser proof for Settings > Funções seeded-role drift reconciliation.
 * It pins the explicit admin review/apply flow only: no initial write, add-only proposal,
 * empty apply body, and preservation of customized permissions plus unrelated roles.
 */
import { expect, test, type Locator, type Page, type Route } from '@playwright/test';
import {
  DEFAULT_SETTINGS,
  type Dashboard,
  type PermissionGrant,
  type RoleView,
  type SeededRoleReconciliationView,
  type Settings,
  type UserView,
} from '../src/api/types';

const USER_ID = 'b9aa8d60-1000-4000-8000-00000000f601';
const RECONCILIATION_PATH = '/v1/roles/platform-admin/seeded-drift-reconciliation';
const CUSTOM_PERMISSION = 'data.wipe';
const MISSING_DEFAULT_PERMISSION = 'platform.logs.write';

type ReconciliationCall = {
  method: string;
  pathname: string;
  body: unknown;
};

type SeededRoleFixtureState = {
  roles: RoleView[];
  settings: Settings;
};

test('seeded role drift requires explicit browser review and preserves custom state', async ({
  page,
}) => {
  const reconciliationCalls: ReconciliationCall[] = [];
  await routeSeededRoleDriftFixtures(page, reconciliationCalls, { canManageRoles: true });

  await page.goto('/configuracoes?sec=funcoes');

  await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Funções' })).toBeVisible();

  const ownerRow = roleRow(page, 'Owner');
  const platformRow = roleRow(page, 'Platform Administrator');
  const customRow = roleRow(page, 'Custom Reviewer');
  await expect(ownerRow).toContainText('Protegida');
  await expect(ownerRow).toContainText('3 permissões');
  await expect(platformRow).toContainText('2 permissões');
  await expect(platformRow).toContainText('Revisão manual');
  await expect(platformRow).toContainText(`Defaults em falta: ${MISSING_DEFAULT_PERMISSION}`);
  await expect(customRow).toContainText('2 permissões');
  await expect(customRow).not.toContainText('Revisão manual');
  expect(reconciliationCalls.filter((call) => call.method === 'POST')).toEqual([]);

  await platformRow.getByRole('button', { name: 'Rever defaults' }).click();

  await expect(platformRow.getByText(`Adicionar só: ${MISSING_DEFAULT_PERMISSION}`)).toBeVisible();
  expect(reconciliationCalls).toEqual([
    { method: 'GET', pathname: RECONCILIATION_PATH, body: null },
  ]);

  await platformRow.getByRole('button', { name: 'Aplicar defaults em falta' }).click();

  await expect(page.getByText(`Reconciliação aplicada: ${MISSING_DEFAULT_PERMISSION}`)).toBeVisible();
  await expect(platformRow).toContainText('3 permissões');
  await expect(platformRow).toContainText('Atual');
  await expect(platformRow).not.toContainText('Revisão manual');
  await expect(ownerRow).toContainText('3 permissões');
  await expect(customRow).toContainText('2 permissões');
  expect(reconciliationCalls).toEqual([
    { method: 'GET', pathname: RECONCILIATION_PATH, body: null },
    { method: 'POST', pathname: RECONCILIATION_PATH, body: {} },
  ]);

  await platformRow.getByRole('button', { name: 'Editar' }).click();
  await expect(checkedPermission(page, CUSTOM_PERMISSION)).toBeChecked();
  await expect(checkedPermission(page, MISSING_DEFAULT_PERMISSION)).toBeChecked();
});

test('seeded role drift review is disabled without role.manage', async ({ page }) => {
  const reconciliationCalls: ReconciliationCall[] = [];
  await routeSeededRoleDriftFixtures(page, reconciliationCalls, { canManageRoles: false });

  await page.goto('/configuracoes?sec=funcoes');

  const platformRow = roleRow(page, 'Platform Administrator');
  await expect(platformRow).toContainText('Revisão manual');
  const review = platformRow.getByRole('button', { name: 'Rever defaults' });
  await expect(review).toHaveAttribute('aria-disabled', 'true');

  await review.dispatchEvent('click');
  expect(reconciliationCalls).toEqual([]);
});

async function routeSeededRoleDriftFixtures(
  page: Page,
  reconciliationCalls: ReconciliationCall[],
  options: { canManageRoles: boolean },
): Promise<void> {
  const state: SeededRoleFixtureState = {
    roles: roleFixtures({ reconciled: false }),
    settings: {
      ...DEFAULT_SETTINGS,
      onboarding: { completed: true, completed_at: '2026-07-13T09:00:00.000Z' },
    },
  };

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (method === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, sessionFixture(options.canManageRoles));
      return;
    }
    if (method === 'GET' && pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: [rosterUserFixture()],
      });
      return;
    }
    if (method === 'GET' && pathname === '/v1/session/permissions') {
      await fulfillJson(route, sessionPermissionsFixture(options.canManageRoles));
      return;
    }
    if (method === 'GET' && pathname === '/v1/users') {
      await fulfillJson(route, [userFixture()]);
      return;
    }
    if (method === 'GET' && pathname === '/v1/settings') {
      await fulfillJson(route, state.settings);
      return;
    }
    if (method === 'PUT' && pathname === '/v1/settings') {
      state.settings = request.postDataJSON() as Settings;
      await fulfillJson(route, state.settings);
      return;
    }
    if (method === 'GET' && pathname === '/v1/dashboard') {
      await fulfillJson(route, dashboardFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/notifications/triage') {
      await fulfillJson(route, { entries: [], durable: true, max_entries_per_owner: 500 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 0 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/roles') {
      await fulfillJson(route, state.roles);
      return;
    }
    if (method === 'GET' && pathname === '/v1/permissions') {
      await fulfillJson(route, permissionCatalogFixture());
      return;
    }
    if (pathname === RECONCILIATION_PATH) {
      const body = method === 'POST' ? request.postDataJSON() : null;
      reconciliationCalls.push({ method, pathname, body });
      if (method === 'GET') {
        await fulfillJson(route, reconciliationFixture({ applied: false }));
        return;
      }
      if (method === 'POST') {
        state.roles = roleFixtures({ reconciled: true });
        await fulfillJson(route, reconciliationFixture({ applied: true }));
        return;
      }
    }

    await fulfillJson(
      route,
      { error: `Unhandled seeded role drift e2e route: ${method} ${pathname}` },
      500,
    );
  });
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function roleRow(page: Page, name: string): Locator {
  return page.getByRole('row').filter({ hasText: name });
}

function checkedPermission(page: Page, permission: string): Locator {
  return page.locator('label.rbac-matrix__perm').filter({ hasText: permission }).locator('input');
}

function roleFixtures({ reconciled }: { reconciled: boolean }): RoleView[] {
  return [
    {
      id: 'owner',
      name: 'Owner',
      permissions: ['role.manage', CUSTOM_PERMISSION, MISSING_DEFAULT_PERMISSION],
      protected: true,
      seeded_role_drift: null,
    },
    {
      id: 'platform-admin',
      name: 'Platform Administrator',
      permissions: reconciled
        ? ['role.manage', CUSTOM_PERMISSION, MISSING_DEFAULT_PERMISSION]
        : ['role.manage', CUSTOM_PERMISSION],
      protected: false,
      seeded_role_drift: reconciled
        ? { missing_default_permissions: [], requires_manual_review: false }
        : {
            missing_default_permissions: [MISSING_DEFAULT_PERMISSION],
            requires_manual_review: true,
          },
    },
    {
      id: 'custom-reviewer',
      name: 'Custom Reviewer',
      permissions: ['entity.read', 'ledger.read'],
      protected: false,
      seeded_role_drift: null,
    },
  ];
}

function reconciliationFixture({
  applied,
}: {
  applied: boolean;
}): SeededRoleReconciliationView {
  return {
    role_id: 'platform-admin',
    role_name: 'Platform Administrator',
    current_permissions: applied
      ? ['role.manage', CUSTOM_PERMISSION, MISSING_DEFAULT_PERMISSION]
      : ['role.manage', CUSTOM_PERMISSION],
    missing_default_permissions: applied ? [] : [MISSING_DEFAULT_PERMISSION],
    proposed_permissions: ['role.manage', CUSTOM_PERMISSION, MISSING_DEFAULT_PERMISSION],
    applied_permissions: applied ? [MISSING_DEFAULT_PERMISSION] : [],
    applied,
    requires_manual_review: !applied,
  };
}

function permissionCatalogFixture() {
  return {
    permissions: [
      { permission: 'entity.read', meta: false },
      { permission: 'ledger.read', meta: false },
      { permission: CUSTOM_PERMISSION, meta: false },
      { permission: MISSING_DEFAULT_PERMISSION, meta: false },
      { permission: 'role.manage', meta: true },
    ],
  };
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function sessionGrants(canManageRoles: boolean): PermissionGrant[] {
  return permissionCatalogFixture()
    .permissions.map((info) => info.permission)
    .filter((permission) => canManageRoles || permission !== 'role.manage')
    .map(permissionGrant);
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'operator.rbac',
    display_name: 'Operator RBAC',
    created_at: '2026-07-13T09:00:00.000Z',
    active: true,
    has_secret: true,
    has_attestation_key: false,
    has_recovery_phrase: false,
  };
}

function rosterUserFixture() {
  const user = userFixture();
  return {
    id: user.id,
    username: user.username,
    display_name: user.display_name,
    has_secret: user.has_secret,
  };
}

function sessionFixture(canManageRoles: boolean) {
  return {
    user: userFixture(),
    permissions: sessionGrants(canManageRoles),
  };
}

function sessionPermissionsFixture(canManageRoles: boolean) {
  const user = userFixture();
  return {
    user_id: user.id,
    username: user.username,
    role_assignments: [{ role_id: 'platform-admin', scope: { kind: 'global' } }],
    permissions: sessionGrants(canManageRoles),
  };
}

function dashboardFixture(): Dashboard {
  return {
    entities: 0,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: 0,
    ledger_valid: true,
    current_work: {
      open_books: [],
      act_counts_by_state: {
        Draft: 0,
        Review: 0,
        Convened: 0,
        Deliberated: 0,
        TextApproved: 0,
        Signing: 0,
        Sealed: 0,
        Archived: 0,
      },
    },
    alerts: [],
    reminders: [],
    recent_events: [],
  };
}
