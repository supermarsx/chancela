/**
 * Route-stubbed browser coverage for the Data Management SQLCipher key-rotation path.
 * The API replies are secret-free fixtures so the test pins the UI execution flow without
 * depending on live storage providers.
 */
import { expect, test, type Page, type Route } from './fixtures';
import {
  DEFAULT_SETTINGS,
  type Dashboard,
  type DataKeyRotationExecuteBody,
  type DataKeyRotationExecution,
  type DataKeyRotationPreflight,
  type DataKeyRotationPreflightBody,
  type DataStatusResponse,
  type PermissionGrant,
  type Settings,
  type UserView,
} from '../src/api/types';

const USER_ID = 'a3f14f20-9000-4000-8000-00000000d901';
const PREFLIGHT_CURRENT_KEY = 'current-sqlcipher-key-e2e';
const PREFLIGHT_REPLACEMENT_KEY = 'preflight-replacement-key-e2e';
const EXECUTION_REPLACEMENT_KEY = 'execution-replacement-key-e2e';

test('data key rotation preflight reveals guarded execution and submits only the replacement key', async ({
  page,
}) => {
  const preflightBodies: DataKeyRotationPreflightBody[] = [];
  const executionBodies: DataKeyRotationExecuteBody[] = [];
  await routeDataKeyRotationFixtures(page, preflightBodies, executionBodies);

  await page.goto('/settings/data');

  await expect(page.getByRole('heading', { name: 'Estado do armazenamento' })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Verificação prévia da rotação da chave de dados' }),
  ).toBeVisible();
  await expect(page.getByText('Durável aberto')).toBeVisible();

  await page.getByLabel('Chave atual').fill(PREFLIGHT_CURRENT_KEY);
  await page.getByLabel('Chave de substituição').fill(PREFLIGHT_REPLACEMENT_KEY);

  const preflightResponse = waitForApiResponse(page, '/v1/data/key-rotation/preflight', 'POST');
  await page.getByRole('button', { name: 'Verificar rotação' }).click();
  expect((await preflightResponse).status()).toBe(200);

  expect(preflightBodies).toEqual([
    {
      current_key: PREFLIGHT_CURRENT_KEY,
      new_key: PREFLIGHT_REPLACEMENT_KEY,
    },
  ]);

  await expect(page.getByText('Resultado da verificação')).toBeVisible();
  await expect(page.locator('.badge').filter({ hasText: 'ready' })).toBeVisible();
  await expect(page.getByText('Sem bloqueios indicados.')).toBeVisible();
  await expect(page.getByLabel('Chave atual')).toHaveValue('');
  await expect(page.getByLabel('Chave de substituição')).toHaveValue('');

  const executionForm = page.getByRole('form', { name: 'Execução da rotação SQLCipher' });
  await expect(executionForm).toBeVisible();
  await executionForm.getByLabel('Nova chave SQLCipher').fill(EXECUTION_REPLACEMENT_KEY);

  const executionResponse = waitForApiResponse(page, '/v1/data/key-rotation', 'POST');
  await executionForm.getByRole('button', { name: 'Executar rekey SQLCipher' }).click();
  expect((await executionResponse).status()).toBe(200);

  expect(executionBodies).toEqual([
    {
      new_key: EXECUTION_REPLACEMENT_KEY,
    },
  ]);
  expect(executionBodies[0]).not.toHaveProperty('current_key');

  await expect(page.getByText('Resultado da execução SQLCipher')).toBeVisible();
  await expect(page.locator('.badge').filter({ hasText: 'rekey_applied' })).toBeVisible();
  await expect(page.getByText('sqlcipher_rekey')).toBeVisible();
  await expect(page.getByText('Integridade pós-rekey')).toBeVisible();
  await expect(executionForm.getByLabel('Nova chave SQLCipher')).toHaveValue('');

  const body = page.locator('body');
  await expect(body).not.toContainText(PREFLIGHT_CURRENT_KEY);
  await expect(body).not.toContainText(PREFLIGHT_REPLACEMENT_KEY);
  await expect(body).not.toContainText(EXECUTION_REPLACEMENT_KEY);
});

async function routeDataKeyRotationFixtures(
  page: Page,
  preflightBodies: DataKeyRotationPreflightBody[],
  executionBodies: DataKeyRotationExecuteBody[],
): Promise<void> {
  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (method === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, sessionFixture());
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
      await fulfillJson(route, sessionPermissionsFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/users') {
      await fulfillJson(route, [userFixture()]);
      return;
    }
    if (method === 'GET' && pathname === '/v1/settings') {
      await fulfillJson(route, settingsFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/dashboard') {
      await fulfillJson(route, dashboardFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/notifications/triage') {
      await fulfillJson(route, {
        entries: [],
        durable: true,
        max_entries_per_owner: 500,
      });
      return;
    }
    if (method === 'GET' && pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 12 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/data/status') {
      await fulfillJson(route, dataStatusFixture());
      return;
    }
    if (method === 'POST' && pathname === '/v1/data/key-rotation/preflight') {
      preflightBodies.push(request.postDataJSON() as DataKeyRotationPreflightBody);
      await fulfillJson(route, dataKeyRotationPreflightFixture());
      return;
    }
    if (method === 'POST' && pathname === '/v1/data/key-rotation') {
      executionBodies.push(request.postDataJSON() as DataKeyRotationExecuteBody);
      await fulfillJson(route, dataKeyRotationExecutionFixture());
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled data key rotation e2e route: ${method} ${pathname}` },
      500,
    );
  });
}

async function waitForApiResponse(page: Page, pathname: string, method: string) {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === pathname && response.request().method() === method;
  });
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'operator.keyrotation',
    display_name: 'Operator Key Rotation',
    created_at: '2026-07-10T09:00:00.000Z',
    active: true,
    has_secret: false,
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

function sessionFixture() {
  return {
    user: userFixture(),
    permissions: [
      'ledger.read',
      'settings.manage',
      'settings.read',
      'user.manage',
    ].map(permissionGrant),
  };
}

function sessionPermissionsFixture() {
  const user = userFixture();
  return {
    user_id: user.id,
    username: user.username,
    role_assignments: [{ role_id: 'owner', scope: { kind: 'global' } }],
    permissions: sessionFixture().permissions,
  };
}

function settingsFixture(): Settings {
  return {
    ...DEFAULT_SETTINGS,
    onboarding: { completed: true, completed_at: '2026-07-10T09:00:00.000Z' },
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
    ledger_length: 12,
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

function dataStatusFixture(): DataStatusResponse {
  return {
    generated_at: '2026-07-10T09:15:00.000Z',
    persistence: {
      mode: 'durable',
      data_dir_configured: true,
      durable_store_open: true,
      database_encryption_configured: true,
      store_schema_version: 7,
      ledger_length: 12,
      ledger_verified: true,
      degraded: false,
    },
    data_dir: {
      path: 'F:\\Chancela\\Data',
      exists: true,
      is_directory: true,
    },
    permissions: {
      read_dir: { ok: true, checked: true, message: 'ok' },
      create_file: { ok: true, checked: true, message: 'ok' },
      write_file: { ok: true, checked: true, message: 'ok' },
      delete_probe_file: { ok: true, checked: true, message: 'ok' },
      sqlite_store_open: { ok: true, checked: true, message: 'ok' },
    },
    usage: {
      total_bytes: 8192,
      filesystem: [],
      sqlite_logical: [],
      scan_errors: [],
    },
  };
}

function dataKeyRotationPreflightFixture(): DataKeyRotationPreflight {
  return {
    ready: true,
    status: 'ready',
    next_action: 'Submeter a chave de substituição para executar PRAGMA rekey.',
    evidence: {
      database_format: 'sqlcipher',
      current_key_config: 'configured',
      requested_key_config: 'configured',
      sqlcipher_available: true,
      database_file: 'F:\\Chancela\\Data\\chancela.sqlite',
    },
  };
}

function dataKeyRotationExecutionFixture(): DataKeyRotationExecution {
  return {
    status: 'rekey_applied',
    rekey_executed: true,
    ledger_integrity_verified: true,
    ledger_length: 12,
    evidence: {
      operation: 'sqlcipher_rekey',
      requested_key_config: 'configured',
      sqlcipher_available: true,
      checkpointed_before_rekey: true,
      checkpointed_after_rekey: true,
      post_rekey_integrity_checked: true,
    },
  };
}
