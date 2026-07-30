/**
 * Route-stubbed browser proof for Settings > Operacoes platform service controls.
 * The fixtures pin UI behavior only: desired-state recording, supervisor-required
 * messaging, and settings autosave for log overrides. No real process control is used.
 */
import { expect, test, type Page, type Route } from './fixtures';
import {
  DEFAULT_SETTINGS,
  type Dashboard,
  type PermissionGrant,
  type PlatformControlResponse,
  type PlatformLogsResponse,
  type PlatformServiceStatus,
  type PlatformServiceAction,
  type ServerEnvResponse,
  type ServerEnvVarView,
  type Settings,
  type UserView,
} from '../src/api/types';
import { platformServicePtPT } from '../src/i18n/platformServiceFallback';

const USER_ID = 'a3f14f20-9000-4000-8000-00000000d902';

type ControlRequest = {
  serviceId: string;
  action: string;
};

type PlatformOperationsFixtureState = {
  settings: Settings;
  services: PlatformServiceStatus[];
};

test('the API and MCP tabs own their service rows, and MCP start records as supervisor-required only', async ({
  page,
}) => {
  const controlRequests: ControlRequest[] = [];
  const settingsPuts: Settings[] = [];
  await routePlatformOperationsFixtures(page, controlRequests, settingsPuts);

  await page.goto('/admin');

  await expect(page.getByRole('heading', { name: 'Administração', exact: true })).toBeVisible();
  await expect(page.getByText(/não prometem controlo direto de processos/i)).toBeVisible();

  // Both service rows moved to their own sub-tabs (t82, t82b); Plataforma routes to them.
  await expect(page.getByText('Chancela API server')).toHaveCount(0);
  await expect(page.getByText('Chancela MCP stdio server')).toHaveCount(0);

  // t120: API and IA e MCP live under the Integrações group, so the walk is group-then-pane.
  const groups = page.getByRole('group', { name: 'Secções de administração' });
  const operations = page.getByRole('group', { name: 'Áreas de administração' });
  await groups.getByRole('button', { name: 'Integrações' }).click();
  await operations.getByRole('button', { name: 'API' }).click();
  await expect(page.getByRole('heading', { name: 'Servidor API', exact: true })).toBeVisible();

  const apiRow = serviceRow(page, 'Chancela API server');
  await expect(apiRow).toBeVisible();
  await expect(apiRow).toContainText('Servidor API');
  await expect(apiRow).toContainText('A executar');
  await expect(apiRow).toContainText('Reinício necessário');
  // Server-authored English resolved to pt-PT by `platformServiceFallback.ts` (t92). Named by KEY
  // so a reviewed rewording does not turn this red; the copy itself is gated by that module's
  // divergence test against `platform_ops.rs`.
  await expect(apiRow).toContainText(platformServicePtPT.capabilityLimitation['api.restart']);

  // The launch-time security posture used to be transcribed into this pane as a hard-coded table
  // of ten variable names and their defaults — a second copy of the server's own registry, which
  // could only drift away from it. It now lives in one place, "Ambiente do servidor", rendered from
  // `GET /v1/platform/env` with the value the running process actually resolved. What this pane
  // must still guarantee is the *route* to it; the vars themselves are asserted where they render,
  // in the test below.
  await expect(page.getByRole('link', { name: 'Ambiente do servidor' })).toBeVisible();

  // The API keys pane is the sibling of this one, at its own unchanged address.
  const apiPanes = page.getByRole('group', { name: 'Áreas da API' });
  await expect(apiPanes.getByRole('button', { name: 'Chaves API' })).toBeVisible();

  await operations.getByRole('button', { name: 'IA e MCP' }).click();
  await expect(page.getByRole('heading', { name: 'Servidor MCP', exact: true })).toBeVisible();
  await expect(page.getByText('Garantia IA/MCP')).toBeVisible();

  const mcpRow = serviceRow(page, 'Chancela MCP stdio server');
  await expect(mcpRow).toBeVisible();
  await expect(mcpRow).toContainText('Servidor MCP stdio');
  await expect(mcpRow).toContainText('Parado');
  await expect(mcpRow).toContainText('Supervisor necessário');
  await expect(mcpRow).toContainText(platformServicePtPT.serviceLimitation['mcp.external_launch']);

  const controlResponse = waitForApiResponse(
    page,
    '/v1/platform/services/mcp_stdio/actions/start',
    'POST',
  );
  await mcpRow.getByRole('button', { name: /Registar arranque/ }).click();
  expect((await controlResponse).status()).toBe(200);

  expect(controlRequests).toEqual([{ serviceId: 'mcp_stdio', action: 'start' }]);
  await expect(mcpRow).toContainText('Pedido por');
  await expect(mcpRow).toContainText('e2e.platform.operator');
  await expect(mcpRow).toContainText(platformServicePtPT.controlMessage['mcp_stdio.start']);
  await expect(mcpRow).not.toContainText(/started process|spawned process|processo iniciado/i);

  // The MCP service log override moved onto this same tab and still writes the settings document.
  await expect(page.getByRole('heading', { name: 'Registos do MCP' })).toBeVisible();

  const autosaveResponse = waitForApiResponse(page, '/v1/settings', 'PUT');
  await page.getByLabel('MCP stdio').selectOption('warn');
  expect((await autosaveResponse).status()).toBe(200);

  expect(settingsPuts.length).toBeGreaterThan(0);
  const latestSettings = settingsPuts.at(-1);
  expect(latestSettings?.platform.logging.service_overrides).toMatchObject({
    mcp_stdio: 'warn',
  });
  expect(controlRequests).toEqual([{ serviceId: 'mcp_stdio', action: 'start' }]);
});

/**
 * The guarantee the API pane used to carry: an operator can see the launch-time security posture —
 * the CORS allow-list, the rate limiter, HSTS, the session cap. It now holds one level deeper, in
 * "Ambiente do servidor", and holds *harder*: the pane shows the value the running process actually
 * resolved and where it came from, not a default transcribed by hand into the web build.
 */
test('the server-environment pane surfaces the launch-time security posture with its live values', async ({
  page,
}) => {
  await routePlatformOperationsFixtures(page, [], []);

  await page.goto('/admin');
  await expect(page.getByRole('heading', { name: 'Administração', exact: true })).toBeVisible();

  const operations = page.getByRole('group', { name: 'Áreas de administração' });
  await operations.getByRole('button', { name: 'Ambiente do servidor' }).click();

  // Every var the old hard-coded table named is still visible to the operator.
  await expect(page.getByText('CHANCELA_CORS_ALLOWED_ORIGINS')).toBeVisible();
  await expect(page.getByText('CHANCELA_RATE_LIMIT_PER_SECOND')).toBeVisible();
  await expect(page.getByText('CHANCELA_HSTS_MAX_AGE')).toBeVisible();
  await expect(page.getByText('CHANCELA_SESSION_MAX_LIFETIME')).toBeVisible();

  // ... with what the process resolved, which the transcribed table could never show.
  const corsRow = envRow(page, 'CHANCELA_CORS_ALLOWED_ORIGINS');
  await expect(corsRow).toContainText('app.example.pt');
  // CORS is a Tier C boundary, so the pane must say so rather than present it as a plain setting.
  await expect(corsRow).toContainText('Fronteira de segurança');

  // A Tier B secret is never echoed — only whether it is configured.
  const secretRow = envRow(page, 'CHANCELA_DB_KEY');
  await expect(secretRow).toContainText('Configurada');
  await expect(page.getByText(/e2e-never-echoed/)).toHaveCount(0);

  // A var only the separate MCP process reads is shown, but never as an editor whose edit would
  // silently do nothing: the row states which process reads it.
  const mcpRow = envRow(page, 'CHANCELA_MCP_TRANSPORT');
  await expect(mcpRow).toContainText('chancela-mcp');
  await expect(mcpRow.getByRole('combobox')).toHaveCount(0);
});

/** The `.field` row whose label is the variable name. */
function envRow(page: Page, name: string) {
  return page.locator('.field').filter({ has: page.getByText(name, { exact: true }) });
}

async function routePlatformOperationsFixtures(
  page: Page,
  controlRequests: ControlRequest[],
  settingsPuts: Settings[],
): Promise<void> {
  const state: PlatformOperationsFixtureState = {
    settings: settingsFixture(),
    services: platformServicesFixture(),
  };

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
      await fulfillJson(route, state.settings);
      return;
    }
    if (method === 'PUT' && pathname === '/v1/settings') {
      const body = request.postDataJSON() as Settings;
      settingsPuts.push(body);
      state.settings = body;
      await fulfillJson(route, body);
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
    if (method === 'GET' && pathname === '/v1/platform/services') {
      await fulfillJson(route, { services: state.services });
      return;
    }
    if (method === 'GET' && pathname === '/v1/platform/logs') {
      await fulfillJson(route, platformLogsFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/platform/env') {
      await fulfillJson(route, serverEnvFixture());
      return;
    }

    const controlMatch = pathname.match(/^\/v1\/platform\/services\/([^/]+)\/actions\/([^/]+)$/);
    if (method === 'POST' && controlMatch) {
      const [, serviceId, action] = controlMatch;
      controlRequests.push({ serviceId, action });
      const control = platformControlFixture(action as PlatformServiceAction);
      state.services = state.services.map((service) =>
        service.id === control.service.id ? control.service : service,
      );
      state.settings = {
        ...state.settings,
        platform: {
          ...state.settings.platform,
          mcp_stdio_server: {
            enabled: control.service.enabled,
            desired_state: control.service.desired_state,
            last_action: control.service.last_action,
          },
        },
      };
      await fulfillJson(route, control);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled platform operations e2e route: ${method} ${pathname}` },
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

function serviceRow(page: Page, label: string) {
  return page.locator('section.platform-service-row').filter({ hasText: label });
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'operator.platform',
    display_name: 'Operator Platform',
    created_at: '2026-07-13T09:00:00.000Z',
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
    permissions: ['ledger.read', 'settings.manage', 'settings.read', 'user.manage'].map(
      permissionGrant,
    ),
  };
}

/**
 * `GET /v1/platform/env` — the rows the retired hard-coded table used to transcribe, plus one Tier B
 * secret and one var only the separate MCP process reads, so the fixture exercises all three
 * treatments the pane must keep apart. The secret carries a value the server would never send; if it
 * ever reaches the page the masking assertion catches it.
 */
function serverEnvFixture(): ServerEnvResponse {
  const row = (over: Partial<ServerEnvVarView> & Pick<ServerEnvVarView, 'name' | 'group'>) => ({
    tier: 'A' as const,
    editable: true,
    secret: false,
    boundary: false,
    narrow_only: false,
    acknowledgement_required: false,
    excluded_typed_slice: null,
    external_reader: null,
    source: 'env' as const,
    configured: true,
    effective_value: null,
    override_value: null,
    default_value: null,
    restart_pending: false,
    validator: { kind: 'free_text' as const, allowed: null },
    ...over,
  });

  return {
    vars: [
      row({
        name: 'CHANCELA_CORS_ALLOWED_ORIGINS',
        group: 'cors',
        tier: 'C',
        boundary: true,
        acknowledgement_required: true,
        effective_value: 'app.example.pt',
        validator: { kind: 'host_list', allowed: null },
      }),
      row({
        name: 'CHANCELA_RATE_LIMIT_PER_SECOND',
        group: 'rate_limit',
        effective_value: '50',
        default_value: '50',
        validator: { kind: 'unsigned', allowed: null },
      }),
      row({
        name: 'CHANCELA_HSTS_MAX_AGE',
        group: 'hsts',
        effective_value: '63072000',
        default_value: '63072000',
        validator: { kind: 'unsigned', allowed: null },
      }),
      row({
        name: 'CHANCELA_SESSION_MAX_LIFETIME',
        group: 'session',
        effective_value: '604800',
        default_value: '604800',
        validator: { kind: 'unsigned', allowed: null },
      }),
      row({
        name: 'CHANCELA_DB_KEY',
        group: 'database',
        tier: 'B',
        editable: false,
        secret: true,
        // A real server never sends this; the pane must not render it even when one does.
        effective_value: 'e2e-never-echoed',
      }),
      row({
        name: 'CHANCELA_MCP_TRANSPORT',
        group: 'mcp',
        tier: 'D',
        editable: false,
        source: 'default',
        configured: false,
        default_value: 'stdio',
        external_reader:
          'read by the separate `chancela-mcp` server process, not by this one — set it in the ' +
          'environment that launches the MCP server',
        validator: { kind: 'enum', allowed: ['stdio', 'http-sse'] },
      }),
    ],
    restart_pending: false,
    overrides_path: '/var/lib/chancela/env-overrides.json',
    generated_at: '2026-07-13T09:00:00.000Z',
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
    onboarding: { completed: true, completed_at: '2026-07-13T09:00:00.000Z' },
    platform: {
      ...DEFAULT_SETTINGS.platform,
      logging: {
        global: 'info',
        app: 'info',
        api: 'info',
        mcp: 'info',
        service_overrides: {},
      },
      api_server: {
        enabled: true,
        desired_state: 'running',
        last_action: null,
      },
      mcp_stdio_server: {
        enabled: false,
        desired_state: 'stopped',
        last_action: null,
      },
      audit: [],
    },
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

function platformServicesFixture(): PlatformServiceStatus[] {
  return [apiServiceFixture(), mcpServiceFixture()];
}

function apiServiceFixture(): PlatformServiceStatus {
  return {
    id: 'api',
    kind: 'api',
    label: 'Chancela API server',
    configured: true,
    enabled: true,
    desired_state: 'running',
    actual_runtime_status: 'running',
    controllable_actions: [
      {
        action: 'start',
        supported: false,
        outcome: 'unsupported',
        limitation: 'The current API process cannot start another copy of itself.',
      },
      {
        action: 'stop',
        supported: false,
        outcome: 'unsupported',
        limitation: 'The current API process cannot stop itself through this request.',
      },
      {
        action: 'restart',
        supported: false,
        outcome: 'restart_required',
        limitation: 'Restart requires an external supervisor or process relaunch.',
      },
    ],
    logging_level: 'info',
    last_action: null,
    limitations: [
      'The API can observe this process as running only because it is serving this request.',
      'Start, stop, and restart require an external supervisor or process relaunch.',
    ],
  };
}

function mcpServiceFixture(): PlatformServiceStatus {
  return {
    id: 'mcp_stdio',
    kind: 'mcp',
    label: 'Chancela MCP stdio server',
    configured: false,
    enabled: false,
    desired_state: 'stopped',
    actual_runtime_status: 'unknown',
    controllable_actions: mcpActionCapabilities(),
    logging_level: 'info',
    last_action: null,
    limitations: [
      'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
      'No MCP API key or other secret is exposed through this status surface.',
      'Tenant AI/MCP gate settings.ai.enabled is false; a launcher must mirror it before MCP can serve.',
    ],
  };
}

function mcpActionCapabilities() {
  return [
    {
      action: 'start',
      supported: false,
      outcome: 'supervisor_required',
      limitation:
        'The stdio MCP server is launched externally; the API can only record desired state.',
    },
    {
      action: 'stop',
      supported: false,
      outcome: 'supervisor_required',
      limitation:
        'The stdio MCP server is launched externally; the API can only record desired state.',
    },
    {
      action: 'restart',
      supported: false,
      outcome: 'supervisor_required',
      limitation:
        'The stdio MCP server is launched externally; the API can only record desired state.',
    },
  ] satisfies PlatformServiceStatus['controllable_actions'];
}

function platformControlFixture(action: PlatformServiceAction): PlatformControlResponse {
  const service: PlatformServiceStatus = {
    ...mcpServiceFixture(),
    enabled: true,
    desired_state: 'running',
    last_action: {
      action,
      requested_at: '2026-07-13T09:15:00.000Z',
      requested_by: 'e2e.platform.operator',
      outcome: 'supervisor_required',
      message:
        'MCP start desired state was recorded; relaunch the external MCP client or supervisor.',
    },
  };

  return {
    service,
    action,
    result: {
      kind: 'supervisor_required',
      supported: false,
      applied_to_settings: true,
      desired_state: 'running',
      actual_runtime_status: 'unknown',
      message:
        'MCP start desired state was recorded; relaunch the external MCP client or supervisor.',
      limitations: service.limitations,
    },
  };
}

function platformLogsFixture(): PlatformLogsResponse {
  return {
    logs: [],
    tail: 100,
    order: 'newest_first',
    retention: {
      retention_limit: 512,
      retained_count: 0,
      oldest_seq: null,
      newest_seq: null,
      dropped_before_seq: null,
      durable: false,
      basis: 'memory',
      source: 'process_memory',
    },
    limitations: [
      'API-owned structured tail only; this does not tail stdout/stderr or MCP child-process logs.',
      'Forwarded logs require an external supervisor or client to submit structured entries.',
    ],
  };
}
