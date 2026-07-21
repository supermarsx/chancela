/**
 * Focused browser coverage for operator-facing edge flows that are risky at the shell/API/UI
 * boundary. These tests use route-level fixtures so they stay hermetic and avoid depending on
 * the shared E2E server's current mutable data.
 */
import { expect, test, type Locator, type Page, type Route } from './fixtures';
import { routeShellPolling } from './shell-routes';
import type {
  Dashboard,
  DsrRequestType,
  DsrRequestView,
  LedgerEventView,
  PermissionGrant,
  RoleView,
  SessionPermissions,
  Settings,
  TsaCatalogView,
  TsaRecordView,
  TsaSummaryView,
  TslCatalogView,
  TslProviderView,
  TslServiceDetailView,
  TslServiceSummaryView,
  TslSummaryView,
  UserView,
} from '../src/api/types';

const OPERATOR = userFixture({
  id: '11111111-1111-4111-8111-111111111111',
  username: 'operator.edge',
  display_name: 'Operador Edge',
});

const TARGET_USER = userFixture({
  id: '22222222-2222-4222-8222-222222222222',
  username: 'amelia.edge',
  display_name: 'Amélia Edge',
});

const OPERATOR_PERMISSIONS = [
  'settings.read',
  'settings.manage',
  'user.manage',
  'role.assign',
  'ledger.read',
];

const CREDENTIAL_MARKER_PATTERN =
  /password_hash|api_secret|sk_live_e2e_secret|argon2id|credential_material|plain-secret-e2e|recovery_phrase/i;

test('legacy user-management URLs canonicalize into Configurações users only', async ({ page }) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeHealth(page);
  await routeLedgerVerify(page);
  await routeRolesAndScopeLookups(page);
  await routeDsr(page, TARGET_USER.id, { requests: [] });

  await page.goto('/users');
  await expect(page).toHaveURL(/\/settings\/users$/);
  await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();
  await expect(settingsSectionButton(page, 'Utilizadores')).toHaveAttribute('aria-pressed', 'true');
  await expect(panelByTitle(page, 'Utilizadores')).toBeVisible();
  await expect(page.locator('main[data-route-key="/settings"]')).toBeVisible();

  await page.goto('/users/new');
  await expect(page).toHaveURL(/\/settings\/users\?user=novo$/);
  await expect(settingsSectionButton(page, 'Utilizadores')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByLabel('Nome de utilizador')).toBeVisible();
  await expect(page.locator('main[data-route-key="/settings"]')).toBeVisible();

  await page.goto(`/users/${TARGET_USER.id}#acesso`);
  await expect(page).toHaveURL(
    new RegExp(`/settings/users\\?user=${TARGET_USER.id}#acesso$`),
  );
  await expect(page.getByRole('heading', { name: 'Identidade' })).toBeVisible();
  await expect(page.locator('section#acesso')).toBeVisible();
  await expect(page.locator('main[data-route-key="/settings"]')).toBeVisible();
});

test('DSR export and empty request list do not render secret-bearing JSON', async ({ page }) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeHealth(page);
  await routeLedgerVerify(page);
  await routeRolesAndScopeLookups(page);
  await routeDsr(page, TARGET_USER.id, {
    requests: [],
    exportBody: dsrExportWithCredentialMarkers(),
  });

  await page.goto(`/settings/users?user=${TARGET_USER.id}`);

  const dsr = panelByTitle(page, 'Pedidos DSR / privacidade');
  await expect(dsr).toBeVisible();
  await expect(dsr.getByText('Sem pedidos DSR')).toBeVisible();
  await expectNoCredentialMarkers(page);

  await dsr.getByRole('button', { name: 'Descarregar exportação DSR' }).click();

  await expect(page.getByText('Exportação DSR/privacy descarregada.')).toBeVisible();
  await expectNoCredentialMarkers(page);
});

test('DSR request-list error response does not leak diagnostic credential fields', async ({
  page,
}) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeHealth(page);
  await routeLedgerVerify(page);
  await routeRolesAndScopeLookups(page);
  await routeDsr(page, TARGET_USER.id, {
    error: {
      status: 500,
      body: {
        error: 'Falha temporária na lista DSR.',
        password_hash: 'argon2id$v=19$m=65536$plain-secret-e2e',
        api_secret: 'sk_live_e2e_secret',
      },
    },
  });

  await page.goto(`/settings/users?user=${TARGET_USER.id}`);

  const dsr = panelByTitle(page, 'Pedidos DSR / privacidade');
  await expect(dsr).toBeVisible();
  await expect(dsr.getByText('Falha temporária na lista DSR.')).toBeVisible();
  await expectNoCredentialMarkers(page);
});

test('DSR request success list renders lifecycle fields without hidden credential markers', async ({
  page,
}) => {
  const pending = dsrRequestFixture({
    id: 'dsr-pending',
    request_type: 'export',
    status: 'pending',
    execution_notes: 'credential_material=plain-secret-e2e',
  });
  const completed = dsrRequestFixture({
    id: 'dsr-completed',
    request_type: 'erasure',
    status: 'completed',
    completed_at: '2026-07-08T12:00:00.000Z',
    completed_by: 'operator.edge',
    retention_review: 'password_hash=argon2id$v=19$m=65536$plain-secret-e2e',
  });

  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeHealth(page);
  await routeLedgerVerify(page);
  await routeRolesAndScopeLookups(page);
  await routeDsr(page, TARGET_USER.id, { requests: [pending, completed] });

  await page.goto(`/settings/users?user=${TARGET_USER.id}`);

  const dsr = panelByTitle(page, 'Pedidos DSR / privacidade');
  await expect(dsr).toBeVisible();
  await expect(dsr.getByRole('row').filter({ hasText: 'Exportação' })).toContainText('Pendente');
  await expect(dsr.getByRole('row').filter({ hasText: 'Apagamento' })).toContainText('Concluído');
  await expectNoCredentialMarkers(page);
});

test('dashboard entrance sorts recent activity, caps at ten, and keeps six metrics in one desktop row', async ({
  page,
}) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeHealth(page);
  await routeDashboard(page, dashboardFixture(dashboardEdgeEvents()));

  // Atividades atuais is the landing panel, so the metrics and the ledger feed each need
  // their own `/dashboard/:tab` section.
  await page.goto('/dashboard/stats');

  await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();

  const metricCards = page.locator('.dashboard-metrics--summary > .card');
  await expect(metricCards).toHaveCount(6);
  const boxes = await metricCards.evaluateAll((cards) =>
    cards.map((card) => {
      const rect = card.getBoundingClientRect();
      return { top: Math.round(rect.top), left: Math.round(rect.left) };
    }),
  );
  expect(new Set(boxes.map((box) => box.top)).size).toBe(1);
  expect(boxes.map((box) => box.left)).toEqual(
    [...boxes.map((box) => box.left)].sort((a, b) => a - b),
  );

  await page.goto('/dashboard/events');
  const rows = panelByTitle(page, 'Últimos eventos do registo').locator('tbody tr');
  await expect(rows).toHaveCount(10);
  const rowTexts = await rows.evaluateAll((trs) => trs.map((tr) => tr.textContent ?? ''));

  expect(rowTexts[0]).toContain('edge.event.12');
  expect(rowTexts[1]).toContain('edge.event.11');
  expect(rowTexts[9]).toContain('edge.event.03');
  expect(rowTexts.join('\n')).not.toContain('edge.event.02');
  expect(rowTexts.join('\n')).not.toContain('edge.event.01');
});

test('trust catalog keeps unsafe metadata inert and TSL/TSA searches accent-insensitive', async ({
  page,
}) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeHealth(page);
  await routeTrustCatalog(page);

  await page.goto('/tools/trust');

  const catalog = panelByTitle(page, 'Catálogo de confiança');
  const tsa = panelByTitle(page, 'TSA / RFC 3161');
  await expect(catalog).toBeVisible();
  await expect(tsa).toBeVisible();

  await page.getByLabel('Procurar na lista de confiança TSL').fill('qualificada agil');
  await expect(
    catalog.locator('.trust-pick--service', { hasText: 'Assinatura Qualificada Ágil' }),
  ).toBeVisible();
  await expect(
    catalog.locator('.trust-pick--service', { hasText: 'Serviço Sem Metadados' }),
  ).toHaveCount(0);

  await catalog.locator('.trust-pick--service', { hasText: 'Assinatura Qualificada Ágil' }).click();
  await expect(catalog.getByText('javascript:alert("service")')).toBeVisible();
  await expect(catalog.getByText('data:text/html,<b>x</b>')).toBeVisible();
  await expectNoUnsafeAnchors(page);

  await page.getByLabel('Procurar na lista de confiança TSL').fill('');
  await catalog.locator('.trust-pick--provider', { hasText: 'Certificação Ágil' }).click();
  await expect(catalog.getByText('javascript:alert("provider")')).toBeVisible();
  await expect(catalog.getByText('data:text/html,<svg onload=alert(1)>')).toBeVisible();
  await expectNoUnsafeAnchors(page);

  await catalog.locator('.trust-pick--service', { hasText: 'Serviço Sem Metadados' }).click();
  await expect(
    catalog.locator('.trust-detail__title', { hasText: 'Serviço Sem Metadados' }),
  ).toBeVisible();
  await expect(catalog.getByText('Sem dados publicados.')).toHaveCount(3);
  await expectNoUnsafeAnchors(page);

  await tsa.getByLabel('Procurar registos TSA').fill('evora');
  await expect(tsa.getByRole('button', { name: /QTST Évora/ })).toBeVisible();
  await expect(tsa.getByRole('button', { name: /TST Lisboa/ })).toHaveCount(0);
  await expect(tsa.getByText('javascript:alert("tsa")').first()).toBeVisible();
  await expectNoUnsafeAnchors(page);
});

function settingsSectionButton(page: Page, name: string): Locator {
  return page
    .getByRole('group', { name: 'Secções de configuração' })
    .getByRole('button', { name, exact: true });
}

function panelByTitle(page: Page, title: string): Locator {
  return page.locator('.panel').filter({ has: page.getByRole('heading', { name: title }) });
}

async function routeAuthenticatedShell(
  page: Page,
  permissions = OPERATOR_PERMISSIONS,
): Promise<void> {
  // First, so a spec's own stub for the same URL (registered later) still wins.
  await routeShellPolling(page);

  const users = [OPERATOR, TARGET_USER];
  const grants = permissions.map(permissionGrant);
  const session = { user: OPERATOR, permissions: grants };
  const sessionPermissions: SessionPermissions = {
    user_id: OPERATOR.id,
    username: OPERATOR.username,
    role_assignments: [{ role_id: 'owner', scope: { kind: 'global' } }],
    permissions: grants,
  };

  await page.route('**/v1/session**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/session/permissions') {
      await fulfillJson(route, sessionPermissions);
      return;
    }
    if (request.method() === 'GET' && pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: users
          .filter((user) => user.active)
          .map((user) => ({
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            has_secret: user.has_secret,
          })),
      });
      return;
    }
    if (request.method() === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, session);
      return;
    }

    await route.continue();
  });

  await page.route('**/v1/users**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/users') {
      await fulfillJson(route, users);
      return;
    }

    const userId = pathname.match(/^\/v1\/users\/([^/]+)$/)?.[1];
    if (request.method() === 'GET' && userId) {
      const user = users.find((item) => item.id === decodeURIComponent(userId));
      await fulfillJson(route, user ?? { error: 'not found' }, user ? 200 : 404);
      return;
    }

    const roleUserId = pathname.match(/^\/v1\/users\/([^/]+)\/roles$/)?.[1];
    if ((request.method() === 'POST' || request.method() === 'DELETE') && roleUserId) {
      await fulfillJson(route, []);
      return;
    }

    await route.continue();
  });
}

async function routeSettings(page: Page): Promise<void> {
  await page.route('**/v1/settings', async (route) => {
    const request = route.request();
    if (new URL(request.url()).pathname !== '/v1/settings') {
      await route.continue();
      return;
    }
    if (request.method() === 'GET') {
      await fulfillJson(route, settingsFixture());
      return;
    }
    if (request.method() === 'PUT') {
      await fulfillJson(route, request.postDataJSON() as unknown);
      return;
    }
    await route.continue();
  });
}

async function routeHealth(page: Page): Promise<void> {
  await page.route('**/health', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
      return;
    }
    await route.continue();
  });
}

async function routeLedgerVerify(page: Page): Promise<void> {
  await page.route('**/v1/ledger/verify', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, { valid: true, length: 0 });
      return;
    }
    await route.continue();
  });
}

async function routeRolesAndScopeLookups(page: Page): Promise<void> {
  const roles: RoleView[] = [
    {
      id: 'owner',
      name: 'Proprietário',
      permissions: OPERATOR_PERMISSIONS,
      protected: true,
    },
  ];

  await page.route('**/v1/roles', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, roles);
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/entities', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, []);
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/books', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, []);
      return;
    }
    await route.continue();
  });
}

async function routeDsr(
  page: Page,
  userId: string,
  options:
    | { requests: DsrRequestView[]; exportBody?: unknown }
    | { error: { status: number; body: unknown }; exportBody?: unknown },
): Promise<void> {
  await page.route(`**/v1/privacy/users/${userId}/**`, async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;

    if (request.method() === 'GET' && pathname === `/v1/privacy/users/${userId}/export`) {
      await fulfillJson(route, options.exportBody ?? dsrExportFixture());
      return;
    }

    if (request.method() === 'GET' && pathname === `/v1/privacy/users/${userId}/dsr-requests`) {
      if ('error' in options) {
        await fulfillJson(route, options.error.body, options.error.status);
      } else {
        await fulfillJson(route, options.requests);
      }
      return;
    }

    if (request.method() === 'POST' && pathname === `/v1/privacy/users/${userId}/dsr-requests`) {
      const body = request.postDataJSON() as { request_type: DsrRequestType };
      await fulfillJson(
        route,
        dsrRequestFixture({ id: 'dsr-created', request_type: body.request_type }),
        201,
      );
      return;
    }

    const completeId = pathname.match(
      new RegExp(`^/v1/privacy/users/${userId}/dsr-requests/([^/]+)/complete$`),
    )?.[1];
    if (request.method() === 'POST' && completeId) {
      await fulfillJson(
        route,
        dsrRequestFixture({
          id: decodeURIComponent(completeId),
          status: 'completed',
          completed_at: '2026-07-08T12:00:00.000Z',
          completed_by: OPERATOR.username,
        }),
      );
      return;
    }

    await route.continue();
  });
}

async function routeDashboard(page: Page, dashboard: Dashboard): Promise<void> {
  await page.route('**/v1/dashboard', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, dashboard);
      return;
    }
    await route.continue();
  });
}

async function routeTrustCatalog(page: Page): Promise<void> {
  const catalog = trustCatalogFixture();
  const tsa = tsaCatalogFixture();

  await page.route('**/v1/trust/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (pathname === '/v1/trust/status') {
      await fulfillJson(route, catalog.summary);
      return;
    }
    if (pathname === '/v1/trust/catalog') {
      await fulfillJson(route, catalog);
      return;
    }
    if (pathname === '/v1/trust/tsa') {
      await fulfillJson(route, tsa);
      return;
    }

    const providerId = pathname.match(/^\/v1\/trust\/providers\/([^/]+)$/)?.[1];
    if (providerId) {
      const provider = catalog.providers.find((item) => item.id === decodeURIComponent(providerId));
      await fulfillJson(
        route,
        provider ? { provider, summary: catalog.summary } : { error: 'not found' },
        provider ? 200 : 404,
      );
      return;
    }

    const serviceId = pathname.match(/^\/v1\/trust\/services\/([^/]+)$/)?.[1];
    if (serviceId) {
      const service = catalog.providers
        .flatMap((provider) => provider.services)
        .find((item) => item.id === decodeURIComponent(serviceId));
      await fulfillJson(
        route,
        service ? serviceDetailFixture(service, catalog.summary) : { error: 'not found' },
        service ? 200 : 404,
      );
      return;
    }

    await route.continue();
  });
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function expectNoCredentialMarkers(page: Page): Promise<void> {
  const bodyText = await page.locator('body').innerText();
  const bodyHtml = await page.locator('body').evaluate((body) => body.innerHTML);
  expect(bodyText).not.toMatch(CREDENTIAL_MARKER_PATTERN);
  expect(bodyHtml).not.toMatch(CREDENTIAL_MARKER_PATTERN);
}

async function expectNoUnsafeAnchors(page: Page): Promise<void> {
  await expect(
    page.locator(
      'a[href^="javascript:"], a[href^="data:"], a[href^="file:"], a[href^="vbscript:"]',
    ),
  ).toHaveCount(0);
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function userFixture(overrides: Partial<UserView>): UserView {
  return {
    id: '00000000-0000-4000-8000-000000000000',
    username: 'operator',
    display_name: 'Operador',
    created_at: '2026-01-01T00:00:00.000Z',
    active: true,
    has_secret: false,
    has_attestation_key: false,
    has_recovery_phrase: false,
    ...overrides,
  };
}

function settingsFixture(): Settings {
  return {
    schema_version: 1,
    organization: { name: null, default_actor: 'api' },
    documents: { locale: 'pt-PT', numbering_scheme_default: 'Sequential' },
    catalog: {
      cae_update_url: null,
      cae_sources: [],
      cae_official_source: false,
      preferred_official_source: 'Ine',
    },
    signing: {
      preferred_family: 'ChaveMovelDigital',
      tsa_url: 'javascript:alert("tsa-settings")',
      tsl_url: null,
      require_qualified_for_seal: false,
      cmd: { env: 'preprod', application_id: null, ama_cert_configured: false },
    },
    appearance: {
      theme: 'system',
      leather_texture: true,
      texture_intensity: 60,
      button_texture: true,
    },
    onboarding: { completed: true, completed_at: '2026-01-01T00:00:00.000Z' },
    ai: { enabled: false },
  };
}

function dsrRequestFixture(overrides: Partial<DsrRequestView> = {}): DsrRequestView {
  return {
    id: 'dsr-1',
    subject_user_id: TARGET_USER.id,
    request_type: 'export',
    status: 'pending',
    created_at: '2026-07-08T09:00:00.000Z',
    created_by: OPERATOR.username,
    ...overrides,
  };
}

function dsrExportFixture() {
  return {
    exported_at: '2026-07-08T09:00:00.000Z',
    scope: 'user',
    format_version: 1,
    redaction_notes: ['non-secret export'],
    exclusions: ['credential material'],
    user: { ...TARGET_USER, role_assignments: [] },
    ledger_event_refs: [],
  };
}

function dsrExportWithCredentialMarkers() {
  return {
    ...dsrExportFixture(),
    credential_material: {
      password_hash: 'argon2id$v=19$m=65536$plain-secret-e2e',
      api_secret: 'sk_live_e2e_secret',
      recovery_phrase: 'plain-secret-e2e',
    },
  };
}

function dashboardFixture(recentEvents: LedgerEventView[]): Dashboard {
  return {
    entities: 3,
    books_open: 2,
    books_total: 4,
    acts_total: 8,
    acts_draft: 5,
    acts_awaiting_signature: 1,
    acts_sealed: 2,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: recentEvents.length,
    ledger_valid: true,
    // DashboardPage reads `current_work.act_counts_by_state` unguarded, so the fixture must
    // carry it — the shell only reaches the dashboard now that the poll stubs keep it signed in.
    current_work: {
      open_books: [],
      act_counts_by_state: {
        Draft: 5,
        Review: 0,
        Convened: 0,
        Deliberated: 0,
        TextApproved: 0,
        Signing: 1,
        Sealed: 2,
        Archived: 0,
      },
    },
    alerts: [],
    reminders: [],
    recent_events: recentEvents,
  };
}

function dashboardEdgeEvents(): LedgerEventView[] {
  const seqs = [1, 7, 12, 3, 10, 5, 11, 9, 4, 8, 2, 6];
  return seqs.map((seq) => {
    const day = seq >= 11 ? 12 : seq;
    return ledgerEvent(
      seq,
      `edge.event.${String(seq).padStart(2, '0')}`,
      `2026-01-${String(day).padStart(2, '0')}T10:00:00.000Z`,
    );
  });
}

function ledgerEvent(seq: number, kind: string, timestamp: string): LedgerEventView {
  const hex = String(seq).padStart(64, '0');
  return {
    id: `edge-event-${seq}`,
    seq,
    actor: 'api',
    justification: null,
    timestamp,
    scope: 'global',
    kind,
    payload_digest: hex,
    prev_hash: hex,
    hash: hex,
    chains: ['global'],
    attestation: null,
  };
}

const TRUST_SUMMARY: TslSummaryView = {
  source: {
    kind: 'Fixture',
    path: null,
    note: '',
  },
  scheme_operator_name: 'Operador TSL E2E',
  scheme_name: 'Lista de confiança E2E',
  scheme_territory: 'PT',
  sequence_number: null,
  issue_date_time: null,
  next_update: null,
  stale: false,
  validation: {
    checked_at: '2026-01-01T00:00:00.000Z',
    signature: 'Valid',
    error: null,
  },
  providers: 1,
  services: 3,
  ca_qc_services: 1,
  qualified_esignature_services: 1,
  trusted_esignature_services: 1,
};

function trustCatalogFixture(): TslCatalogView {
  const agile = serviceFixture({
    id: 'svc-agil',
    provider_id: 'provider-agil',
    provider_name: 'Certificação Ágil',
    name: 'Assinatura Qualificada Ágil',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
    status: { kind: 'Granted', uri: 'javascript:alert("status")' },
    ca_qc: true,
    qualified_for_esignatures: true,
    trusted_for_esignatures: true,
    additional_service_info: ['data:text/html,<b>x</b>'],
    service_supply_points: ['javascript:alert("service")'],
    identities: {
      certificates: 1,
      subject_names: ['CN=Assinatura Qualificada Ágil,O=Certificação,C=PT'],
      subject_key_ids: ['agil-ski'],
    },
  });
  const evora = serviceFixture({
    id: 'svc-evora',
    provider_id: 'provider-agil',
    provider_name: 'Certificação Ágil',
    name: 'Selo Temporal Évora',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
    status: { kind: 'Granted', uri: null },
    service_supply_points: ['https://tsa.example.test/evora'],
    identities: {
      certificates: 1,
      subject_names: ['CN=Selo Temporal Évora,O=Certificação,C=PT'],
      subject_key_ids: ['evora-ski'],
    },
  });
  const missing = serviceFixture({
    id: 'svc-missing',
    provider_id: 'provider-agil',
    provider_name: 'Certificação Ágil',
    name: 'Serviço Sem Metadados',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/Other',
    status: { kind: 'Other', uri: null },
    identities: {
      certificates: 0,
      subject_names: [],
      subject_key_ids: [],
    },
  });

  return {
    summary: TRUST_SUMMARY,
    providers: [
      providerFixture(
        'provider-agil',
        'Certificação Ágil',
        [agile, evora, missing],
        ['javascript:alert("provider")', 'data:text/html,<svg onload=alert(1)>'],
      ),
    ],
  };
}

function serviceFixture(overrides: Partial<TslServiceSummaryView>): TslServiceSummaryView {
  return {
    id: 'svc-e2e',
    provider_id: 'provider-e2e',
    provider_name: 'Prestador E2E',
    name: 'Serviço E2E',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/Other',
    status: { kind: 'Granted', uri: null },
    status_starting_time: null,
    status_starting_time_raw: null,
    ca_qc: false,
    qualified_for_esignatures: false,
    trusted_for_esignatures: false,
    additional_service_info: [],
    service_supply_points: [],
    history_count: 0,
    identities: {
      certificates: 0,
      subject_names: [],
      subject_key_ids: [],
    },
    ...overrides,
  };
}

function providerFixture(
  id: string,
  name: string,
  services: TslServiceSummaryView[],
  informationUris: string[],
): TslProviderView {
  return {
    id,
    name,
    trade_names: ['Ágil Trust'],
    information_uris: informationUris,
    analysis: {
      services: services.length,
      granted_services: services.filter((service) => service.status.kind === 'Granted').length,
      withdrawn_services: services.filter((service) => service.status.kind === 'Withdrawn').length,
      other_status_services: services.filter((service) => service.status.kind === 'Other').length,
      services_with_history: services.filter((service) => service.history_count > 0).length,
      services_with_supply_points: services.filter(
        (service) => service.service_supply_points.length > 0,
      ).length,
      ca_qc_services: services.filter((service) => service.ca_qc).length,
      qualified_esignature_services: services.filter((service) => service.qualified_for_esignatures)
        .length,
      trusted_esignature_services: services.filter((service) => service.trusted_for_esignatures)
        .length,
      duplicate_service_names: [],
    },
    services,
  };
}

function serviceDetailFixture(
  service: TslServiceSummaryView,
  summary: TslSummaryView,
): TslServiceDetailView {
  return {
    ...service,
    digital_identities: service.identities.subject_names.length
      ? [
          {
            kind: 'X509SubjectName',
            value: service.identities.subject_names[0],
            sha256: 'a'.repeat(64),
            byte_length: 128,
          },
        ]
      : [],
    history: [],
    summary,
  };
}

function tsaCatalogFixture(): TsaCatalogView {
  const records = [
    tsaRecordFixture({
      id: 'tsa-evora',
      provider_name: 'Tempo Seguro',
      name: 'QTST Évora',
      service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
      qualified_timestamp_service: true,
      trusted: true,
      service_supply_points: ['javascript:alert("tsa")'],
      identities: {
        certificates: 1,
        subject_names: ['CN=QTST Évora,O=Tempo Seguro,C=PT'],
        subject_key_ids: ['tsa-evora-ski'],
      },
    }),
    tsaRecordFixture({
      id: 'tsa-lisboa',
      provider_name: 'Tempo Seguro',
      name: 'TST Lisboa',
      service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TST',
      qualified_timestamp_service: false,
      trusted: false,
      service_supply_points: [],
      identities: {
        certificates: 1,
        subject_names: ['CN=TST Lisboa,O=Tempo Seguro,C=PT'],
        subject_key_ids: ['tsa-lisboa-ski'],
      },
    }),
  ];
  return { summary: tsaSummaryFixture(records), records };
}

function tsaSummaryFixture(records: TsaRecordView[]): TsaSummaryView {
  return {
    configured_url: 'javascript:alert("tsa")',
    status: 'Ready',
    status_message: 'Fixture TSA E2E.',
    profile: {
      protocol: 'RFC3161',
      hash_algorithm: 'sha256',
      request_content_type: 'application/timestamp-query',
      response_content_type: 'application/timestamp-reply',
      nonce_policy: 'required',
      cert_req_default: true,
      accepted_policy: 'any',
    },
    accepted_hash: {
      algorithm: 'sha256',
      input: 'fixture',
      digest: '0'.repeat(64),
    },
    timestamp: null,
    last_probe: {
      kind: 'Fixture',
      status: 'Passed',
      checked_at: '2026-01-01T00:00:00.000Z',
      request_der_sha256: '1'.repeat(64),
      response_der_sha256: '2'.repeat(64),
      request_matches_fixture: true,
      error: null,
    },
    tsl: {
      source: TRUST_SUMMARY.source,
      signature: 'Valid',
      error: null,
    },
    records: records.length,
    granted_records: records.filter((record) => record.granted).length,
    trusted_records: records.filter((record) => record.trusted).length,
    policy_analysis: {
      accepted_policy: 'any',
      fixture_policy: null,
      fixture_policy_accepted: true,
      qualified_timestamp_records: records.filter((record) => record.qualified_timestamp_service)
        .length,
      trusted_qualified_timestamp_records: records.filter(
        (record) => record.qualified_timestamp_service && record.trusted,
      ).length,
      advisory: false,
    },
  };
}

function tsaRecordFixture(overrides: Partial<TsaRecordView>): TsaRecordView {
  return {
    id: 'tsa-e2e',
    provider_id: 'provider-agil',
    provider_name: 'Tempo Seguro',
    name: 'TSA E2E',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TST',
    status: { kind: 'Granted', uri: null },
    status_starting_time: null,
    status_starting_time_raw: null,
    qualified_timestamp_service: false,
    granted: true,
    effective: true,
    trusted: false,
    additional_service_info: [],
    service_supply_points: [],
    history_count: 0,
    identities: {
      certificates: 0,
      subject_names: [],
      subject_key_ids: [],
    },
    analysis: {
      classification: 'TimestampService',
      trust_basis: 'Fixture',
      blocking_reasons: [],
    },
    ...overrides,
  };
}
