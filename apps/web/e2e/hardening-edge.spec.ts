/**
 * Focused hardening coverage for CI-E2E edge cases that are risky at the browser/API
 * boundary: API-key principals must not become interactive sessions, and trust catalog
 * filtering must remain deterministic over offline fixture data.
 */
import {
  expect,
  test,
  type APIRequestContext,
  type Locator,
  type Page,
  type Route,
} from './fixtures';
import { OPERATOR, OPERATOR_PASSWORD, signInAt } from './auth';
import { routeShellPolling } from './shell-routes';
import type {
  ApiKeyCreated,
  SessionResult,
  TsaCatalogView,
  TsaRecordView,
  TsaSummaryView,
  TslCatalogView,
  TslProviderView,
  TslServiceDetailView,
  TslServiceSummaryView,
  TslSummaryView,
} from '../src/api/types';

test('API-key bearer works for granted reads but cannot satisfy session or step-up routes', async ({
  page,
}) => {
  await signInAt(page, '/');
  const origin = new URL(page.url()).origin;
  const apiKey = await createApiKeyWithSession(page.request, origin);
  const bearer = { Authorization: `Bearer ${apiKey.secret}` };

  const ledger = await page.request.get(`${origin}/api/v1/ledger/events?limit=1`, {
    headers: bearer,
  });
  expect(ledger.ok(), await ledger.text()).toBeTruthy();

  const sessionOnly = await page.request.get(`${origin}/v1/session`, { headers: bearer });
  expect([401, 403], await sessionOnly.text()).toContain(sessionOnly.status());

  const reanchor = await page.request.post(`${origin}/v1/ledger/recovery/reanchor`, {
    headers: bearer,
    data: {
      reason: 'E2E bearer boundary probe',
      reauth: { password: OPERATOR_PASSWORD },
    },
  });
  expect([401, 403], await reanchor.text()).toContain(reanchor.status());
});

test('TSL catalog structured filters handle accent search, service filters, and empty states', async ({
  page,
}) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeTrustCatalog(page);

  await page.goto('/tools/trust');

  const catalog = panelByTitle(page, 'Catálogo de confiança');
  await expect(catalog).toBeVisible();
  await expect(catalog.getByRole('button', { name: /Assinatura Qualificada Ágil/ })).toBeVisible();

  await page
    .getByRole('searchbox', { name: 'Procurar na lista de confiança TSL', exact: true })
    .fill('agil');
  await expect(catalog.getByRole('button', { name: /Assinatura Qualificada Ágil/ })).toBeVisible();
  await expect(
    catalog.getByRole('button', { name: /Selo Temporal Qualificado Retirado/ }),
  ).toHaveCount(0);
  await expect(page).toHaveURL(/[?&]trustQ=agil/);

  await catalog.getByRole('button', { name: 'Qualificados' }).click();
  await expect(catalog.getByRole('button', { name: /Assinatura Qualificada Ágil/ })).toBeVisible();
  await expect(page).toHaveURL(/[?&]trustFilter=qualified/);

  await page
    .getByRole('searchbox', { name: 'Procurar na lista de confiança TSL', exact: true })
    .fill('');
  await catalog.getByRole('button', { name: 'Todos', exact: true }).click();
  await expect(catalog.getByRole('button', { name: 'Todos', exact: true })).toHaveAttribute(
    'aria-pressed',
    'true',
  );
  await catalog.locator('#trust-type-filter').selectOption('qtst');
  await catalog.locator('#trust-status-filter').selectOption('Withdrawn');

  await expect(
    catalog.getByRole('button', { name: /Selo Temporal Qualificado Retirado/ }),
  ).toBeVisible();
  await expect(catalog.getByRole('button', { name: /Assinatura Qualificada Ágil/ })).toHaveCount(0);
  await expect(page).toHaveURL(/[?&]trustType=qtst/);
  await expect(page).toHaveURL(/[?&]trustStatus=Withdrawn/);

  await setSwitch(catalog, 'Com histórico', true);
  await setSwitch(catalog, 'Com ponto de serviço', true);
  await expect(
    catalog.getByRole('button', { name: /Selo Temporal Qualificado Retirado/ }),
  ).toBeVisible();
  await expect(page).toHaveURL(/[?&]trustHistory=1/);
  await expect(page).toHaveURL(/[?&]trustSupply=1/);

  await catalog.locator('#trust-status-filter').selectOption('Granted');
  await expect(catalog.getByText('Sem resultados')).toBeVisible();
  await expect(catalog.getByText('Nenhum item selecionado')).toBeVisible();
});

test('TSA catalog filters qualified timestamp records without live timestamp calls', async ({
  page,
}) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeTrustCatalog(page);

  await page.goto('/tools/trust/tsa');

  const tsa = panelByTitle(page, 'TSA / RFC 3161');
  await expect(tsa).toBeVisible();
  await expect(
    tsa.getByText('Offline TSA fixture ready; no live timestamp request was sent.'),
  ).toBeVisible();

  await tsa.getByRole('searchbox', { name: 'Procurar registos TSA', exact: true }).fill('lisboa');
  await expect(tsa.getByRole('button', { name: /QTST Lisboa/ })).toBeVisible();
  await expect(tsa.getByRole('button', { name: /TST Retirado/ })).toHaveCount(0);
  await expect(page).toHaveURL(/[?&]tsaQ=lisboa/);

  await tsa.getByRole('searchbox', { name: 'Procurar registos TSA', exact: true }).fill('');
  await expect(page).toHaveURL((url) => !url.searchParams.has('tsaQ'));
  await tsa.locator('#tsa-type-filter').selectOption('qtst');
  await setSwitch(tsa, 'Com ponto de serviço', true);

  await expect(tsa.getByRole('button', { name: /QTST Lisboa/ })).toBeVisible();
  await expect(tsa.getByText('1 de 2 registos TSA')).toBeVisible();
  await expect(page).toHaveURL(/[?&]tsaType=qtst/);
  await expect(page).toHaveURL(/[?&]tsaSupply=1/);

  await tsa.locator('#tsa-status-filter').selectOption('Withdrawn');
  await expect(tsa.getByText('Sem registos TSA')).toBeVisible();
  await expect(page).toHaveURL(/[?&]tsaStatus=Withdrawn/);

  await setSwitch(tsa, 'Com ponto de serviço', false);
  await expect(page).toHaveURL((url) => !url.searchParams.has('tsaSupply'));
  // Address the final orthogonal filter combination directly so the assertion is not coupled to
  // an earlier search-navigation transition still settling in Chromium.
  await page.goto('/tools/trust/tsa?tsaStatus=Withdrawn&tsaType=tst');
  await expect(page).toHaveURL(/[?&]tsaType=tst/);
  await expect(tsa.getByRole('button', { name: /TST Retirado/ })).toBeVisible();
  await expect(tsa.getByRole('button', { name: /QTST Lisboa/ })).toHaveCount(0);
});

function panelByTitle(page: Page, title: string) {
  return page.locator('.panel').filter({ has: page.getByRole('heading', { name: title }) });
}

async function setSwitch(panel: Locator, name: string, checked: boolean): Promise<void> {
  const input = panel.getByRole('switch', { name });
  if ((await input.isChecked()) !== checked) {
    await panel.locator('label.toggle', { hasText: name }).click();
  }
  if (checked) {
    await expect(input).toBeChecked();
  } else {
    await expect(input).not.toBeChecked();
  }
}

async function createApiKeyWithSession(
  request: APIRequestContext,
  origin: string,
): Promise<ApiKeyCreated> {
  // t33-e2: sign in by the typed identifier. The unauthenticated roster no longer publishes
  // the operator's id (or that they exist at all) — the server resolves the username.
  const sessionResponse = await request.post(`${origin}/v1/session`, {
    data: { username: OPERATOR.username, password: OPERATOR_PASSWORD },
  });
  expect(sessionResponse.ok(), await sessionResponse.text()).toBeTruthy();
  const session = (await sessionResponse.json()) as SessionResult;

  const keyResponse = await request.post(`${origin}/v1/api-keys`, {
    headers: { 'X-Chancela-Session': session.token },
    data: {
      name: `E2E bearer boundary ${Date.now()}`,
      grant: {
        kind: 'permissions',
        permissions: ['ledger.read', 'ledger.recover'],
        scope: { kind: 'global' },
      },
      rate_limit: { rpm: 120, burst: 10 },
    },
  });
  expect(keyResponse.ok(), await keyResponse.text()).toBeTruthy();
  return (await keyResponse.json()) as ApiKeyCreated;
}

async function routeAuthenticatedShell(
  page: Page,
  permissions = ['settings.manage', 'ledger.read'],
): Promise<void> {
  // First, so a spec's own stub for the same URL (registered later) still wins.
  await routeShellPolling(page);

  const user = userFixture();
  const session = {
    user,
    permissions: permissions.map((permission) => ({
      permission,
      scope: { kind: 'global' },
      source: 'role',
    })),
  };

  await page.route('**/v1/session**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, session);
      return;
    }
    if (request.method() === 'GET' && pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: [
          {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            has_secret: false,
          },
        ],
      });
      return;
    }

    await route.continue();
  });

  await page.route('**/v1/users', async (route) => {
    const request = route.request();
    if (request.method() === 'GET' && new URL(request.url()).pathname === '/v1/users') {
      await fulfillJson(route, [user]);
      return;
    }

    await route.continue();
  });
}

async function routeSettings(page: Page): Promise<void> {
  await page.route('**/v1/settings', async (route) => {
    const request = route.request();
    if (request.method() === 'GET' && new URL(request.url()).pathname === '/v1/settings') {
      await fulfillJson(route, settingsFixture());
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
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    const url = new URL(request.url());
    const pathname = url.pathname;
    if (pathname === '/v1/trust/status') {
      await fulfillJson(route, catalog.summary);
      return;
    }
    if (pathname === '/v1/trust/catalog') {
      await fulfillJson(
        route,
        url.search ? filterTrustServices(catalog, url.searchParams) : catalog,
      );
      return;
    }
    if (pathname === '/v1/trust/tsa') {
      await fulfillJson(route, url.search ? filterTsaRecords(tsa, url.searchParams) : tsa);
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

function filterTrustServices(
  catalog: TslCatalogView,
  params: URLSearchParams,
): TslServiceSummaryView[] {
  const search = normalizeSearch(params.get('search') ?? '');
  const identifier = normalizeSearch(params.get('identifier') ?? '');
  const serviceType = normalizeSearch(params.get('service_type') ?? '');
  const status = params.get('status');
  const history = params.get('history');
  const supplyPoint = params.get('supply_point');
  const limit = Number(params.get('limit') ?? Number.MAX_SAFE_INTEGER);

  return catalog.providers
    .flatMap((provider) => provider.services)
    .filter((service) => {
      const searchable = normalizeSearch(
        [
          service.name,
          service.provider_name,
          service.service_type,
          service.status.kind,
          service.status.uri,
          ...service.additional_service_info,
          ...service.service_supply_points,
          ...service.identities.subject_names,
          ...service.identities.subject_key_ids,
        ].join(' '),
      );
      const identifiers = normalizeSearch(
        [
          service.id,
          service.provider_id,
          ...service.identities.subject_names,
          ...service.identities.subject_key_ids,
        ].join(' '),
      );
      return (
        (!search || searchable.includes(search)) &&
        (!identifier || identifiers.includes(identifier)) &&
        (!serviceType || normalizeSearch(service.service_type).includes(serviceType)) &&
        (!status || service.status.kind === status) &&
        (!history || service.history_count > 0) &&
        (!supplyPoint || service.service_supply_points.length > 0)
      );
    })
    .slice(0, Number.isFinite(limit) ? limit : undefined);
}

function filterTsaRecords(catalog: TsaCatalogView, params: URLSearchParams): TsaRecordView[] {
  const search = normalizeSearch(params.get('search') ?? '');
  const identifier = normalizeSearch(params.get('identifier') ?? '');
  const serviceType = normalizeSearch(params.get('service_type') ?? '');
  const status = params.get('status');
  const supplyPoint = params.get('supply_point');
  const limit = Number(params.get('limit') ?? Number.MAX_SAFE_INTEGER);

  return catalog.records
    .filter((record) => {
      const searchable = normalizeSearch(
        [
          record.name,
          record.provider_name,
          record.service_type,
          record.status.kind,
          record.status.uri,
          ...record.additional_service_info,
          ...record.service_supply_points,
          ...record.identities.subject_names,
          ...record.identities.subject_key_ids,
        ].join(' '),
      );
      const identifiers = normalizeSearch(
        [
          record.id,
          record.provider_id,
          ...record.identities.subject_names,
          ...record.identities.subject_key_ids,
        ].join(' '),
      );
      return (
        (!search || searchable.includes(search)) &&
        (!identifier || identifiers.includes(identifier)) &&
        (!serviceType || normalizeSearch(record.service_type).includes(serviceType)) &&
        (!status || record.status.kind === status) &&
        (!supplyPoint || record.service_supply_points.length > 0)
      );
    })
    .slice(0, Number.isFinite(limit) ? limit : undefined);
}

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .toLowerCase();
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function userFixture() {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    username: 'e2e.operator',
    display_name: 'Operador E2E',
    created_at: '2026-01-01T00:00:00.000Z',
    active: true,
    has_secret: false,
    has_attestation_key: false,
    has_recovery_phrase: false,
  };
}

function settingsFixture() {
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
      tsa_url: 'http://ts.cartaodecidadao.pt/tsa/server',
      tsl_url: 'https://www.gns.gov.pt/media/TSLPT.xml',
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

const TRUST_SOURCE = {
  kind: 'Fixture' as const,
  path: null,
  note: 'E2E offline trust fixture; no live TSL fetch attempted',
};

const TRUST_SUMMARY: TslSummaryView = {
  source: TRUST_SOURCE,
  scheme_operator_name: 'Operador TSL E2E',
  scheme_name: 'Lista de confiança E2E',
  scheme_territory: 'PT',
  sequence_number: 7,
  issue_date_time: '2026-01-01T00:00:00.000Z',
  next_update: '2026-02-01T00:00:00.000Z',
  stale: false,
  validation: {
    checked_at: '2026-01-01T00:00:00.000Z',
    signature: 'Valid',
    error: null,
  },
  providers: 2,
  services: 3,
  ca_qc_services: 1,
  qualified_esignature_services: 1,
  trusted_esignature_services: 1,
};

function trustCatalogFixture(): TslCatalogView {
  const qualified = serviceFixture({
    id: 'svc-qualified-ca',
    provider_id: 'provider-multicert',
    provider_name: 'MULTICERT - Serviços de Certificação Eletrónica',
    name: 'Assinatura Qualificada Ágil',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC',
    status: { kind: 'Granted', uri: 'urn:e2e:granted' },
    ca_qc: true,
    qualified_for_esignatures: true,
    trusted_for_esignatures: true,
    additional_service_info: ['http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures'],
    service_supply_points: ['https://ca.example.test/ocsp'],
    history_count: 2,
    subject: 'CN=Assinatura Qualificada Ágil,O=MULTICERT,C=PT',
  });
  const withdrawnQtst = serviceFixture({
    id: 'svc-withdrawn-qtst',
    provider_id: 'provider-tempo',
    provider_name: 'Tempo Seguro PT',
    name: 'Selo Temporal Qualificado Retirado',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
    status: { kind: 'Withdrawn', uri: 'urn:e2e:withdrawn' },
    service_supply_points: ['https://tsa-retired.example.test/rfc3161'],
    history_count: 1,
    subject: 'CN=Selo Temporal Qualificado Retirado,O=Tempo Seguro,C=PT',
  });
  const other = serviceFixture({
    id: 'svc-other',
    provider_id: 'provider-tempo',
    provider_name: 'Tempo Seguro PT',
    name: 'Serviço não qualificado',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/Other',
    status: { kind: 'Other', uri: 'urn:e2e:other' },
    subject: 'CN=Serviço não qualificado,O=Tempo Seguro,C=PT',
  });

  return {
    summary: TRUST_SUMMARY,
    providers: [
      providerFixture('provider-multicert', 'MULTICERT - Serviços de Certificação Eletrónica', [
        qualified,
      ]),
      providerFixture('provider-tempo', 'Tempo Seguro PT', [withdrawnQtst, other]),
    ],
  };
}

function serviceFixture(
  overrides: Partial<TslServiceSummaryView> & { subject?: string },
): TslServiceSummaryView {
  const subject = overrides.subject ?? `CN=${overrides.name ?? 'E2E'},O=Fixture,C=PT`;
  return {
    id: 'svc-e2e',
    provider_id: 'provider-e2e',
    provider_name: 'Prestador E2E',
    name: 'Serviço E2E',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/Other',
    status: { kind: 'Granted', uri: null },
    status_starting_time: '2020-01-01T00:00:00.000Z',
    status_starting_time_raw: '2020-01-01T00:00:00.000Z',
    ca_qc: false,
    qualified_for_esignatures: false,
    trusted_for_esignatures: false,
    additional_service_info: [],
    service_supply_points: [],
    history_count: 0,
    identities: {
      certificates: 1,
      subject_names: [subject],
      subject_key_ids: [`${overrides.id ?? 'svc-e2e'}-ski`],
    },
    ...overrides,
  };
}

function providerFixture(
  id: string,
  name: string,
  services: TslServiceSummaryView[],
): TslProviderView {
  return {
    id,
    name,
    trade_names: [name.split(' ')[0]],
    information_uris: [`https://${id}.example.test/`],
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
    digital_identities: [
      {
        kind: 'X509SubjectName',
        value: service.identities.subject_names[0] ?? service.name,
        sha256: 'a'.repeat(64),
        byte_length: 128,
      },
    ],
    history:
      service.history_count > 0
        ? [
            {
              name: `${service.name} histórico`,
              service_type: service.service_type,
              status: service.status,
              status_starting_time: '2019-01-01T00:00:00.000Z',
              status_starting_time_raw: '2019-01-01T00:00:00.000Z',
              additional_service_info: service.additional_service_info,
              service_supply_points: service.service_supply_points,
              identities: service.identities,
            },
          ]
        : [],
    summary,
  };
}

function tsaCatalogFixture(): TsaCatalogView {
  const records = [
    tsaRecordFixture({
      id: 'tsa-qualified-lisboa',
      provider_name: 'Tempo Seguro PT',
      name: 'QTST Lisboa',
      service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST',
      status: { kind: 'Granted', uri: 'urn:e2e:granted' },
      qualified_timestamp_service: true,
      granted: true,
      effective: true,
      trusted: true,
      service_supply_points: ['https://tsa-lisboa.example.test/rfc3161'],
      subject: 'CN=QTST Lisboa,O=Tempo Seguro,C=PT',
      classification: 'QualifiedTimestampService',
      trust_basis: 'GrantedByValidTsl',
    }),
    tsaRecordFixture({
      id: 'tsa-withdrawn-tst',
      provider_name: 'Tempo Seguro PT',
      name: 'TST Retirado',
      service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TST',
      status: { kind: 'Withdrawn', uri: 'urn:e2e:withdrawn' },
      qualified_timestamp_service: false,
      granted: false,
      effective: false,
      trusted: false,
      subject: 'CN=TST Retirado,O=Tempo Seguro,C=PT',
      classification: 'TimestampService',
      trust_basis: 'Withdrawn',
      blocking_reasons: ['Serviço retirado na fixture TSL'],
    }),
  ];

  return { summary: tsaSummaryFixture(records), records };
}

function tsaSummaryFixture(records: TsaRecordView[]): TsaSummaryView {
  return {
    configured_url: 'http://tsa.local.test/rfc3161',
    status: 'Ready',
    status_message: 'Offline TSA fixture ready; no live timestamp request was sent.',
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
    timestamp: {
      gen_time: '2026-01-01T00:00:00.000Z',
      policy: '1.2.3.4.5',
      serial_number: '42',
      token_sha256: '3'.repeat(64),
      token_bytes: 2048,
      tsa_certificate_embedded: true,
    },
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
      source: TRUST_SOURCE,
      signature: 'Valid',
      error: null,
    },
    records: records.length,
    granted_records: records.filter((record) => record.granted).length,
    trusted_records: records.filter((record) => record.trusted).length,
    policy_analysis: {
      accepted_policy: 'any',
      fixture_policy: '1.2.3.4.5',
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

function tsaRecordFixture(
  overrides: Partial<TsaRecordView> & {
    subject?: string;
    classification?: string;
    trust_basis?: string;
    blocking_reasons?: string[];
  },
): TsaRecordView {
  const subject = overrides.subject ?? `CN=${overrides.name ?? 'TSA E2E'},O=Fixture,C=PT`;
  return {
    id: 'tsa-e2e',
    provider_id: 'provider-tempo',
    provider_name: 'Tempo Seguro PT',
    name: 'TSA E2E',
    service_type: 'http://uri.etsi.org/TrstSvc/Svctype/TSA/TST',
    status: { kind: 'Granted', uri: null },
    status_starting_time: '2020-01-01T00:00:00.000Z',
    status_starting_time_raw: '2020-01-01T00:00:00.000Z',
    qualified_timestamp_service: false,
    granted: true,
    effective: true,
    trusted: false,
    additional_service_info: [],
    service_supply_points: [],
    history_count: 0,
    identities: {
      certificates: 1,
      subject_names: [subject],
      subject_key_ids: [`${overrides.id ?? 'tsa-e2e'}-ski`],
    },
    analysis: {
      classification: overrides.classification ?? 'TimestampService',
      trust_basis: overrides.trust_basis ?? 'Fixture',
      blocking_reasons: overrides.blocking_reasons ?? [],
    },
    ...overrides,
  };
}
