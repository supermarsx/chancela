/**
 * Focused browser proof for the local/co-located CC batch-signing UI.
 *
 * All API calls are route-stubbed. The tests mount the real signing panel for an unsigned act in «Em assinatura»
 * act and prove the browser request/result behavior only; they do not contact CC middleware,
 * card readers, CMD/CSC/QTSP providers, SCAP, trust services, or live signing systems.
 * This is route-stubbed local browser proof only, not live Autenticacao.gov/CC middleware,
 * card-reader, PKCS#11, hardware, CMD, CSC/QTSP, SCAP, TSA/TSL, or provider execution.
 * It covers optional transient PIN request/clear/no-storage behavior, blank PIN omission,
 * per-document results, auth accounting, declared signer-capacity evidence, and the
 * `POST /v1/signature/cc/batch-sign` route boundary.
 */
import { expect, test, type Page, type Route } from './fixtures';

const ACT_ID = '8f13e6b8-2000-4000-8000-00000000c001';
const BOOK_ID = '8f13e6b8-2000-4000-8000-00000000c002';
const ENTITY_ID = '8f13e6b8-2000-4000-8000-00000000c003';
const USER_ID = '8f13e6b8-2000-4000-8000-00000000c004';
const MANUAL_ACT_ID = '8f13e6b8-2000-4000-8000-00000000c099';
const SIGNED_DIGEST = 'd4'.repeat(32);

type BatchResponseOverrides = {
  auth_mode?: 'single_auth' | 'per_document_auth';
  auth_events?: number;
  [key: string]: unknown;
};

test('local CC batch panel submits transient PIN and renders route-stubbed per-document results', async ({
  page,
}) => {
  const audit = createAudit();
  await routeLocalCcBatchFixtures(page, audit);

  await page.goto(`/acts/${ACT_ID}`);

  const batchPanel = page.getByLabel('Assinatura local em lote com Cartão de Cidadão');
  await expect(batchPanel).toBeVisible();
  await expect(batchPanel.getByText('Cartão de Cidadão local em lote')).toBeVisible();
  await expect(batchPanel.getByText('Assinatura CC local apenas')).toBeVisible();

  // The remote per-document batch panel is a sibling with the same field names, so every
  // locator here is scoped to the local CC batch panel.
  await batchPanel.getByLabel('ID do ato').fill(MANUAL_ACT_ID);
  await batchPanel.getByRole('button', { name: 'Adicionar', exact: true }).click();
  await expect(batchPanel.getByText('2 selecionados de 200')).toBeVisible();

  await batchPanel.getByLabel('Qualidade/capacidade declarada').fill(' Presidente da Mesa ');
  await batchPanel.getByLabel('Ator').fill(' operador-local ');
  await batchPanel.getByLabel('PIN de assinatura do Cartão de Cidadão (opcional)').fill(' 1234 ');
  await batchPanel.getByRole('button', { name: 'Assinar lote com CC local' }).click();

  await expect
    .poll(() => audit.batchBodies)
    .toEqual([
      {
        act_ids: [ACT_ID, MANUAL_ACT_ID],
        capacity: 'Presidente da Mesa',
        actor: 'operador-local',
        pin: '1234',
      },
    ]);
  await expect(page.getByLabel('PIN de assinatura do Cartão de Cidadão (opcional)')).toHaveValue(
    '',
  );

  await expect(page.getByText('Autenticação única')).toBeVisible();
  await expect(page.getByText('1').first()).toBeVisible();
  await expect(page.getByText('doc-local-cc-batch-current')).toBeVisible();
  await expect(
    page
      .locator('code.digest__value')
      .filter({ hasText: `${SIGNED_DIGEST.slice(0, 8)}…${SIGNED_DIGEST.slice(-8)}` }),
  ).toBeVisible();
  await expect(page.getByText('erro técnico route-stubbed sem PIN')).toBeVisible();
  await expect(page.getByText(/Presidente da Mesa/)).toBeVisible();
  await expect(
    page.getByText(
      'Resultados técnicos devolvidos pelo servidor; sem afirmação adicional de estatuto jurídico, CMD/CSC remoto ou certificação do prestador.',
    ),
  ).toBeVisible();

  await expectNoStoredPin(page, '1234');
  expect(audit.forbiddenCalls).toEqual([]);
  expect(audit.unhandledCalls).toEqual([]);
  await expectNoProviderLegalOrQualifiedBatchClaim(page);
});

test('local CC batch panel omits blank PIN and reports per-document authentication from response', async ({
  page,
}) => {
  const audit = createAudit({ auth_mode: 'per_document_auth', auth_events: 2 });
  await routeLocalCcBatchFixtures(page, audit);

  await page.goto(`/acts/${ACT_ID}`);
  const batchPanel = page.getByLabel('Assinatura local em lote com Cartão de Cidadão');
  await batchPanel.getByLabel('ID do ato').fill(MANUAL_ACT_ID);
  await batchPanel.getByRole('button', { name: 'Adicionar', exact: true }).click();
  await batchPanel.getByRole('button', { name: 'Assinar lote com CC local' }).click();

  await expect.poll(() => audit.batchBodies).toEqual([{ act_ids: [ACT_ID, MANUAL_ACT_ID] }]);
  expect(audit.batchBodies[0]).not.toHaveProperty('pin');
  await expect(batchPanel.getByText('Autenticação por documento', { exact: true })).toBeVisible();
  await expect(batchPanel.getByText('Autenticação única', { exact: true })).toHaveCount(0);

  expect(audit.forbiddenCalls).toEqual([]);
  expect(audit.unhandledCalls).toEqual([]);
  await expectNoProviderLegalOrQualifiedBatchClaim(page);
});

function createAudit(responseOverrides: BatchResponseOverrides = {}) {
  return {
    responseOverrides,
    batchBodies: [] as Array<Record<string, unknown>>,
    forbiddenCalls: [] as string[],
    unhandledCalls: [] as string[],
  };
}

async function routeLocalCcBatchFixtures(
  page: Page,
  audit: ReturnType<typeof createAudit>,
): Promise<void> {
  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (isForbiddenLiveProviderPath(pathname, method)) {
      audit.forbiddenCalls.push(`${method} ${pathname}`);
      await fulfillJson(
        route,
        { error: `unexpected live provider route: ${method} ${pathname}` },
        500,
      );
      return;
    }

    if (method === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, sessionFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/session/roster') {
      await fulfillJson(route, { onboarding_required: false, users: [rosterUserFixture()] });
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
      await fulfillJson(route, { entries: [], durable: true, max_entries_per_owner: 500 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 5 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/acts') {
      await fulfillJson(route, [actFixture()]);
      return;
    }
    if (method === 'GET' && pathname === `/v1/entities/${ENTITY_ID}`) {
      await fulfillJson(route, entityFixture());
      return;
    }
    if (method === 'GET' && pathname === `/v1/books/${BOOK_ID}`) {
      await fulfillJson(route, bookFixture());
      return;
    }
    if (method === 'GET' && pathname === `/v1/books/${BOOK_ID}/acts`) {
      await fulfillJson(route, [actFixture()]);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}`) {
      await fulfillJson(route, actFixture());
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/compliance`) {
      await fulfillJson(route, complianceFixture());
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/follow-ups`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/document/bundle`) {
      await fulfillJson(route, documentBundleFixture());
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/documents/generated`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === '/v1/documents/imported') {
      await fulfillJson(route, []);
      return;
    }
    // The generated-minutes card lists convocatoria templates for the act's entity family.
    if (method === 'GET' && pathname === '/v1/templates') {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/signature/external-invites`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/external-signing/envelopes`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === '/v1/signature/providers') {
      await fulfillJson(route, signatureProvidersFixture());
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/signature`) {
      await fulfillJson(route, unsignedSignatureFixture());
      return;
    }
    if (method === 'POST' && pathname === '/v1/signature/cc/batch-sign') {
      const body = readJsonBody(request.postDataJSON());
      audit.batchBodies.push(body);
      await fulfillJson(route, batchResponseFixture(audit.responseOverrides));
      return;
    }

    audit.unhandledCalls.push(`${method} ${pathname}`);
    await fulfillJson(
      route,
      { error: `Unhandled local CC batch-signing e2e route: ${method} ${pathname}` },
      500,
    );
  });
}

function isForbiddenLiveProviderPath(pathname: string, method: string): boolean {
  if (pathname.startsWith('/v1/trust/')) return true;
  if (pathname.startsWith('/v1/scap/')) return true;
  if (pathname.includes('/signature/cmd/')) return true;
  if (pathname.includes('/signature/remote/')) return true;
  if (pathname.includes('/signature/local/')) return true;
  if (pathname.includes('/signature/xades/')) return true;
  if (pathname.includes('/signature/asic/')) return true;
  if (pathname.includes('/signature/dss/')) return true;
  if (pathname.includes('/signature/official/import')) return true;
  if (pathname.includes('/document/signed')) return true;
  return (
    method === 'POST' &&
    pathname.includes('/signature/cc/') &&
    pathname !== '/v1/signature/cc/batch-sign'
  );
}

async function expectNoStoredPin(page: Page, pin: string): Promise<void> {
  const stored = await page.evaluate(() => ({
    local: { ...window.localStorage },
    session: { ...window.sessionStorage },
    url: window.location.href,
  }));
  expect(JSON.stringify(stored)).not.toContain(pin);
}

async function expectNoProviderLegalOrQualifiedBatchClaim(page: Page): Promise<void> {
  const batchPanel = page.getByLabel('Assinatura local em lote com Cartão de Cidadão');
  await expect(batchPanel).not.toContainText(
    /prestador certificado|certificação de prestador confirmada|provider-certified|validade legal confirmada|validade jurídica confirmada|efeito legal confirmado|estatuto qualificado confirmado|assinatura eletrónica qualificada|SCAP verificada|CMD\/CSC remoto concluído|lote remoto concluído|single OTP|\bSAD\b/i,
  );
  await expect(batchPanel.getByRole('button', { name: 'Descarregar PDF assinado' })).toHaveCount(0);
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function readJsonBody(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function userFixture() {
  return {
    id: USER_ID,
    username: 'local.cc.batch',
    display_name: 'Local CC Batch',
    created_at: '2026-01-01T00:00:00.000Z',
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

function permissionGrant(permission: string) {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function sessionFixture() {
  return {
    user: userFixture(),
    permissions: [
      'act.archive',
      'act.edit',
      'book.export',
      'ledger.read',
      'settings.manage',
      'signing.perform',
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
      preferred_family: 'CartaoDeCidadao',
      tsa_url: 'http://ts.cartaodecidadao.pt/tsa/server',
      tsl_url: 'https://www.gns.gov.pt/media/TSLPT.xml',
      tsl_sources: [],
      tsa_providers: [],
      require_qualified_for_seal: false,
      cmd: { env: 'preprod', application_id: null, ama_cert_configured: false },
      providers: [],
    },
    platform: {
      logging: {
        global: 'info',
        app: 'info',
        api: 'info',
        mcp: 'info',
        service_overrides: {},
      },
      api_server: { enabled: true, desired_state: 'running', last_action: null },
      mcp_stdio_server: { enabled: false, desired_state: 'stopped', last_action: null },
      audit: [],
    },
    registry_auto_update: {
      enabled: false,
      cadence: { kind: 'interval_hours', hours: 24 },
      stale_threshold_hours: 720,
      min_backoff_minutes: 60,
      max_backoff_minutes: 1440,
      max_attempts_per_run: 10,
      entity_defaults: { enabled: false, enabled_profiles: [] },
    },
    workflow: {
      reminders: {
        enabled: true,
        lead_days: [30, 7],
        no_due_date_interval_days: 14,
        max_items: 200,
      },
      notifications: {
        enabled: true,
        show_badge: true,
        popup: { enabled: true, max_items: 5 },
      },
    },
    appearance: {
      theme: 'system',
      leather_texture: true,
      texture_intensity: 60,
      button_texture: true,
    },
    ui: {
      dashboard_density: 'comfortable',
      reduce_motion: false,
      high_contrast: false,
      locale: 'pt-PT',
    },
    onboarding: { completed: true, completed_at: '2026-01-01T00:00:00.000Z' },
    ai: { enabled: false },
  };
}

function dashboardFixture() {
  return {
    entities: 1,
    books_open: 1,
    books_total: 1,
    acts_total: 1,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 1,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: 5,
    ledger_valid: true,
    alerts: [],
    reminders: [],
    recent_events: [],
  };
}

function entityFixture() {
  return {
    id: ENTITY_ID,
    name: 'Local CC Batch Browser Proof, S.A.',
    nipc: '503004642',
    nipc_validated: true,
    seat: 'Lisboa',
    family: 'CommercialCompany',
    kind: 'SociedadeAnonima',
    profile: {
      family: 'CommercialCompany',
      rule_pack_id: 'csc-art63/v2',
      allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
      signature_policy: 'QualifiedPreferred',
      template_family: 'csc-commercial',
      calendar_presets: [],
    },
    statute: null,
  };
}

function bookFixture() {
  return {
    id: BOOK_ID,
    entity_id: ENTITY_ID,
    kind: 'AssembleiaGeral',
    state: 'Open',
    purpose: 'Livro local CC batch E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 3,
    predecessor: null,
    required_signatories_abertura: ['Presidente da Mesa'],
    required_signatories_encerramento: null,
  };
}

function actFixture() {
  return {
    id: ACT_ID,
    book_id: BOOK_ID,
    title: 'Ata local CC batch E2E',
    // Signing actions are only open while the act is «Em assinatura»: sealing deliberately
    // closes them (SigningPanel `signingOpen`). This fixture must therefore stay pre-seal.
    state: 'Signing',
    seal_event_seq: null,
    retifies: null,
    channel: 'Physical',
    meeting_date: '2026-07-12',
    meeting_time: '12:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presencas local CC batch E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Amelia Marques', secretarios: ['Rui Secretario'] },
    agenda: [{ number: 1, text: 'Prova local de browser do lote CC' }],
    referenced_documents: [],
    deliberations: 'Ata em assinatura para prova de browser do lote CC local.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amelia Marques', capacity: 'Chair' }],
    ata_number: 3,
    payload_digest: 'ab'.repeat(32),
    document_digest: '71'.repeat(32),
    signed_document_digest: null,
    created_at: '2026-07-12T12:00:00.000Z',
    updated_at: '2026-07-12T12:05:00.000Z',
  };
}

function complianceFixture() {
  return {
    rule_pack: 'csc-art63/v2',
    family: 'CommercialCompany',
    statute_overlay: false,
    issues: [],
    errors: 0,
    warnings: 0,
    seal_allowed: true,
  };
}

function documentBundleFixture() {
  return {
    act_id: ACT_ID,
    document: {
      id: 'doc-local-cc-batch-source',
      template_id: 'csc-ata-ag/v1',
      pdf_digest: '71'.repeat(32),
      profile: 'application/pdf; profile=PDF/A-2u',
      created_at: '2026-07-12T12:05:00.000Z',
    },
    pdf: {
      media_type: 'application/pdf',
      byte_length: 2048,
      download: `/v1/acts/${ACT_ID}/document`,
    },
    attachments_manifest: [],
    validation_report: null,
  };
}

function signatureProvidersFixture() {
  return [
    {
      id: 'cmd',
      family: 'ChaveMovelDigital',
      label: 'Chave Móvel Digital',
      evidentiary_level: 'Qualified',
      configured: false,
    },
  ];
}

function unsignedSignatureFixture() {
  return {
    status: 'unsigned',
    finalization: 'por_assinar',
    require_qualified_for_seal: false,
    pending: null,
    evidence: evidenceFixture(),
  };
}

function batchResponseFixture(overrides: BatchResponseOverrides = {}) {
  return {
    family: 'CartaoDeCidadao',
    auth_mode: 'single_auth',
    auth_events: 1,
    trusted_list_status: null,
    requested: 2,
    signed: 1,
    failed: 1,
    signer_capacity_evidence: {
      requested_provider_capacity: 'Presidente da Mesa',
      source: 'operator_request',
      verification_status: 'declared_only',
      verification_source: null,
      verified_at: null,
      authority_reference: null,
      status_scope: 'request_operator_evidence_only',
    },
    results: [
      {
        act_id: ACT_ID,
        status: 'signed',
        document_id: 'doc-local-cc-batch-current',
        signed_pdf_digest: SIGNED_DIGEST,
        signed_at: '2026-07-12T12:06:00.000Z',
        timestamp_token: false,
      },
      {
        act_id: MANUAL_ACT_ID,
        status: 'error',
        error: 'erro técnico route-stubbed sem PIN',
      },
    ],
    ...overrides,
  };
}

function evidenceFixture() {
  return {
    current_level: 'Unsigned',
    timestamp_evidence_present: false,
    dss_revocation_evidence_present: false,
    dss_revocation_evidence_status: 'not_present',
    dss: {
      present: false,
      vri_count: 0,
      certificate_count: 0,
      ocsp_count: 0,
      crl_count: 0,
      certificate_sha256: [],
      ocsp_sha256: [],
      crl_sha256: [],
      revocation_evidence_present: false,
      inspection_status: 'not_present',
    },
    doc_timestamp: {
      present: false,
      count: 0,
      token_sha256: [],
      validations: [],
      all_imprints_valid: false,
      inspection_status: 'not_present',
    },
    local_b_lt_style_evidence_present: false,
    production_b_lt_status: 'lt_not_implemented',
    live_revocation_fetching: false,
    legal_b_lt_claimed: false,
    legal_b_lta_claimed: false,
    renewal_policy: { status: 'not_configured', action: 'manual_review' },
    long_term_status: ['not_configured', 'lt_not_implemented', 'lta_not_implemented'],
    timestamp_trust: null,
    status_scope: 'technical_evidence_only',
  };
}
