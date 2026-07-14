/**
 * Focused browser proof for route-stubbed remote signing.
 *
 * The API is route-stubbed. These tests prove reload adoption chooses the matching confirm
 * endpoint for already-open CMD or CSC/QTSP sessions, and that repeated remote-session initiate
 * opens per-document pending rows without echoing credentials. They do not contact providers,
 * trust services, signing devices, SCAP, or live credential systems.
 */
import { expect, test, type Page, type Route } from './fixtures';

const ACT_ID = '7c2d8f40-3000-4000-8000-00000000f901';
const SECOND_ACT_ID = '7c2d8f40-3000-4000-8000-00000000f905';
const BOOK_ID = '7c2d8f40-3000-4000-8000-00000000f902';
const ENTITY_ID = '7c2d8f40-3000-4000-8000-00000000f903';
const USER_ID = '7c2d8f40-3000-4000-8000-00000000f904';
const CSC_PROVIDER_ID = 'multicert-e2e';
const FAKE_CMD_OTP = '999888';
const FAKE_CSC_ACTIVATION = '445566';
const REMOTE_BATCH_CREDENTIAL = 'remote-batch-secret';
const SIGNED_DIGEST = 'c9'.repeat(32);

type ConfirmPendingCase = 'cmd' | 'csc';
type PendingCase = ConfirmPendingCase | 'remote-batch';

test('pending CSC/QTSP session resumes after reload and confirms through provider remote endpoint', async ({
  page,
}) => {
  const audit = createAudit();
  await routePendingSessionFixtures(page, 'csc', audit);

  await page.goto(`/atas/${ACT_ID}`);
  await expect(page.getByLabel('Código de autorização')).toBeVisible();
  await expect(page.getByText('Código de ativação de teste já enviado')).toBeVisible();

  await page.reload();
  await expect(page.getByLabel('Código de autorização')).toBeVisible();
  await expect(page.getByText('Código de ativação de teste já enviado')).toBeVisible();

  const confirmResponse = waitForApiResponse(
    page,
    `/v1/acts/${ACT_ID}/signature/remote/${CSC_PROVIDER_ID}/confirm`,
    'POST',
  );
  await page.getByLabel('Código de autorização').fill(FAKE_CSC_ACTIVATION);
  await page.getByRole('button', { name: 'Confirmar assinatura' }).click();
  expect((await confirmResponse).status()).toBe(200);

  expect(audit.confirmBodies).toEqual([
    {
      endpoint: 'remote',
      body: { session_id: 'sess-csc-resume', activation: FAKE_CSC_ACTIVATION },
    },
  ]);
  expect(audit.endpointMismatches).toEqual([]);
  expect(audit.unhandledCalls).toEqual([]);
  await expect(page.getByText('Ata assinada.')).toBeVisible();
  await expect(page.getByText('Estado na Lista de Confiança')).toHaveCount(0);
  await expectNoLiveTrustOrLegalClaim(page);
});

test('legacy CMD pending session resumes after reload and confirms through CMD endpoint', async ({
  page,
}) => {
  const audit = createAudit();
  await routePendingSessionFixtures(page, 'cmd', audit);

  await page.goto(`/atas/${ACT_ID}`);
  await expect(page.getByLabel('Código SMS (OTP)')).toBeVisible();
  await expect(page.getByText('+351 9....678')).toBeVisible();

  await page.reload();
  await expect(page.getByLabel('Código SMS (OTP)')).toBeVisible();
  await expect(page.getByText('+351 9....678')).toBeVisible();

  const confirmResponse = waitForApiResponse(
    page,
    `/v1/acts/${ACT_ID}/signature/cmd/confirm`,
    'POST',
  );
  await page.getByLabel('Código SMS (OTP)').fill(FAKE_CMD_OTP);
  await page.getByRole('button', { name: 'Confirmar assinatura' }).click();
  expect((await confirmResponse).status()).toBe(200);

  expect(audit.confirmBodies).toEqual([
    {
      endpoint: 'cmd',
      body: { session_id: 'sess-cmd-resume', otp: FAKE_CMD_OTP },
    },
  ]);
  expect(audit.endpointMismatches).toEqual([]);
  expect(audit.unhandledCalls).toEqual([]);
  await expect(page.getByText('Ata assinada.')).toBeVisible();
  await expect(page.getByText('Estado na Lista de Confiança')).toHaveCount(0);
  await expectNoLiveTrustOrLegalClaim(page);
});

test('remote batch initiate opens per-document pending sessions without credential echo', async ({
  page,
}) => {
  const audit = createAudit();
  await routePendingSessionFixtures(page, 'remote-batch', audit);

  await page.goto(`/atas/${ACT_ID}`);
  const remoteBatch = page.getByLabel('Início remoto por documento');
  await expect(remoteBatch).toBeVisible();
  await expect(remoteBatch.getByText('Uma ativação por documento')).toBeVisible();

  await remoteBatch.getByLabel('ID do ato').fill(SECOND_ACT_ID);
  await remoteBatch.getByRole('button', { name: 'Adicionar' }).click();
  await remoteBatch.getByLabel('Prestador remoto').selectOption(CSC_PROVIDER_ID);
  await remoteBatch
    .getByLabel('Referência do utilizador para sessões remotas')
    .fill('amelia.marques');
  await remoteBatch.getByLabel('Credencial para sessões remotas').fill(REMOTE_BATCH_CREDENTIAL);
  await remoteBatch.getByLabel('Qualidade/capacidade declarada').fill('Presidente da Mesa');
  await remoteBatch.getByLabel('Ator').fill('e2e-operator');

  const batchResponse = waitForApiResponse(
    page,
    `/v1/signature/remote/${CSC_PROVIDER_ID}/batch-initiate`,
    'POST',
  );
  await remoteBatch.getByRole('button', { name: 'Iniciar sessões remotas' }).click();
  expect((await batchResponse).status()).toBe(200);

  expect(audit.batchBodies).toEqual([
    {
      act_ids: [ACT_ID, SECOND_ACT_ID],
      user_ref: 'amelia.marques',
      credential: REMOTE_BATCH_CREDENTIAL,
      capacity: 'Presidente da Mesa',
      actor: 'e2e-operator',
    },
  ]);
  expect(audit.endpointMismatches).toEqual([]);
  expect(audit.unhandledCalls).toEqual([]);

  await expect(remoteBatch.getByLabel('Credencial para sessões remotas')).toHaveValue('');
  await expect(remoteBatch.getByText('sess-batch-current')).toBeVisible();
  await expect(remoteBatch.getByText('código enviado para a ata atual')).toBeVisible();
  await expect(remoteBatch.getByText('ato já assinado no servidor de teste')).toBeVisible();
  await expect(remoteBatch.getByText('Confirmar no fluxo normal deste ato.')).toBeVisible();
  await expect(remoteBatch).not.toContainText(REMOTE_BATCH_CREDENTIAL);
  await expectNoLiveTrustOrLegalClaim(page);
});

function createAudit() {
  return {
    confirmBodies: [] as Array<{ endpoint: 'cmd' | 'remote'; body: Record<string, unknown> }>,
    batchBodies: [] as Array<Record<string, unknown>>,
    endpointMismatches: [] as string[],
    unhandledCalls: [] as string[],
  };
}

async function routePendingSessionFixtures(
  page: Page,
  pendingCase: PendingCase,
  audit: ReturnType<typeof createAudit>,
): Promise<void> {
  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (isUnexpectedLiveSigningOrTrustPath(pathname, method, pendingCase)) {
      audit.endpointMismatches.push(`${method} ${pathname}`);
      await fulfillJson(route, { error: `unexpected signing/trust route: ${method} ${pathname}` }, 500);
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
      await fulfillJson(route, { valid: true, length: 7 });
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
      // Keep this proof scoped to pending-session reload adoption/routing. The focused unit tests
      // cover signed-record rendering; this route-stubbed browser test must not promote the stub
      // response into a provider, qualified-status, finalization, or legal-readiness UI claim.
      await fulfillJson(
        route,
        pendingCase === 'remote-batch'
          ? unsignedStatusFixture()
          : pendingStatusFixture(pendingCase),
      );
      return;
    }
    if (
      method === 'POST' &&
      pathname === `/v1/signature/remote/${CSC_PROVIDER_ID}/batch-initiate`
    ) {
      audit.batchBodies.push(readJsonBody(request.postDataJSON()));
      await fulfillJson(route, remoteBatchInitiateFixture());
      return;
    }
    if (method === 'POST' && pathname === `/v1/acts/${ACT_ID}/signature/cmd/confirm`) {
      const body = readJsonBody(request.postDataJSON());
      audit.confirmBodies.push({ endpoint: 'cmd', body });
      await fulfillJson(route, confirmResultFixture('cmd'));
      return;
    }
    if (
      method === 'POST' &&
      pathname === `/v1/acts/${ACT_ID}/signature/remote/${CSC_PROVIDER_ID}/confirm`
    ) {
      const body = readJsonBody(request.postDataJSON());
      audit.confirmBodies.push({ endpoint: 'remote', body });
      await fulfillJson(route, confirmResultFixture('csc'));
      return;
    }

    audit.unhandledCalls.push(`${method} ${pathname}`);
    await fulfillJson(
      route,
      { error: `Unhandled pending-session resume e2e route: ${method} ${pathname}` },
      500,
    );
  });
}

function isUnexpectedLiveSigningOrTrustPath(
  pathname: string,
  method: string,
  pendingCase: PendingCase,
): boolean {
  if (pathname.startsWith('/v1/trust/')) return true;
  if (pathname.startsWith('/v1/scap/')) return true;
  if (pathname.includes('/signature/cc/')) return true;
  if (pathname.includes('/signature/local/')) return true;
  if (pathname.includes('/signature/xades/')) return true;
  if (pathname.includes('/signature/asic/')) return true;
  if (pathname.includes('/signature/dss/')) return true;
  if (pathname.includes('/signature/official/import')) return true;
  if (method !== 'POST') return false;

  const cmdConfirm = `/v1/acts/${ACT_ID}/signature/cmd/confirm`;
  const remoteConfirm = `/v1/acts/${ACT_ID}/signature/remote/${CSC_PROVIDER_ID}/confirm`;
  const remoteBatchInitiate = `/v1/signature/remote/${CSC_PROVIDER_ID}/batch-initiate`;
  if (pendingCase === 'remote-batch') {
    return (
      pathname.includes('/signature/cmd/') ||
      (pathname.includes('/signature/remote/') && pathname !== remoteBatchInitiate)
    );
  }
  if (pendingCase === 'cmd') {
    return (
      pathname.includes('/signature/remote/') ||
      (pathname.includes('/signature/cmd/') && pathname !== cmdConfirm)
    );
  }
  return (
    pathname.includes('/signature/cmd/') ||
    (pathname.includes('/signature/remote/') && pathname !== remoteConfirm)
  );
}

async function expectNoLiveTrustOrLegalClaim(page: Page): Promise<void> {
  await expect(page.locator('body')).not.toContainText(
    /validação do prestador confirmada|prestador validou|validade legal confirmada|validade jurídica confirmada|efeito legal confirmado|suficiência legal|conclusão jurídica confirmada|estatuto qualificado confirmado|Lista de Confiança validada|produção CSC|CSC de produção|SCAP verificada/i,
  );
  await expect(page.getByText('Ata assinada com assinatura eletrónica qualificada')).toHaveCount(0);
  await expect(
    page.getByText('Assinatura eletrónica qualificada (Chave Móvel Digital).'),
  ).toHaveCount(0);
  await expect(
    page.getByText(
      'Assinatura eletrónica qualificada (certificado qualificado de prestador de confiança).',
    ),
  ).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Descarregar PDF assinado' })).toHaveCount(0);
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

function readJsonBody(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function userFixture() {
  return {
    id: USER_ID,
    username: 'pending.resume',
    display_name: 'Pending Resume',
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
      preferred_family: 'OtherQualified',
      tsa_url: 'http://ts.cartaodecidadao.pt/tsa/server',
      tsl_url: 'https://www.gns.gov.pt/media/TSLPT.xml',
      tsl_sources: [],
      tsa_providers: [],
      require_qualified_for_seal: false,
      cmd: { env: 'preprod', application_id: null, ama_cert_configured: false },
      providers: [
        {
          id: 'cmd',
          mode: 'CMD',
          label: 'Chave Móvel Digital (CMD/SCMD)',
          configured: false,
          production_blocked: true,
          local_only: false,
          note: 'Route-stubbed browser proof; no live CMD provider.',
        },
        {
          id: CSC_PROVIDER_ID,
          mode: 'CSC_QTSP',
          label: 'Multicert E2E',
          configured: true,
          production_blocked: true,
          local_only: false,
          note: 'Route-stubbed browser proof; no production CSC/QTSP readiness claim.',
        },
      ],
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
    ledger_length: 7,
    ledger_valid: true,
    alerts: [],
    reminders: [],
    recent_events: [],
  };
}

function entityFixture() {
  return {
    id: ENTITY_ID,
    name: 'Pending Resume Browser Proof, S.A.',
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
    purpose: 'Livro pending resume E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 12,
    predecessor: null,
    required_signatories_abertura: ['Presidente da Mesa'],
    required_signatories_encerramento: null,
  };
}

function actFixture() {
  return {
    id: ACT_ID,
    book_id: BOOK_ID,
    title: 'Ata pending session resume E2E',
    state: 'Sealed',
    seal_event_seq: 5,
    retifies: null,
    channel: 'Physical',
    meeting_date: '2026-07-12',
    meeting_time: '12:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presencas pending resume E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Amelia Marques', secretarios: ['Rui Secretario'] },
    agenda: [{ number: 1, text: 'Prova local de retoma de sessao pendente' }],
    referenced_documents: [],
    deliberations: 'Ata selada para prova de browser da retoma de sessao pendente.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amelia Marques', capacity: 'Chair' }],
    ata_number: 12,
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
      id: 'doc-pending-resume-e2e',
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
      configured: true,
    },
    {
      id: CSC_PROVIDER_ID,
      family: 'QualifiedCertificate',
      label: 'Multicert E2E',
      evidentiary_level: 'Qualified',
      configured: true,
    },
  ];
}

function pendingStatusFixture(pendingCase: ConfirmPendingCase) {
  return {
    status: 'pending',
    finalization: 'finalizado',
    require_qualified_for_seal: false,
    pending:
      pendingCase === 'cmd'
        ? {
            session_id: 'sess-cmd-resume',
            masked_phone: '+351 9....678',
            expires_at: '2026-07-12T12:10:00.000Z',
          }
        : {
            session_id: 'sess-csc-resume',
            masked_phone: 'Código de ativação de teste já enviado',
            provider_id: CSC_PROVIDER_ID,
            family: 'QualifiedCertificate',
            activation_hint: 'Código de ativação de teste já enviado',
            expires_at: '2026-07-12T12:10:00.000Z',
          },
    evidence: evidenceFixture(),
  };
}

function unsignedStatusFixture() {
  return {
    status: 'unsigned',
    finalization: 'finalizado',
    require_qualified_for_seal: false,
    evidence: evidenceFixture(),
  };
}

function remoteBatchInitiateFixture() {
  return {
    provider_id: CSC_PROVIDER_ID,
    family: 'QualifiedCertificate',
    evidentiary_level: 'RouteStubbed',
    auth_mode: 'per_document_activation',
    requested: 2,
    pending: 1,
    failed: 1,
    initiate_events: 1,
    results: [
      {
        act_id: ACT_ID,
        status: 'pending',
        session_id: 'sess-batch-current',
        provider_id: CSC_PROVIDER_ID,
        family: 'QualifiedCertificate',
        pending_status: 'activation_pending',
        activation_hint: 'código enviado para a ata atual',
        expires_at: '2026-07-12T12:10:00.000Z',
      },
      {
        act_id: SECOND_ACT_ID,
        status: 'error',
        error: 'ato já assinado no servidor de teste',
      },
    ],
  };
}

function confirmResultFixture(pendingCase: ConfirmPendingCase) {
  return {
    document_id: 'doc-pending-resume-e2e',
    act_id: ACT_ID,
    provider_id: pendingCase === 'csc' ? CSC_PROVIDER_ID : undefined,
    family: pendingCase === 'cmd' ? 'ChaveMovelDigital' : 'QualifiedCertificate',
    evidentiary_level: 'RouteStubbed',
    trusted_list_status: null,
    signed_at: '2026-07-12T12:06:00.000Z',
    signed_pdf_digest: SIGNED_DIGEST,
    timestamp_token: false,
    finalization: 'finalizado',
  };
}

function evidenceFixture(currentLevel = 'Unsigned') {
  return {
    current_level: currentLevel,
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
