/**
 * Focused browser proof for signed-in operator external-signing slot evidence.
 * The API is route-stubbed: this records operator-supplied technical slot
 * evidence only, with no provider, trust-service, credential, legal-completion,
 * qualified-signature, or envelope-completion claim.
 */
import { expect, test, type Locator, type Page, type Route } from './fixtures';

const ACT_ID = '6b7a5a40-2000-4000-8000-00000000e701';
const BOOK_ID = '6b7a5a40-2000-4000-8000-00000000e702';
const ENTITY_ID = '6b7a5a40-2000-4000-8000-00000000e703';
const USER_ID = '6b7a5a40-2000-4000-8000-00000000e704';
const ENVELOPE_ID = 'env-operator-browser-proof';
const SLOT_ID = 'slot-operator-evidence';

const ENTITY_NAME = 'Operator Evidence Browser Proof, S.A.';
const ACT_TITLE = 'Ata evidencia tecnica operador E2E';
const CANONICAL_DIGEST = '71'.repeat(32);
const SLOT_DIGEST = 'd4'.repeat(32);
const PROVIDER_FIELD_PATTERN =
  /provider|prestador|credential|credentials|credencial|credenciais|pin|otp|can|token|password|passphrase|private_key|signing_key|trust|qualified|qualified_status|legal|completion/i;

test('signed-in operator records external signer slot evidence as technical evidence only', async ({
  page,
}) => {
  const updateBodies: Array<Record<string, unknown>> = [];
  const unexpectedProviderCalls: string[] = [];
  const unhandledCalls: string[] = [];

  await routeExternalSigningOperatorEvidenceFixtures(page, {
    updateBodies,
    unexpectedProviderCalls,
    unhandledCalls,
  });

  await page.goto(`/acts/${ACT_ID}`);

  // The act is «Em assinatura»: the banner asserting the document is frozen is the signing
  // snapshot note (it becomes «Ata selada» only after sealing, which closes signing).
  await expect(
    page
      .getByRole('note')
      .filter({ hasText: 'Cópia canónica congelada para assinatura' })
      .first(),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toBeVisible();

  const envelopeSection = page
    .locator('.external-signing-envelope')
    .filter({ hasText: 'Marta Representante' });
  await expect(envelopeSection).toBeVisible();
  await expect(page.getByText('Acompanhamento operacional apenas')).toBeVisible();
  await expect(
    page.getByText('A evidência do slot é apenas metadados técnicos fornecidos pelo operador.'),
  ).toBeVisible();
  await expect(envelopeSection).toContainText('Envelope 1');
  await expect(envelopeSection).toContainText('Aberto');
  await expect(envelopeSection).toContainText('0 de 1 assinados');
  await expect(envelopeSection).toContainText(SLOT_ID);
  await expect(envelopeSection).toContainText('Marta Representante');
  await expect(envelopeSection).toContainText('Pendente');
  await expect(envelopeSection).toContainText('Verificação de documento oficial');
  await expect(envelopeSection).toContainText('Capacidade de representação');
  await expect(envelopeSection).toContainText('Sem evidência registada');
  await expect(envelopeSection).toContainText(
    'Fluxo operacional; sem contacto com prestador, sem validacao de confianca e sem conclusao legal.',
  );

  await envelopeSection.getByRole('button', { name: 'Registar evidência' }).click();
  await expect(envelopeSection.getByText('Evidência técnica do operador')).toBeVisible();
  await expect(envelopeSection).toContainText(
    'Regista evidência técnica fornecida pelo operador para este slot e marca o slot como assinado. Não contacta prestadores nem conclui o envelope ou a ata.',
  );
  await expect(envelopeSection).toContainText('Evidência de identidade incompleta');
  await expectNoCredentialInputs(envelopeSection);
  await expectNoPositiveClaimText(page);

  const submit = envelopeSection.getByRole('button', {
    name: 'Registar evidência e marcar slot assinado',
  });
  await expect(submit).toBeDisabled();

  await envelopeSection.getByLabel('Referência da evidência').fill('operator-log:slot-1');
  await envelopeSection.getByLabel('Digest opcional').fill(SLOT_DIGEST);
  await envelopeSection
    .getByLabel('Referência para Verificação de documento oficial')
    .fill('id-check:passport-4451');
  await envelopeSection
    .getByLabel('Referência para Capacidade de representação')
    .fill('registry-proxy:2026-07-12');
  await expect(submit).toBeEnabled();

  const updateResponse = waitForApiResponse(
    page,
    `/v1/external-signing/envelopes/${ENVELOPE_ID}`,
    'PATCH',
  );
  await submit.click();
  expect((await updateResponse).status()).toBe(200);

  expect(updateBodies).toHaveLength(1);
  expect(updateBodies[0]).toEqual({
    slots: [
      {
        id: SLOT_ID,
        status: 'signed',
        evidence: [
          {
            label: 'Evidência técnica do operador',
            reference: 'operator-log:slot-1',
            digest: SLOT_DIGEST,
          },
          {
            label: 'Evidência técnica: Verificação de documento oficial',
            reference: 'id-check:passport-4451',
            identity_requirement: 'government_id_check',
          },
          {
            label: 'Evidência técnica: Capacidade de representação',
            reference: 'registry-proxy:2026-07-12',
            identity_requirement: 'representative_capacity',
          },
        ],
      },
    ],
  });
  expect(updateBodies[0]).not.toHaveProperty('complete');
  expect(updateBodies[0]).not.toHaveProperty('actor');
  assertNoProviderCredentialOrClaimFields(updateBodies[0]);

  await expect(page.getByText('Evidência técnica do slot registada.')).toBeVisible();
  await expect(envelopeSection).toContainText('Aberto');
  await expect(envelopeSection).toContainText('1 de 1 assinados');
  await expect(envelopeSection).toContainText('Nenhum');
  await expect(envelopeSection).toContainText('Assinado');
  await expect(envelopeSection).toContainText('Evidência técnica do operador');
  await expect(envelopeSection).toContainText('operator-log:slot-1');
  await expect(envelopeSection.getByTitle(SLOT_DIGEST)).toBeVisible();
  await expect(envelopeSection).toContainText('Evidência técnica: Verificação de documento oficial');
  await expect(envelopeSection).toContainText('id-check:passport-4451');
  await expect(envelopeSection).toContainText('Evidência técnica: Capacidade de representação');
  await expect(envelopeSection).toContainText('registry-proxy:2026-07-12');
  await expect(envelopeSection.getByRole('button', { name: 'Registar evidência' })).toHaveCount(0);
  await expect(envelopeSection).toContainText('Sem ação');
  await expect(envelopeSection).not.toContainText('Concluído');

  await expectNoCredentialInputs(envelopeSection);
  await expectNoPositiveClaimText(page);
  expect(unexpectedProviderCalls).toEqual([]);
  expect(unhandledCalls).toEqual([]);
});

async function routeExternalSigningOperatorEvidenceFixtures(
  page: Page,
  audit: {
    updateBodies: Array<Record<string, unknown>>;
    unexpectedProviderCalls: string[];
    unhandledCalls: string[];
  },
): Promise<void> {
  let envelope = pendingEnvelopeFixture();

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (isLiveSigningOrTrustPath(pathname)) {
      audit.unexpectedProviderCalls.push(`${method} ${pathname}`);
      await fulfillJson(route, { error: `unexpected provider/trust call: ${pathname}` }, 500);
      return;
    }

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
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/signature`) {
      await fulfillJson(route, unsignedStatusFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/signature/providers') {
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
      await fulfillJson(route, [envelope]);
      return;
    }
    if (method === 'PATCH' && pathname === `/v1/external-signing/envelopes/${ENVELOPE_ID}`) {
      const body = readJsonBody(request.postDataJSON());
      audit.updateBodies.push(body);
      envelope = signedEnvelopeFixture();
      await fulfillJson(route, envelope);
      return;
    }

    audit.unhandledCalls.push(`${method} ${pathname}`);
    await fulfillJson(
      route,
      { error: `Unhandled external-signing operator evidence e2e route: ${method} ${pathname}` },
      500,
    );
  });
}

function isLiveSigningOrTrustPath(pathname: string): boolean {
  if (pathname.startsWith('/v1/trust/')) return true;
  if (pathname.startsWith('/v1/scap/')) return true;
  if (pathname.includes('/signature/cmd/')) return true;
  if (pathname.includes('/signature/cc/')) return true;
  if (pathname.includes('/signature/remote/')) return true;
  if (pathname.includes('/signature/local/')) return true;
  if (pathname.includes('/signature/xades/')) return true;
  if (pathname.includes('/signature/asic/')) return true;
  if (pathname.includes('/signature/dss/')) return true;
  if (pathname.includes('/signature/official/import')) return true;
  return false;
}

async function expectNoCredentialInputs(scope: Page | Locator): Promise<void> {
  await expect(scope.locator('input[type="password"]')).toHaveCount(0);
  await expect(
    scope.locator(
      [
        'input[id*="pin" i]',
        'input[id*="otp" i]',
        'input[id*="can" i]',
        'input[id*="credential" i]',
        'input[id*="private-key" i]',
        'input[id*="private_key" i]',
        'input[id*="signing-key" i]',
        'input[id*="signing_key" i]',
        'input[id*="token" i]',
        'input[id*="password" i]',
        'input[id*="passphrase" i]',
        'input[name*="pin" i]',
        'input[name*="otp" i]',
        'input[name*="can" i]',
        'input[name*="credential" i]',
        'input[name*="private-key" i]',
        'input[name*="private_key" i]',
        'input[name*="signing-key" i]',
        'input[name*="signing_key" i]',
        'input[name*="token" i]',
        'input[name*="password" i]',
        'input[name*="passphrase" i]',
      ].join(', '),
    ),
  ).toHaveCount(0);
  await expect(
    scope.locator('label').filter({
      hasText:
        /^(PIN|OTP|CAN|credencial|credenciais|chave privada|private key|signing key|token|palavra-passe|password|passphrase)\b/i,
    }),
  ).toHaveCount(0);
}

function signingPanel(page: Page): Locator {
  return page
    .locator('.panel')
    .filter({ has: page.getByRole('heading', { name: 'Assinatura qualificada' }) });
}

/**
 * The signing surface must not claim provider validation, qualified status or legal effect.
 * Scoped to the qualified-signature card: the surrounding editor carries unrelated
 * *negated* disclaimers («…não afirma suficiência legal…») that a naive substring match hits.
 */
async function expectNoPositiveClaimText(page: Page): Promise<void> {
  await expect(signingPanel(page)).not.toContainText(
    /Chancela assinou|assinado pela Chancela|validado pelo prestador|prestador validou|validação do prestador confirmada|validade legal confirmada|validade jurídica confirmada|efeito legal confirmado|suficiência legal|conclusão jurídica confirmada|estatuto qualificado confirmado|Lista de Confiança validada|notarização|certificação oficial/i,
  );
}

function assertNoProviderCredentialOrClaimFields(value: unknown, path = 'body'): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoProviderCredentialOrClaimFields(entry, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    expect(key, `${path}.${key}`).not.toMatch(PROVIDER_FIELD_PATTERN);
    assertNoProviderCredentialOrClaimFields(entry, `${path}.${key}`);
  }
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
    username: 'operator.evidence',
    display_name: 'Operator Evidence',
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
    name: ENTITY_NAME,
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
    purpose: 'Livro evidencia tecnica operador E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 8,
    predecessor: null,
    required_signatories_abertura: ['Presidente da Mesa'],
    required_signatories_encerramento: null,
  };
}

function actFixture() {
  return {
    id: ACT_ID,
    book_id: BOOK_ID,
    title: ACT_TITLE,
    // Signing actions are only open while the act is «Em assinatura»: sealing deliberately
    // closes them (SigningPanel `signingOpen`). This fixture must therefore stay pre-seal.
    state: 'Signing',
    seal_event_seq: null,
    retifies: null,
    channel: 'Physical',
    meeting_date: '2026-07-12',
    meeting_time: '12:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presencas operador evidence E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Amelia Marques', secretarios: ['Rui Secretario'] },
    agenda: [{ number: 1, text: 'Aprovacao de evidencia tecnica de slot externo' }],
    referenced_documents: [],
    deliberations: 'Ata em assinatura para prova local de evidencia tecnica de assinatura externa.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amelia Marques', capacity: 'Chair' }],
    ata_number: 8,
    payload_digest: 'ab'.repeat(32),
    document_digest: CANONICAL_DIGEST,
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
      id: 'doc-external-operator-evidence-e2e',
      template_id: 'csc-ata-ag/v1',
      pdf_digest: CANONICAL_DIGEST,
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

function unsignedStatusFixture() {
  return {
    status: 'unsigned',
    finalization: 'finalizado',
    require_qualified_for_seal: false,
    evidence: evidenceFixture(),
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

function pendingEnvelopeFixture() {
  return {
    id: ENVELOPE_ID,
    act_id: ACT_ID,
    order_policy: 'parallel',
    slots: [
      {
        id: SLOT_ID,
        signer_label: 'Marta Representante',
        contact_hint: 'slot externo prova operador',
        identity_requirements: ['government_id_check', 'representative_capacity'],
        required: true,
        status: 'pending',
        evidence: [],
      },
    ],
    completed: false,
    completion: {
      completed: false,
      required_slot_count: 1,
      signed_required_slot_count: 0,
      blocking_required_slot_ids: [SLOT_ID],
    },
    notice:
      'Fluxo operacional; sem contacto com prestador, sem validacao de confianca e sem conclusao legal.',
  };
}

function signedEnvelopeFixture() {
  return {
    ...pendingEnvelopeFixture(),
    slots: [
      {
        ...pendingEnvelopeFixture().slots[0],
        status: 'signed',
        evidence: [
          {
            label: 'Evidência técnica do operador',
            reference: 'operator-log:slot-1',
            digest: SLOT_DIGEST,
          },
          {
            label: 'Evidência técnica: Verificação de documento oficial',
            reference: 'id-check:passport-4451',
            identity_requirement: 'government_id_check',
          },
          {
            label: 'Evidência técnica: Capacidade de representação',
            reference: 'registry-proxy:2026-07-12',
            identity_requirement: 'representative_capacity',
          },
        ],
      },
    ],
    completed: false,
    completion: {
      completed: false,
      required_slot_count: 1,
      signed_required_slot_count: 1,
      blocking_required_slot_ids: [],
    },
  };
}
