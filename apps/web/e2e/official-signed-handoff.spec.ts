import { Buffer } from 'node:buffer';
import { expect, test, type Locator, type Page, type Route } from './fixtures';

const ACT_ID = '4f75c924-6b15-4ee8-8f18-5d56f120e101';
const BOOK_ID = '4f75c924-6b15-4ee8-8f18-5d56f120e102';
const ENTITY_ID = '4f75c924-6b15-4ee8-8f18-5d56f120e103';
const USER_ID = '4f75c924-6b15-4ee8-8f18-5d56f120e104';

const ENTITY_NAME = 'Official Handoff Browser Proof, Lda.';
const ACT_TITLE = 'Ata handoff oficial E2E';
const CANONICAL_DIGEST = '31'.repeat(32);
const SIGNED_DIGEST = 'c1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';
const SIGNED_PDF_BYTES = '%PDF-official-handoff-signed-evidence';
const SIGNED_PDF_BASE64 = Buffer.from(SIGNED_PDF_BYTES).toString('base64');

const OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS = [
  'official_import_preserves_uploaded_signed_pdf_as_technical_evidence',
  'official_import_trust_validation_not_performed',
  'official_import_qualified_status_not_claimed',
  'official_import_legal_status_not_claimed',
  'official_import_no_secret_factor_collected',
] as const;

test('official signed-PDF handoff import is technical evidence only in the browser', async ({
  page,
}) => {
  const importBodies: Array<Record<string, unknown>> = [];
  const unexpectedLiveCalls: string[] = [];
  const unhandledCalls: string[] = [];

  await routeOfficialHandoffFixtures(page, {
    importBodies,
    unexpectedLiveCalls,
    unhandledCalls,
  });

  await page.goto(`/atas/${ACT_ID}`);

  // The act is «Em assinatura»: the banner asserting the document is frozen is the signing
  // snapshot note (it becomes «Ata selada» only after sealing, which closes signing).
  await expect(
    page
      .getByRole('note')
      .filter({ hasText: 'Cópia canónica congelada para assinatura' })
      .first(),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toBeVisible();
  await expect(page.getByText('PDF já assinado na Autenticação.gov')).toBeVisible();
  await expect(
    page.getByText(
      'Importe o PDF assinado fora da Chancela. Guarda evidência técnica apenas; não afirma validação na Lista de Confiança, estatuto qualificado ou conclusão jurídica.',
    ),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Importar PDF assinado' }).click();

  await expect(page.getByText('Importar PDF assinado por handoff oficial')).toBeVisible();
  await expect(
    page.getByText(
      'Escolha o PDF já assinado na Autenticação.gov ou noutro handoff oficial. Chancela guarda o ficheiro como evidência técnica apenas e não afirma validação na Lista de Confiança, estatuto qualificado ou conclusão jurídica.',
    ),
  ).toBeVisible();
  await expect(page.getByText('Limites a reconhecer')).toBeVisible();
  await expect(
    page.getByText('O PDF assinado carregado é preservado como evidência técnica.'),
  ).toBeVisible();
  await expect(
    page.getByText('Chancela não realiza validação na Lista de Confiança neste fluxo.'),
  ).toBeVisible();
  await expect(
    page.getByText('Chancela não afirma estatuto qualificado para esta importação.'),
  ).toBeVisible();
  await expect(
    page.getByText('Chancela não afirma conclusão jurídica para esta importação.'),
  ).toBeVisible();
  await expect(
    page.getByText('Este fluxo não recolhe PIN, OTP, CAN, credenciais, tokens ou palavras-passe.'),
  ).toBeVisible();

  await expectNoCredentialInputs(page);
  await expectNoPositiveClaimText(page);

  const submit = page.getByRole('button', { name: 'Importar evidência técnica' });
  await expect(submit).toBeDisabled();

  await page.locator('#sign-official-file').setInputFiles({
    name: 'signed-by-official-app.pdf',
    mimeType: 'application/pdf',
    buffer: Buffer.from(SIGNED_PDF_BYTES),
  });
  await page.locator('#sign-official-provider').fill('Autenticação.gov');
  await page.locator('#sign-official-source').fill('operator_selected_cc_or_cmd');
  await expect(page.locator('#sign-official-filename')).toHaveValue('signed-by-official-app.pdf');
  await expect(submit).toBeDisabled();
  expect(importBodies).toEqual([]);

  await page.getByLabel(/reconheço estes limites/).check();
  await expect(submit).toBeEnabled();
  await submit.click();

  await expect(page.getByText('PDF assinado importado como evidência técnica.')).toBeVisible();
  await expect(page.getByText('Ata com PDF assinado importado da Autenticação.gov')).toBeVisible();
  await expect(
    page.getByText(
      'PDF assinado importado de handoff oficial: evidência técnica apenas; não afirma validação na Lista de Confiança, estatuto qualificado ou conclusão jurídica.',
    ),
  ).toBeVisible();
  await expect(
    page.getByText(
      'A importação guarda o PDF assinado e a evidência técnica observada. Os metadados indicados pelo operador não são autoridade para confiança, qualificação ou conclusão jurídica.',
    ),
  ).toBeVisible();
  // Two legitimate renderings now: the evidence definition list and the provider chip in the
  // (signing-open) picker. The evidence entry is the one this assertion is about.
  await expect(page.getByText('Handoff oficial Autenticação.gov', { exact: true })).toBeVisible();
  // The signed digest can render in two panels (signer evidence list and the canonical-vs-signed
  // technical comparison, which appears once the document bundle resolves); assert the first.
  await expect(page.getByTitle(SIGNED_DIGEST).first()).toBeVisible();
  // The technical-comparison panel does render a Trust List row, but only to report that no
  // status was provided. A *claimed* status is what this assertion guards against.
  await expect(
    page.getByText(/Estado na Lista de Confiança(?!:? não fornecido)/u),
  ).toHaveCount(0);

  expect(importBodies).toHaveLength(1);
  expect(importBodies[0]).toEqual({
    signed_pdf_base64: SIGNED_PDF_BASE64,
    provider: 'Autenticação.gov',
    source: 'operator_selected_cc_or_cmd',
    filename: 'signed-by-official-app.pdf',
    acknowledged_guardrail_ids: [...OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS],
  });
  expect(Object.keys(importBodies[0]).sort()).toEqual([
    'acknowledged_guardrail_ids',
    'filename',
    'provider',
    'signed_pdf_base64',
    'source',
  ]);
  for (const forbidden of [
    'pin',
    'otp',
    'can',
    'credential',
    'credentials',
    'passphrase',
    'password',
    'token',
    'signing_key',
    'private_key',
    'trust_validation_performed',
    'qualified_status_claimed',
    'legal_status_claimed',
  ]) {
    expect(importBodies[0]).not.toHaveProperty(forbidden);
  }

  await expectNoCredentialInputs(page);
  await expectNoPositiveClaimText(page);
  expect(unexpectedLiveCalls).toEqual([]);
  expect(unhandledCalls).toEqual([]);
});

async function routeOfficialHandoffFixtures(
  page: Page,
  audit: {
    importBodies: Array<Record<string, unknown>>;
    unexpectedLiveCalls: string[];
    unhandledCalls: string[];
  },
): Promise<void> {
  let imported = false;

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (isLiveSigningOrTrustPath(pathname)) {
      audit.unexpectedLiveCalls.push(`${method} ${pathname}`);
      await fulfillJson(route, { error: `unexpected live signing/trust call: ${pathname}` }, 500);
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
      await fulfillJson(route, { valid: true, length: 6 });
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
      await fulfillJson(route, actFixture(imported));
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
      await fulfillJson(
        route,
        imported ? importedSignatureStatusFixture() : unsignedStatusFixture(),
      );
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
      await fulfillJson(route, []);
      return;
    }
    if (method === 'POST' && pathname === `/v1/acts/${ACT_ID}/signature/official/import`) {
      const body = readJsonBody(request.postDataJSON());
      audit.importBodies.push(body);
      imported = true;
      await fulfillJson(route, officialImportResultFixture(), 201);
      return;
    }

    audit.unhandledCalls.push(`${method} ${pathname}`);
    await fulfillJson(
      route,
      { error: `Unhandled official handoff e2e route: ${method} ${pathname}` },
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
  return false;
}

async function expectNoCredentialInputs(page: Page): Promise<void> {
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await expect(
    page.locator(
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
    page.locator('label').filter({
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
    username: 'official.handoff',
    display_name: 'Official Handoff Operator',
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
    ledger_length: 6,
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
    purpose: 'Livro handoff oficial E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 7,
    predecessor: null,
    required_signatories_abertura: ['Presidente da Mesa'],
    required_signatories_encerramento: null,
  };
}

function actFixture(imported = false) {
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
    meeting_time: '11:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presenças handoff oficial E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Amélia Marques', secretarios: ['Rui Secretário'] },
    agenda: [{ number: 1, text: 'Aprovação de importação técnica de PDF assinado' }],
    referenced_documents: [],
    deliberations: 'Ata em assinatura para prova local do handoff oficial de PDF assinado.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amélia Marques', capacity: 'Chair' }],
    ata_number: 7,
    payload_digest: 'ab'.repeat(32),
    document_digest: CANONICAL_DIGEST,
    signed_document_digest: imported ? SIGNED_DIGEST : null,
    created_at: '2026-07-12T11:00:00.000Z',
    updated_at: '2026-07-12T11:05:00.000Z',
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
      id: 'doc-official-handoff-e2e',
      template_id: 'csc-ata-ag/v1',
      pdf_digest: CANONICAL_DIGEST,
      profile: 'application/pdf; profile=PDF/A-2u',
      created_at: '2026-07-12T11:05:00.000Z',
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
    evidence: evidence('Unsigned', false, [
      'not_configured',
      'lt_not_implemented',
      'lta_not_implemented',
    ]),
  };
}

function importedSignatureStatusFixture() {
  return {
    status: 'signed',
    finalization: 'finalizado',
    require_qualified_for_seal: false,
    signed: {
      family: 'AutenticacaoGovOfficialHandoff',
      evidentiary_level: 'ImportedOfficialHandoffTechnicalEvidence',
      trusted_list_status: null,
      signer_cert_subject: 'CN=Amélia Marques,O=Official Handoff Browser Proof,C=PT',
      signing_time: '2026-07-12T11:20:00.000Z',
      signed_at: '2026-07-12T11:21:00.000Z',
      signed_pdf_digest: SIGNED_DIGEST,
      timestamp_token: false,
      download: `/v1/acts/${ACT_ID}/document/signed`,
    },
    evidence: evidence('B-B', false, [
      'not_configured',
      'lt_not_implemented',
      'lta_not_implemented',
    ]),
  };
}

function officialImportResultFixture() {
  return {
    document_id: 'doc-official-handoff-e2e',
    act_id: ACT_ID,
    family: 'AutenticacaoGovOfficialHandoff',
    evidentiary_level: 'ImportedOfficialHandoffTechnicalEvidence',
    trusted_list_status: null,
    legal_validation: {
      pades_valid: true,
      byte_range_covers_whole_file: true,
      sealed_pdf_prefix_match: true,
      trust_validation: 'not_performed',
      trust_validation_performed: false,
      qualified_status_claimed: false,
      legal_status_claimed: false,
    },
    signing_time: '2026-07-12T11:20:00.000Z',
    signed_at: '2026-07-12T11:21:00.000Z',
    signed_pdf_digest: SIGNED_DIGEST,
    timestamp_token: false,
    finalization: 'finalizado',
    qualification_claimed: false,
    client_metadata_authoritative: false,
    guardrail_ids: [...OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS],
    acknowledged_guardrail_ids: [...OFFICIAL_SIGNATURE_IMPORT_GUARDRAIL_IDS],
    acknowledgement_notice:
      'Official handoff import stores technical signed-PDF evidence only; acknowledgements record guardrails and do not claim trust-list, qualified-signature, or legal completion.',
  };
}

function evidence(
  current_level: string,
  timestamp_evidence_present: boolean,
  long_term_status: string[],
) {
  return {
    current_level,
    timestamp_evidence_present,
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
    long_term_status,
    timestamp_trust: null,
    status_scope: 'technical_evidence_only',
  };
}
