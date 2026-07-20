import { expect, test, type Page, type Route } from './fixtures';

const ACT_ID = '9d1b7a30-1000-4000-8000-00000000e901';
const BOOK_ID = '9d1b7a30-1000-4000-8000-00000000e902';
const ENTITY_ID = '9d1b7a30-1000-4000-8000-00000000e903';
const USER_ID = '9d1b7a30-1000-4000-8000-00000000e904';

const ENTITY_NAME = 'External Evidence E2E, S.A.';
const ACT_TITLE = 'Ata externa assinada E2E';
const CANONICAL_DIGEST = 'a1'.repeat(32);
const SIGNED_DIGEST = 'f9'.repeat(32);
const SIGNED_PDF_PATH = `/v1/acts/${ACT_ID}/document/signed`;
const INVITE_TOKEN = 'cxi_e2e_signed_pdf_tracking_secret_7890';
const TOKEN_HINT = 'cxi_...7890';

test('signed act external signer invite remains tracking-only and never exposes signed PDF', async ({
  page,
}) => {
  const createBodies: Array<Record<string, unknown>> = [];
  const lookupBodies: Array<Record<string, unknown>> = [];
  const workingCopyBodies: Array<Record<string, unknown>> = [];
  const signedPdfRequests: string[] = [];

  await routeSignedActInviteFixtures(page, {
    createBodies,
    lookupBodies,
    workingCopyBodies,
    signedPdfRequests,
  });

  await page.goto(`/atas/${ACT_ID}`);

  await expect(page.getByRole('note').filter({ hasText: 'Ata selada' }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toBeVisible();
  await expect(page.getByText('Ata assinada com assinatura eletrónica qualificada')).toBeVisible();
  // The signed-record summary and the draft/signed technical comparison both show this
  // digest by design, so scope the assertion to the summary deflist.
  await expect(
    page.locator('.signing-deflist').getByText(abbreviatedDigest(SIGNED_DIGEST)),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Descarregar PDF assinado' })).toBeVisible();

  await expect(page.getByText('Convites de assinatura externa')).toBeVisible();
  await expect(
    page.getByText(
      'Regista uma entrega externa e um token de acompanhamento. Não contacta um prestador, não assina o PDF e não altera o nível de evidência.',
    ),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Criar convite' }).click();
  const inviteForm = page.locator('form').filter({ has: page.locator('#external-invite-name') });
  await inviteForm.locator('#external-invite-name').fill('Carla Signatária');
  await inviteForm.locator('#external-invite-email').fill('carla.signataria@example.test');
  await inviteForm.locator('#external-invite-provider').fill('envelope externo multicert');
  await inviteForm
    .locator('#external-invite-purpose')
    .fill('Acompanhar entrega externa sem disponibilizar o PDF assinado');

  const createResponsePromise = waitForApiResponse(
    page,
    `/v1/acts/${ACT_ID}/signature/external-invites`,
    'POST',
  );
  await inviteForm.getByRole('button', { name: 'Criar convite' }).click();
  const createResponse = await createResponsePromise;
  expect(createResponse.status()).toBe(201);

  expect(createBodies).toHaveLength(1);
  expect(createBodies[0]).toMatchObject({
    recipient_name: 'Carla Signatária',
    recipient_email: 'carla.signataria@example.test',
    provider_hint: 'envelope externo multicert',
    purpose: 'Acompanhar entrega externa sem disponibilizar o PDF assinado',
  });
  expect(Object.keys(createBodies[0]).join('\n')).not.toMatch(/token|signed|pdf|download/i);
  expect(createBodies[0]).not.toHaveProperty('token');
  expect(createBodies[0]).not.toHaveProperty('signed_pdf_digest');
  expect(createBodies[0]).not.toHaveProperty('download');

  await expect(page.getByText('Token do convite emitido uma vez')).toBeVisible();
  await expect(page.locator('code.mono').filter({ hasText: INVITE_TOKEN }).first()).toBeVisible();
  await expect(
    page.locator('code.mono').filter({ hasText: externalInviteLink(page, INVITE_TOKEN) }),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Fechar aviso' }).click();
  await expect(page.locator('body')).not.toContainText(INVITE_TOKEN);

  const inviteRow = page.getByRole('row').filter({ hasText: 'Carla Signatária' });
  await expect(inviteRow).toContainText('Acompanhamento apenas');
  await expect(inviteRow).toContainText(TOKEN_HINT);
  await expect(inviteRow).not.toContainText(INVITE_TOKEN);
  expect(signedPdfRequests).toEqual([]);

  await page.goto(`/assinatura-externa?token=${encodeURIComponent(INVITE_TOKEN)}`);

  await expect(page.getByRole('heading', { name: 'Convite externo' })).toBeVisible();
  await expect(page.getByText(ACT_TITLE)).toBeVisible();
  await expect(page.getByText('Acompanhamento apenas')).toBeVisible();
  await expect(
    page.getByText(
      'Este ecrã regista só a resposta ao convite externo. A aceitação é um reconhecimento de acompanhamento, não assina o PDF e não conclui assinatura qualificada.',
    ),
  ).toBeVisible();
  await expect(
    page.getByText(
      'A pré-visualização disponível é Markdown não canónico. O PDF/A preservado e qualquer PDF assinado não são disponibilizados por este convite.',
    ),
  ).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  await expect(page.locator('body')).not.toContainText(INVITE_TOKEN);

  await expect(page.getByRole('button', { name: /descarregar pdf/i })).toHaveCount(0);
  await expect(page.getByRole('link', { name: /descarregar pdf/i })).toHaveCount(0);
  await expect(page.locator('a[download]')).toHaveCount(0);
  await expect(page.locator('a[href*=".pdf" i], a[href*="signed" i]')).toHaveCount(0);

  await page.getByRole('button', { name: 'Pré-visualizar cópia .md' }).click();
  await expect(page.getByTestId('external-working-copy-preview')).toContainText(
    'SIGNED ACT TRACKING WORKING COPY',
  );

  expect(lookupBodies).toEqual([{ token: INVITE_TOKEN }]);
  expect(workingCopyBodies).toEqual([{ token: INVITE_TOKEN }]);
  expect(signedPdfRequests).toEqual([]);
});

async function routeSignedActInviteFixtures(
  page: Page,
  audit: {
    createBodies: Array<Record<string, unknown>>;
    lookupBodies: Array<Record<string, unknown>>;
    workingCopyBodies: Array<Record<string, unknown>>;
    signedPdfRequests: string[];
  },
): Promise<void> {
  const invites = [existingInviteFixture()];

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;

    if (pathname === SIGNED_PDF_PATH) {
      audit.signedPdfRequests.push(`${method} ${pathname}`);
      await fulfillJson(route, { error: 'signed PDF must not be fetched by invite flow' }, 500);
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
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/signature`) {
      await fulfillJson(route, signedSignatureStatusFixture());
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
    if (pathname === `/v1/acts/${ACT_ID}/signature/external-invites`) {
      if (method === 'GET') {
        await fulfillJson(route, invites);
        return;
      }
      if (method === 'POST') {
        const body = readJsonBody(request.postDataJSON());
        audit.createBodies.push(body);
        const invite = createdInviteFixture(body);
        invites.push(invite);
        await fulfillJson(route, { invite, token: INVITE_TOKEN }, 201);
        return;
      }
    }
    if (method === 'POST' && pathname === '/v1/signature/external-invites/lookup') {
      const body = readJsonBody(request.postDataJSON());
      audit.lookupBodies.push(body);
      await fulfillJson(route, publicInviteEnvelope());
      return;
    }
    if (method === 'POST' && pathname === '/v1/signature/external-invites/document/working-copy') {
      const body = readJsonBody(request.postDataJSON());
      audit.workingCopyBodies.push(body);
      await route.fulfill({
        status: 200,
        contentType: 'text/markdown; charset=utf-8',
        body: '# SIGNED ACT TRACKING WORKING COPY\n\nNon-evidentiary public preview only.',
      });
      return;
    }
    if (method === 'POST' && pathname === '/v1/signature/external-invites/respond') {
      await fulfillJson(route, { ...publicInviteEnvelope(), status: 'accepted' });
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled signed invite e2e route: ${method} ${pathname}` },
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

function readJsonBody(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function externalInviteLink(page: Page, token: string): string {
  return new URL(`/assinatura-externa?token=${encodeURIComponent(token)}`, page.url()).toString();
}

function abbreviatedDigest(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-8)}`;
}

function userFixture() {
  return {
    id: USER_ID,
    username: 'external.evidence',
    display_name: 'External Evidence',
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
    purpose: 'Livro assinatura externa E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 4,
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
    state: 'Sealed',
    seal_event_seq: 5,
    retifies: null,
    channel: 'Physical',
    meeting_date: '2026-04-15',
    meeting_time: '11:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presenças externa E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Amélia Marques', secretarios: ['Rui Secretário'] },
    agenda: [{ number: 1, text: 'Aprovação de assinatura externa' }],
    referenced_documents: [],
    deliberations: 'Deliberação selada e já assinada para cobertura de convites externos.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amélia Marques', capacity: 'Chair' }],
    ata_number: 4,
    payload_digest: 'ab'.repeat(32),
    document_digest: CANONICAL_DIGEST,
    signed_document_digest: SIGNED_DIGEST,
    created_at: '2026-04-15T11:00:00.000Z',
    updated_at: '2026-04-15T11:05:00.000Z',
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
      id: 'doc-external-signed-e2e',
      template_id: 'csc-ata-ag/v1',
      pdf_digest: CANONICAL_DIGEST,
      profile: 'application/pdf; profile=PDF/A-2u',
      created_at: '2026-04-15T11:05:00.000Z',
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

function signedSignatureStatusFixture() {
  return {
    status: 'signed',
    finalization: 'finalizado_qualificado',
    require_qualified_for_seal: false,
    signed: {
      family: 'QualifiedCertificate',
      evidentiary_level: 'Qualified',
      trusted_list_status: 'Granted',
      signer_cert_subject: 'CN=Carla Signatária,O=External Evidence E2E,C=PT',
      signing_time: '2026-04-15T11:20:00.000Z',
      signed_at: '2026-04-15T11:21:00.000Z',
      signed_pdf_digest: SIGNED_DIGEST,
      timestamp_token: true,
      download: SIGNED_PDF_PATH,
    },
    evidence: {
      current_level: 'B-T',
      timestamp_evidence_present: true,
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
        present: true,
        count: 1,
        token_sha256: ['de'.repeat(32)],
        validations: [],
        all_imprints_valid: true,
        inspection_status: 'technical_consistent',
      },
      local_b_lt_style_evidence_present: false,
      production_b_lt_status: 'lt_not_implemented',
      live_revocation_fetching: false,
      legal_b_lt_claimed: false,
      legal_b_lta_claimed: false,
      renewal_policy: { status: 'not_configured', action: 'manual_review' },
      long_term_status: ['timestamped'],
      timestamp_trust: {
        decision: 'accepted',
        policy_oid: '1.2.3.4.5',
        policy_oid_accepted: true,
        tsa_certificate_embedded: true,
        embedded_certificate_count: 1,
        qtst_status: 'granted',
        qtst_authenticated: true,
        qtst_matches: [],
        trust_anchor_count: 1,
        certificate_path_valid: true,
        certificate_path_anchor_index: 0,
        certificate_path_len: 2,
        failure_reasons: [],
        status_scope: 'fixture',
      },
      status_scope: 'fixture',
    },
  };
}

function existingInviteFixture() {
  return {
    id: 'invite-existing-signed-e2e',
    act_id: ACT_ID,
    recipient_name: 'Bruno Existente',
    recipient_email: 'bruno.existente@example.test',
    provider_hint: 'manual-envelope',
    purpose: 'Acompanhar assinatura externa',
    status: 'accepted',
    workflow: 'tracking_only',
    token_hint: 'cxi_...1111',
    created_at: '2026-04-15T11:10:00.000Z',
    created_by: 'external.evidence',
    expires_at: '2026-04-17T11:10:00.000Z',
    responded_at: '2026-04-15T11:30:00.000Z',
  };
}

function createdInviteFixture(body: Record<string, unknown>) {
  return {
    id: 'invite-created-signed-e2e',
    act_id: ACT_ID,
    recipient_name: String(body.recipient_name ?? ''),
    recipient_email: String(body.recipient_email ?? ''),
    provider_hint:
      typeof body.provider_hint === 'string' && body.provider_hint ? body.provider_hint : undefined,
    purpose: String(body.purpose ?? ''),
    status: 'pending',
    workflow: 'tracking_only',
    token_hint: TOKEN_HINT,
    created_at: '2026-04-15T12:00:00.000Z',
    created_by: 'external.evidence',
    expires_at: typeof body.expires_at === 'string' ? body.expires_at : '2026-04-17T12:00:00.000Z',
  };
}

function publicInviteEnvelope() {
  return {
    invite_id: 'invite-created-signed-e2e',
    act: {
      id: ACT_ID,
      title: ACT_TITLE,
      state: 'Sealed',
      meeting_date: '2026-04-15',
      ata_number: 4,
      entity_name: ENTITY_NAME,
      book_kind: 'AssembleiaGeral',
    },
    document: {
      id: 'doc-external-signed-e2e',
      template_id: 'csc-ata-ag/v1',
      profile: 'application/pdf; profile=PDF/A-2u',
      pdf_digest: CANONICAL_DIGEST,
      artifact: {
        kind: 'working_copy_markdown',
        method: 'POST',
        path: '/v1/signature/external-invites/document/working-copy',
        content_type: 'text/markdown; charset=utf-8',
        filename: 'ata-externa-assinada-e2e-working-copy.md',
        notice: 'not canonical',
      },
    },
    recipient_name: 'Carla Signatária',
    provider_hint: 'envelope externo multicert',
    purpose: 'Acompanhar entrega externa sem disponibilizar o PDF assinado',
    status: 'pending',
    workflow: 'tracking_only',
    created_at: '2026-04-15T12:00:00.000Z',
    expires_at: '2026-04-17T12:00:00.000Z',
    notice: 'tracking only; signed PDF is not exposed through public invites',
  };
}
