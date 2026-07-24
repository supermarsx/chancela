/**
 * Focused browser proof for written-resolution evidence receipts.
 * The API is route-stubbed: this verifies local metadata capture and rendering only,
 * without live providers, legal proof, legal acceptance, authority certification, or
 * legal-validity claims.
 */
import { expect, test, type Page, type Route } from './fixtures';
import type {
  ActView,
  BookView,
  ComplianceReport,
  Dashboard,
  Entity,
  PermissionGrant,
  Settings,
  SignatureStatusView,
  UpdateActBody,
  UserView,
  WrittenResolutionEvidenceInput,
  WrittenResolutionEvidenceStatusView,
  WrittenResolutionReviewReceiptInput,
  WrittenResolutionReviewReceiptView,
} from '../src/api/types';

const ACT_ID = '6c5b0e9d-1000-4000-8000-00000000e401';
const BOOK_ID = '6c5b0e9d-1000-4000-8000-00000000e402';
const ENTITY_ID = '6c5b0e9d-1000-4000-8000-00000000e403';
const USER_ID = '6c5b0e9d-1000-4000-8000-00000000e404';
const ACT_PATH = `/v1/acts/${ACT_ID}`;
const ENTITY_NAME = 'Written Resolution Evidence E2E, S.A.';
const ACT_TITLE = 'Deliberação por escrito com evidência local';
const EXISTING_NOTE = 'Existing evidence note retained by the act.';
const EXISTING_CHECKLIST_NOTE = 'Retained approval packet metadata.';
const RECEIPT_NOTE = 'Reviewed retained metadata only; no proof or legal acceptance claim.';
const RECEIPT_DIGEST = 'ab'.repeat(32);

const WRITTEN_RESOLUTION_GUARDRAIL_ACKNOWLEDGEMENTS = [
  'local_metadata_only',
  'no_consent_quorum_identity_or_legal_proof',
  'no_external_validation_provider_authority_or_completion_claim',
] as const;

const FALSE_WRITTEN_RESOLUTION_RECEIPT_FLAGS = {
  consent_proof_claimed: false,
  quorum_proof_claimed: false,
  identity_proof_claimed: false,
  legal_acceptance_claimed: false,
  legal_sufficiency_claimed: false,
  external_validation_claimed: false,
  automatic_approval_claimed: false,
  authority_certified_claimed: false,
} as const;

test('written-resolution evidence receipt patches metadata only and renders no-claim history', async ({
  page,
}) => {
  const patchBodies: UpdateActBody[] = [];
  await routeWrittenResolutionEvidenceFixtures(page, patchBodies);

  await page.goto(`/acts/${ACT_ID}`);

  await expect(page.getByRole('heading', { name: /Deliberação por escrito/ })).toBeVisible();
  await expect(page.getByRole('combobox', { name: 'Canal' })).toHaveValue('WrittenResolution');

  const compliance = page.getByLabel('Revisão local da evidência da deliberação por escrito');
  await expect(compliance).toContainText('Comprovativo registado');
  await expect(compliance).toContainText('Apenas metadados locais');
  await expect(compliance).toContainText('certificação por autoridade');

  const history = page.getByRole('region', {
    name: 'Histórico de comprovativos da deliberação por escrito',
  });
  await expect(history).toContainText('existing.operator@example.pt');
  await expect(history).toContainText('Existing receipt remains in browser history.');

  const form = page.getByRole('form', {
    name: 'Adicionar comprovativo de deliberação por escrito',
  });
  await expect(form).toBeVisible();
  await expect(form).toContainText(
    'Apenas metadados locais; as afirmações de prova, suficiência jurídica, prestador, autoridade, conclusão, assinatura, selo e arquivo permanecem falsas.',
  );
  await form.getByLabel('Revisor').fill('operator@example.pt');
  await form.getByLabel('Revisto em').fill('2026-07-13T10:15:00Z');
  await form.getByLabel('Etiqueta da evidência').fill('Approval pack review receipt');
  await form.getByLabel('Referência da evidência').fill('doc:approval-pack');
  await form.getByLabel('Digest da evidência').fill(RECEIPT_DIGEST);
  await form.getByLabel('Notas do comprovativo').fill(RECEIPT_NOTE);
  await form.getByLabel(/Apenas metadados locais/).check();

  const patchResponse = waitForApiResponse(page, ACT_PATH, 'PATCH');
  await form.getByRole('button', { name: 'Registar comprovativo local' }).click();
  expect((await patchResponse).status()).toBe(200);

  expect(patchBodies).toHaveLength(1);
  const body = patchBodies[0];
  expect(Object.keys(body)).toEqual(['written_resolution_evidence']);

  const evidence = body.written_resolution_evidence;
  expect(evidence).toBeTruthy();
  expect(evidence).not.toBeNull();
  expect(evidence?.note).toBe(EXISTING_NOTE);
  expect(evidence?.checklist).toEqual([
    {
      label: 'Approval pack',
      reference: 'doc:approval-pack',
      digest: null,
      note: EXISTING_CHECKLIST_NOTE,
    },
  ]);

  const receipts = evidence?.review_receipts ?? [];
  expect(receipts).toHaveLength(2);
  expect(receipts[0]).toMatchObject(existingReceiptFixture());
  expect(receipts[1]).toEqual({
    reviewer: 'operator@example.pt',
    reviewed_at: '2026-07-13T10:15:00Z',
    status: 'reviewed',
    guardrail_acknowledgements: [...WRITTEN_RESOLUTION_GUARDRAIL_ACKNOWLEDGEMENTS],
    evidence: [
      {
        label: 'Approval pack review receipt',
        locator: 'doc:approval-pack',
        digest: RECEIPT_DIGEST,
      },
    ],
    note: RECEIPT_NOTE,
    ...FALSE_WRITTEN_RESOLUTION_RECEIPT_FLAGS,
  });
  expect(receipts[1]).toMatchObject(FALSE_WRITTEN_RESOLUTION_RECEIPT_FLAGS);
  expectEveryClaimFlagFalse(body);
  expectNoForbiddenClaimKeys(body);

  await expect(history).toContainText('operator@example.pt');
  await expect(history.locator('time[datetime="2026-07-13T10:15:00Z"]')).toBeVisible();
  await expect(history).toContainText('Approval pack review receipt');
  await expect(history).toContainText(`digest:${RECEIPT_DIGEST}`);
  await expect(history).toContainText(RECEIPT_NOTE);
  await expect(history).toContainText('legal_acceptance_claimed=false');
  await expect(history).toContainText('authority_certified_claimed=false');
  await expect(history).toContainText('external_validation_claimed=false');
  await expect(compliance).toContainText('Comprovativos de revisão');
  await expect(compliance).toContainText('2');
  await expect(page.locator('body')).not.toContainText('Aceitação legal concluída');
  await expect(page.locator('body')).not.toContainText('Prova certificada');
  await expect(page.locator('body')).not.toContainText('Certificação por autoridade concluída');
});

async function routeWrittenResolutionEvidenceFixtures(
  page: Page,
  patchBodies: UpdateActBody[],
): Promise<void> {
  let currentAct = actFixture();

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
      await fulfillJson(route, { entries: [], durable: true, max_entries_per_owner: 500 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 3 });
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
    if (method === 'GET' && pathname === ACT_PATH) {
      await fulfillJson(route, currentAct);
      return;
    }
    if (method === 'PATCH' && pathname === ACT_PATH) {
      const body = request.postDataJSON() as UpdateActBody;
      patchBodies.push(body);
      currentAct = {
        ...currentAct,
        written_resolution_evidence: writtenResolutionEvidenceResponse(
          body.written_resolution_evidence,
        ),
      };
      await fulfillJson(route, currentAct);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/compliance`) {
      await fulfillJson(route, complianceFixture(currentAct));
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/follow-ups`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/documents/generated`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/signature`) {
      await fulfillJson(route, signatureStatusFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/signature/providers') {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/external-signing/envelopes`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/signature/external-invites`) {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === '/v1/documents/imported') {
      await fulfillJson(route, []);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled written-resolution evidence e2e route: ${method} ${pathname}` },
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
    username: 'operator.written_resolution',
    display_name: 'Operator Written Resolution',
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

function sessionFixture() {
  return {
    user: userFixture(),
    permissions: [
      'act.edit',
      'book.export',
      'document.generate',
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
      preferred_family: 'Manual',
      tsa_url: null,
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

function dashboardFixture(): Dashboard {
  return {
    entities: 1,
    books_open: 1,
    books_total: 1,
    acts_total: 1,
    acts_draft: 1,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: 3,
    ledger_valid: true,
    current_work: {
      open_books: [
        {
          book_id: BOOK_ID,
          entity_id: ENTITY_ID,
          entity_name: ENTITY_NAME,
          kind: 'LivroAtas',
          purpose: 'Livro de atas',
          opening_date: '2026-01-01',
          last_ata_number: 0,
          total_acts: 1,
          open_acts: 1,
          next_ata_number: 1,
          links: {
            entity: `/v1/entities/${ENTITY_ID}`,
            book: `/v1/books/${BOOK_ID}`,
            act: ACT_PATH,
            ledger: null,
          },
        },
      ],
      act_counts_by_state: {
        Draft: 1,
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

function entityFixture(): Entity {
  return {
    id: ENTITY_ID,
    name: ENTITY_NAME,
    nipc: '510000000',
    nipc_validated: true,
    seat: 'Lisboa',
    family: 'Commercial',
    kind: 'SociedadePorQuotas',
    profile: {
      family: 'Commercial',
      rule_pack_id: 'csc-art63/v2',
      allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
      signature_policy: 'Simple',
      template_family: 'commercial',
      calendar_presets: [],
    },
    statute: null,
  };
}

function bookFixture(): BookView {
  return {
    id: BOOK_ID,
    entity_id: ENTITY_ID,
    kind: 'LivroAtas',
    state: 'Open',
    purpose: 'Livro de atas',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 0,
    predecessor: null,
    required_signatories_abertura: ['Gerência'],
    required_signatories_encerramento: null,
  };
}

function actFixture(): ActView {
  return {
    id: ACT_ID,
    book_id: BOOK_ID,
    title: ACT_TITLE,
    channel: 'WrittenResolution',
    meeting_date: '2026-07-13',
    meeting_time: null,
    place: null,
    mesa: { presidente: 'Ana Silva', secretarios: [] },
    agenda: [{ number: 1, text: 'Aprovação por deliberação escrita' }],
    attendance_reference: null,
    members_present: null,
    members_represented: null,
    referenced_documents: [],
    written_resolution_evidence: {
      status: evidenceStatusFixture(1),
      checklist: [
        {
          label: 'Approval pack',
          reference: 'doc:approval-pack',
          digest: null,
          note: EXISTING_CHECKLIST_NOTE,
        },
      ],
      review_receipts: [existingReceiptFixture()],
      note: EXISTING_NOTE,
    },
    deliberations: 'Deliberação por escrito registada para prova de fluxo local.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Ana Silva', capacity: 'Chair' }],
    state: 'Draft',
    ata_number: null,
    payload_digest: null,
    seal_event_seq: null,
    seal_metadata: null,
    retifies: null,
    convening: undefined,
    ai_provenance: null,
  };
}

function existingReceiptFixture(): WrittenResolutionReviewReceiptView {
  return {
    reviewer: 'existing.operator@example.pt',
    reviewed_at: '2026-07-12T09:00:00Z',
    status: 'needs_follow_up',
    guardrail_acknowledgements: ['local_metadata_only'],
    evidence: [
      {
        label: 'Existing written approvals folder',
        locator: 'folder:written-approvals',
        digest: null,
      },
    ],
    note: 'Existing receipt remains in browser history.',
    ...FALSE_WRITTEN_RESOLUTION_RECEIPT_FLAGS,
  };
}

function writtenResolutionEvidenceResponse(
  evidence: WrittenResolutionEvidenceInput | null | undefined,
): NonNullable<ActView['written_resolution_evidence']> {
  const reviewReceipts = (evidence?.review_receipts ?? []).map(writtenResolutionReceiptResponse);
  return {
    status: evidenceStatusFixture(reviewReceipts.length),
    checklist: (evidence?.checklist ?? []).map((item) => ({
      label: item.label,
      reference: item.reference ?? null,
      digest: item.digest ?? null,
      note: item.note ?? null,
    })),
    review_receipts: reviewReceipts,
    note: evidence?.note ?? null,
  };
}

function writtenResolutionReceiptResponse(
  receipt: WrittenResolutionReviewReceiptInput,
): WrittenResolutionReviewReceiptView {
  return {
    reviewer: receipt.reviewer,
    reviewed_at: receipt.reviewed_at,
    status: receipt.status,
    guardrail_acknowledgements: receipt.guardrail_acknowledgements,
    evidence: receipt.evidence.map((evidence) => ({
      label: evidence.label,
      locator: evidence.locator ?? null,
      digest: evidence.digest ?? null,
    })),
    note: receipt.note ?? null,
    ...FALSE_WRITTEN_RESOLUTION_RECEIPT_FLAGS,
  };
}

function evidenceStatusFixture(reviewReceipts: number): WrittenResolutionEvidenceStatusView {
  return {
    status: 'referenced_only',
    boundary: 'workflow_evidence_status_only',
    signed_signatory_slots: 0,
    digested_attachments: 0,
    checklist_items: 1,
    digested_checklist_items: 0,
    referenced_checklist_items: 1,
    bound_count: 0,
    referenced_only_count: 1,
    review_receipts: reviewReceipts,
    latest_review_status: reviewReceipts > 1 ? 'reviewed' : 'needs_follow_up',
    reviewed_evidence_locators: reviewReceipts,
    reviewed_evidence_digests: reviewReceipts > 1 ? 1 : 0,
  };
}

function complianceFixture(act: ActView): ComplianceReport {
  return {
    rule_pack: 'csc-art63/v2',
    family: 'Commercial',
    statute_overlay: false,
    issues: [],
    errors: 0,
    warnings: 0,
    seal_allowed: true,
    written_resolution_evidence_status: act.written_resolution_evidence?.status,
  };
}

function signatureStatusFixture(): SignatureStatusView {
  return {
    status: 'unsigned',
    finalization: {
      status: 'pending',
      signed_pdf_available: false,
      final_pdf_digest: null,
      signed_at: null,
    },
    require_qualified_for_seal: false,
    evidence: {
      profile: 'basic_local',
      profile_label: 'Assinatura manual/local',
      ltv_level: 'none',
      ltv_label: 'Sem evidência LTV local',
      evidence_status: 'not_applicable',
      evidence_label: 'Não aplicável',
      timestamp_evidence_present: false,
      dss_revocation_evidence_present: false,
      dss_revocation_evidence_status: 'not_applicable',
      local_b_lt_style_evidence_present: false,
      local_b_lta_style_evidence_present: false,
      has_local_evidence_gap: false,
      legal_validity_claimed: false,
      qualified_signature_claimed: false,
      provider_trust_claimed: false,
    },
  };
}

function expectEveryClaimFlagFalse(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) expectEveryClaimFlagFalse(item);
    return;
  }
  if (typeof value !== 'object' || value === null) {
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (key.endsWith('_claimed')) {
      expect(nested, `${key} must stay false`).toBe(false);
    }
    expectEveryClaimFlagFalse(nested);
  }
}

function expectNoForbiddenClaimKeys(value: unknown): void {
  const forbiddenKeys = new Set([
    'proof_claimed',
    'legal_validity_claimed',
    'authority_claimed',
    'authority_certification_claimed',
    'certification_claimed',
    'legal_certification_claimed',
  ]);
  if (Array.isArray(value)) {
    for (const item of value) expectNoForbiddenClaimKeys(item);
    return;
  }
  if (typeof value !== 'object' || value === null) {
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    expect(forbiddenKeys.has(key), `${key} must not be present`).toBe(false);
    expectNoForbiddenClaimKeys(nested);
  }
}
