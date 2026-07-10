/**
 * Focused browser regression for imported-document operator review. The API is route-stubbed
 * so the test pins the review UI contract without depending on mutable server data.
 */
import { expect, test, type Page, type Route } from './fixtures';
import type {
  ActView,
  BookView,
  ComplianceReport,
  Entity,
  ImportedDocumentReviewBody,
  ImportedDocumentView,
  PermissionGrant,
  Settings,
  SignatureStatusView,
  UserView,
} from '../src/api/types';

const ACT_ID = '2b8d1d70-1000-4000-8000-00000000d301';
const BOOK_ID = '2b8d1d70-1000-4000-8000-00000000d302';
const ENTITY_ID = '2b8d1d70-1000-4000-8000-00000000d303';
const USER_ID = '2b8d1d70-1000-4000-8000-00000000d304';
const IMPORT_ID = '2b8d1d70-1000-4000-8000-00000000d305';

const ENTITY_NAME = 'Imported Review E2E, S.A.';
const ACT_TITLE = 'Ata import review E2E';
const REVIEW_NOTICE =
  'Operator review records a preservation workflow decision only; it does not run OCR, convert bytes, replace the canonical PDF/A, or claim legal acceptance.';
const LEGAL_NOTICE =
  'Imported document preserved as non-canonical evidence only; it does not replace the generated PDF/A or signed PDF, and no legal validity, PDF/A conformance, or signature validity is claimed.';
const REVIEW_NOTE = 'Conferido como evidência preservada, sem conversão canónica.';

test('non-canonical imported document can be reviewed without losing conservative evidence messaging', async ({
  page,
}) => {
  const reviewBodies: ImportedDocumentReviewBody[] = [];
  await routeImportedReviewFixtures(page, reviewBodies);

  await page.goto(`/atas/${ACT_ID}`);

  await expect(page.getByRole('note').filter({ hasText: 'Ata selada' }).first()).toBeVisible();
  await expect(page.getByText('Documentos importados', { exact: true })).toBeVisible();
  await expect(
    page.locator('.badge').filter({ hasText: 'Evidência não canónica' }).first(),
  ).toBeVisible();
  await expect(page.locator('.badge').filter({ hasText: 'Não canónico' }).first()).toBeVisible();
  await expect(page.getByText('Revisão do operador necessária')).toBeVisible();

  const list = page.getByRole('list', { name: 'Documentos importados' });
  await expect(list.getByText('legacy-minutes.doc')).toBeVisible();
  await list.getByRole('button', { name: 'Ver metadados' }).click();

  const metadata = await page.getByRole('group', {
    name: 'Metadados do documento importado',
  });
  await expect(metadata).toContainText('Revisão do operador necessária');
  await expect(metadata).toContainText(REVIEW_NOTICE);
  await expect(metadata).toContainText(LEGAL_NOTICE);
  await expect(metadata).toContainText('Não indicado');

  const form = page.getByRole('form', { name: 'Revisão operacional do documento importado' });
  await expect(form).toBeVisible();
  await expect(form.getByText('Revisão conservadora')).toBeVisible();
  await expect(form.getByText(REVIEW_NOTICE)).toBeVisible();

  const status = page.getByLabel('Estado de revisão');
  await expect(status).toBeVisible();
  await status.selectOption('rejected_non_canonical_evidence');
  await page.getByLabel('Nota da revisão').fill(REVIEW_NOTE);

  const reviewResponse = waitForApiResponse(
    page,
    `/v1/documents/imported/${IMPORT_ID}/review`,
    'PATCH',
  );
  await page.getByRole('button', { name: 'Guardar revisão' }).click();
  expect((await reviewResponse).status()).toBe(200);

  expect(reviewBodies).toEqual([
    {
      review_status: 'rejected_non_canonical_evidence',
      review_note: REVIEW_NOTE,
    },
  ]);

  await expect(metadata).toContainText('Rejeitado como evidência não canónica');
  await expect(metadata).toContainText('2026-07-10T09:30:00.000Z');
  await expect(metadata).toContainText('operator.review');
  await expect(metadata).toContainText(REVIEW_NOTE);
  await expect(metadata).toContainText(REVIEW_NOTICE);
  await expect(metadata).toContainText(LEGAL_NOTICE);
  await expect(
    page.locator('.badge').filter({ hasText: 'Evidência não canónica' }).first(),
  ).toBeVisible();
  await expect(page.locator('.badge').filter({ hasText: 'Não canónico' }).first()).toBeVisible();
  await expect(page.locator('body')).not.toContainText('OCR concluído');
  await expect(page.locator('body')).not.toContainText('Conversão concluída');
  await expect(page.locator('body')).not.toContainText('PDF/A canónico gerado');
});

async function routeImportedReviewFixtures(
  page: Page,
  reviewBodies: ImportedDocumentReviewBody[],
): Promise<void> {
  let currentDocument = importedDocumentFixture();

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
      await fulfillJson(route, signatureStatusFixture());
      return;
    }
    if (method === 'GET' && pathname === '/v1/signature/providers') {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'GET' && pathname === '/v1/documents/imported') {
      await fulfillJson(route, [currentDocument]);
      return;
    }
    if (method === 'GET' && pathname === `/v1/documents/imported/${IMPORT_ID}`) {
      await fulfillJson(route, currentDocument);
      return;
    }
    if (method === 'PATCH' && pathname === `/v1/documents/imported/${IMPORT_ID}/review`) {
      const body = request.postDataJSON() as ImportedDocumentReviewBody;
      reviewBodies.push(body);
      currentDocument = {
        ...currentDocument,
        operator_review_status: body.review_status,
        operator_reviewed_at: '2026-07-10T09:30:00.000Z',
        operator_reviewed_by: 'operator.review',
        operator_review_note: body.review_note ?? null,
      };
      await fulfillJson(route, currentDocument);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled imported review e2e route: ${method} ${pathname}` },
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
    username: 'operator.review',
    display_name: 'Operator Review',
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
      'act.archive',
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

function entityFixture(): Entity {
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

function bookFixture(): BookView {
  return {
    id: BOOK_ID,
    entity_id: ENTITY_ID,
    kind: 'AssembleiaGeral',
    state: 'Open',
    purpose: 'Livro import review E2E',
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

function actFixture(): ActView {
  return {
    id: ACT_ID,
    book_id: BOOK_ID,
    title: ACT_TITLE,
    channel: 'Physical',
    meeting_date: '2026-05-20',
    meeting_time: '10:30',
    place: 'Lisboa',
    mesa: { presidente: 'Amelia Review', secretarios: ['Rui Secretario'] },
    agenda: [{ number: 1, text: 'Aprovação de evidência importada' }],
    attendance_reference: 'Lista de presenças import review E2E',
    members_present: 3,
    members_represented: 0,
    referenced_documents: [],
    deliberations: 'Deliberação selada com documento importado para revisão operacional.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amelia Review', capacity: 'Chair' }],
    state: 'Sealed',
    ata_number: 3,
    payload_digest: 'ab'.repeat(32),
    seal_event_seq: 7,
    seal_metadata: null,
    retifies: null,
  };
}

function complianceFixture(): ComplianceReport {
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
      id: 'doc-import-review-e2e',
      template_id: 'csc-ata-ag/v1',
      pdf_digest: 'cd'.repeat(32),
      profile: 'application/pdf; profile=PDF/A-2u',
      created_at: '2026-05-20T10:45:00.000Z',
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

function signatureStatusFixture(): SignatureStatusView {
  return {
    status: 'unsigned',
    finalization: 'finalizado',
    require_qualified_for_seal: false,
    evidence: {
      current_level: 'unsigned',
      timestamp_evidence_present: false,
      dss_revocation_evidence_present: false,
      dss_revocation_evidence_status: 'not_present',
      long_term_status: ['not_configured'],
      status_scope: 'unsigned',
    },
  };
}

function importedDocumentFixture(): ImportedDocumentView {
  return {
    id: IMPORT_ID,
    act_id: ACT_ID,
    filename: 'legacy-minutes.doc',
    size_bytes: 4096,
    sha256: 'ef'.repeat(32),
    declared_content_type: 'application/msword',
    detected_content_type: 'application/msword',
    evidence_family: 'legacy_word_doc',
    classification: 'legacy_word_doc_non_canonical_evidence',
    imported_at: '2026-07-10T08:45:00.000Z',
    imported_by: 'operator.review',
    operator_review_status: 'operator_review_required',
    operator_reviewed_at: null,
    operator_reviewed_by: null,
    operator_review_note: null,
    operator_review_notice: REVIEW_NOTICE,
    non_canonical: true,
    requires_ocr_review: false,
    canonical_conversion_status: 'not_performed_non_canonical_original_only',
    canonical_conversion_performed: false,
    legal_acceptance_claimed: false,
    legal_notice: LEGAL_NOTICE,
    bytes_download: `/v1/documents/imported/${IMPORT_ID}/bytes`,
  };
}
