/**
 * Focused browser regression for imported-document operator review. The API is route-stubbed
 * so the test pins the review UI contract without depending on mutable server data.
 */
import { expect, test, type Download, type Page, type Route } from './fixtures';
import { readFile, stat } from 'node:fs/promises';
import { Buffer } from 'node:buffer';
import type {
  ActView,
  BookView,
  ComplianceReport,
  Dashboard,
  DashboardAlert,
  Entity,
  ImportedDocumentReviewBody,
  ImportedDocumentView,
  NotificationTriageEntry,
  NotificationTriageStatus,
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
const ACT_PDF_PATH = `/v1/acts/${ACT_ID}/document`;
const IMPORT_BYTES_PATH = `/v1/documents/imported/${IMPORT_ID}/bytes`;
const IMPORT_REVIEW_ALERT_CODE = 'document.import.review_required';
const IMPORT_REVIEW_ALERT_ID = `alert:${IMPORT_REVIEW_ALERT_CODE}:${ENTITY_ID}:${BOOK_ID}:${ACT_ID}:0`;
const PDF_FILENAME = 'imported-review-e2e-s-a-ata-3.pdf';
const PDF_BYTES = Buffer.from(
  '%PDF-1.7\n% Chancela imported-review notification e2e PDF\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n',
  'utf8',
);
const REVIEW_NOTICE =
  'Operator review records a preservation workflow decision only; it does not run OCR, convert bytes, replace the canonical PDF/A, or claim legal acceptance.';
const LEGAL_NOTICE =
  'Imported document preserved as non-canonical evidence only; it does not replace the generated PDF/A or signed PDF, and no legal validity, PDF/A conformance, or signature validity is claimed.';
const REVIEW_NOTE = 'Conferido como evidência preservada, sem conversão canónica.';
const NOTIFICATION_REVIEW_NOTE =
  'Revisto a partir da notificação; original mantido fora do PDF/A canónico.';
const INITIAL_HISTORY_NOTE = 'Triagem inicial mantida como evidência não canónica.';
const REVIEWED_AT = '2026-07-10T09:30:00.000Z';
const REVIEWED_BY = 'operator.review';
const IMPORTED_REVIEW_GUARDRAIL_IDS = [
  'preserved_original_bytes_remain_non_canonical_evidence',
  'canonical_pdfa_record_is_not_replaced',
  'signed_pdf_artifact_is_not_created_or_validated',
  'ocr_or_conversion_output_is_not_promoted_to_canonical_records',
];

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

  const summary = page.getByRole('group', { name: 'Resumo de profundidade da revisão importada' });
  const receipt = page.getByRole('group', { name: 'Recibo de revisão' });
  const history = page.getByRole('group', { name: 'Histórico técnico de revisão' });
  await expect(summary).toContainText('Histórico técnico: sem decisões');
  await expect(summary).toContainText('OCR, conversão, substituição de PDF/A');
  await expect(receipt).toContainText('Sem recibo de revisão');
  await expect(receipt).toContainText('Não efetuado por esta revisão.');
  await expect(receipt).toContainText('Não criado nem validado por esta revisão.');
  await expect(history).toContainText(
    'Sem histórico técnico registado para além dos metadados atuais da revisão.',
  );

  const form = page.getByRole('form', { name: 'Revisão operacional do documento importado' });
  await expect(form).toBeVisible();
  await expect(form.getByText('Revisão conservadora')).toBeVisible();
  await expect(form.getByText(REVIEW_NOTICE)).toBeVisible();

  const status = page.getByLabel('Estado de revisão');
  await expect(status).toBeVisible();
  await status.selectOption('rejected_non_canonical_evidence');
  await page.getByLabel('Nota da revisão').fill(REVIEW_NOTE);
  const save = form.getByRole('button', { name: 'Guardar revisão' });
  await expect(save).toBeDisabled();
  await form.getByLabel(/Confirmo que revi estes limites/).check();
  await expect(save).toBeEnabled();

  const reviewResponse = waitForApiResponse(
    page,
    `/v1/documents/imported/${IMPORT_ID}/review`,
    'PATCH',
  );
  await save.click();
  expect((await reviewResponse).status()).toBe(200);

  expect(reviewBodies).toEqual([
    {
      review_status: 'rejected_non_canonical_evidence',
      acknowledged_guardrail_ids: IMPORTED_REVIEW_GUARDRAIL_IDS,
      review_note: REVIEW_NOTE,
    },
  ]);

  await expect(metadata).toContainText('Rejeitado como evidência não canónica');
  await expect(metadata).toContainText('2026-07-10T09:30:00.000Z');
  await expect(metadata).toContainText('operator.review');
  await expect(metadata).toContainText(REVIEW_NOTE);
  await expect(metadata).toContainText(REVIEW_NOTICE);
  await expect(metadata).toContainText(LEGAL_NOTICE);
  await expect(receipt).toContainText('Rejeitado como evidência não canónica');
  await expect(receipt).toContainText(REVIEW_NOTE);
  await expect(receipt).toContainText('Limites reconhecidos');

  const decisions = history.locator('ol > li');
  await expect(decisions).toHaveCount(2);
  await expect(decisions.nth(0)).toContainText(INITIAL_HISTORY_NOTE);
  await expect(decisions.nth(0)).toContainText('2026-07-09T11:00:00.000Z');
  await expect(decisions.nth(1)).toContainText(REVIEW_NOTE);
  await expect(decisions.nth(1)).toContainText(REVIEWED_AT);
  await expect(decisions.nth(1)).toContainText(REVIEWED_BY);
  await expect(history).toContainText('Histórico de revisão metadata-only');
  await expect(history).toContainText('sem OCR, conversão, substituição de PDF/A');
  await expect(history).toContainText('certificação ou aceitação legal');
  await expect(
    page.locator('.badge').filter({ hasText: 'Evidência não canónica' }).first(),
  ).toBeVisible();
  await expect(page.locator('.badge').filter({ hasText: 'Não canónico' }).first()).toBeVisible();
  await expect(page.locator('body')).not.toContainText('OCR concluído');
  await expect(page.locator('body')).not.toContainText('Conversão concluída');
  await expect(page.locator('body')).not.toContainText('PDF/A canónico gerado');
});

test('dashboard import-review notification routes to review, can be dismissed, and keeps PDF export canonical', async ({
  page,
}) => {
  await installBrowserDownloadFallback(page);
  const reviewBodies: ImportedDocumentReviewBody[] = [];
  const triageUpdates: TriageUpdate[] = [];
  const downloadedPaths: string[] = [];
  await routeImportedReviewFixtures(page, reviewBodies, {
    dashboardAlerts: [importReviewDashboardAlert()],
    downloadedPaths,
    triageUpdates,
  });

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();

  await page.getByRole('button', { name: '1 notificações pendentes' }).click();
  const dialog = page.getByRole('dialog', { name: 'Notificações' });
  await expect(dialog.getByText(`Alerta do painel (${IMPORT_REVIEW_ALERT_CODE})`)).toBeVisible();
  await expect(
    dialog.getByText('legacy-minutes.doc precisa de revisão operacional.'),
  ).toBeVisible();

  await Promise.all([
    page.waitForURL(`**/atas/${ACT_ID}`),
    dialog.getByRole('link', { name: 'Abrir ata' }).click(),
  ]);

  await expect(dialog).toHaveCount(0);
  await expect(sealedActNotice(page)).toBeVisible();
  await expect(page.getByText('Documentos importados', { exact: true })).toBeVisible();

  const list = page.getByRole('list', { name: 'Documentos importados' });
  await list.getByRole('button', { name: 'Ver metadados' }).click();

  const form = page.getByRole('form', { name: 'Revisão operacional do documento importado' });
  await form.getByLabel('Estado de revisão').selectOption('reviewed_non_canonical_original_only');
  await form.getByLabel('Nota da revisão').fill(NOTIFICATION_REVIEW_NOTE);
  const save = form.getByRole('button', { name: 'Guardar revisão' });
  await expect(save).toBeDisabled();
  await form.getByLabel(/Confirmo que revi estes limites/).check();
  await expect(save).toBeEnabled();

  const reviewResponse = waitForApiResponse(
    page,
    `/v1/documents/imported/${IMPORT_ID}/review`,
    'PATCH',
  );
  await save.click();
  expect((await reviewResponse).status()).toBe(200);

  expect(reviewBodies).toEqual([
    {
      review_status: 'reviewed_non_canonical_original_only',
      acknowledged_guardrail_ids: IMPORTED_REVIEW_GUARDRAIL_IDS,
      review_note: NOTIFICATION_REVIEW_NOTE,
    },
  ]);
  const metadata = page.getByRole('group', { name: 'Metadados do documento importado' });
  await expect(metadata).toContainText(
    'Revisto: original preservado apenas como evidência não canónica',
  );
  await expect(metadata).toContainText(NOTIFICATION_REVIEW_NOTE);
  await expect(metadata).toContainText(LEGAL_NOTICE);

  await page.getByRole('button', { name: '1 notificações pendentes' }).click();
  const reopenedDialog = page.getByRole('dialog', { name: 'Notificações' });
  const triageResponse = waitForApiResponse(
    page,
    `/v1/notifications/triage/${encodeURIComponent(IMPORT_REVIEW_ALERT_ID)}`,
    'PATCH',
  );
  await reopenedDialog.getByRole('button', { name: 'Dispensar' }).click();
  expect((await triageResponse).status()).toBe(200);
  await expect(page.locator('.notification-bell')).toHaveAccessibleName('Notificações');
  expect(triageUpdates).toEqual([{ notificationId: IMPORT_REVIEW_ALERT_ID, status: 'dismissed' }]);
  await page.keyboard.press('Escape');
  await expect(reopenedDialog).toHaveCount(0);

  const [download, pdfResponse] = await Promise.all([
    page.waitForEvent('download'),
    waitForApiResponse(page, ACT_PDF_PATH, 'GET'),
    page.getByRole('button', { name: 'Descarregar PDF' }).click(),
  ]);

  expect(pdfResponse.status()).toBe(200);
  expect(await pdfResponse.headerValue('content-type')).toContain('application/pdf');
  await expectDownloadPayload(download, PDF_FILENAME, PDF_BYTES);
  expect(downloadedPaths).toEqual([ACT_PDF_PATH]);
  expect(downloadedPaths).not.toContain(IMPORT_BYTES_PATH);
});

type ImportedReviewRouteOptions = {
  dashboardAlerts?: DashboardAlert[];
  downloadedPaths?: string[];
  triageUpdates?: TriageUpdate[];
};

type TriageUpdate = {
  notificationId: string;
  status: NotificationTriageStatus;
};

async function installBrowserDownloadFallback(page: Page): Promise<void> {
  await page.addInitScript(() => {
    try {
      Object.defineProperty(window, 'showSaveFilePicker', {
        value: undefined,
        configurable: true,
      });
    } catch {
      (window as Window & { showSaveFilePicker?: unknown }).showSaveFilePicker = undefined;
    }
  });
}

async function routeImportedReviewFixtures(
  page: Page,
  reviewBodies: ImportedDocumentReviewBody[],
  options: ImportedReviewRouteOptions = {},
): Promise<void> {
  let currentDocument = importedDocumentFixture();
  const triageEntries: NotificationTriageEntry[] = [];

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
      await fulfillJson(route, dashboardFixture(options.dashboardAlerts ?? []));
      return;
    }
    if (method === 'GET' && pathname === '/v1/notifications/triage') {
      await fulfillJson(route, {
        entries: triageEntries,
        durable: true,
        max_entries_per_owner: 500,
      });
      return;
    }
    const triageNotificationId = pathname.match(/^\/v1\/notifications\/triage\/(.+)$/)?.[1];
    if (method === 'PATCH' && triageNotificationId) {
      const notificationId = decodeURIComponent(triageNotificationId);
      const status = (request.postDataJSON() as { status: NotificationTriageStatus }).status;
      options.triageUpdates?.push({ notificationId, status });
      const entry =
        status === 'unread'
          ? null
          : {
              notification_id: notificationId,
              status,
              updated_at: '2026-07-10T10:15:00.000Z',
            };
      triageEntries.splice(0, triageEntries.length, ...(entry ? [entry] : []));
      await fulfillJson(route, { status, entry, durable: true });
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
    if (method === 'GET' && pathname === ACT_PDF_PATH) {
      options.downloadedPaths?.push(pathname);
      await fulfillBytes(route, PDF_BYTES, 'application/pdf');
      return;
    }
    if (method === 'GET' && pathname === IMPORT_BYTES_PATH) {
      options.downloadedPaths?.push(pathname);
      await fulfillBytes(route, Buffer.from('original imported bytes', 'utf8'), 'application/msword');
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
      currentDocument = reviewedImportedDocumentFixture(currentDocument, body);
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

function sealedActNotice(page: Page) {
  return page.getByRole('note').filter({ hasText: 'Ata selada' }).first();
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

async function fulfillBytes(route: Route, body: Buffer, contentType: string): Promise<void> {
  await route.fulfill({
    status: 200,
    contentType,
    body,
  });
}

async function expectDownloadPayload(
  download: Download,
  filename: string,
  expectedBytes: Buffer,
): Promise<void> {
  expect(download.suggestedFilename()).toBe(filename);
  await expect(download.failure()).resolves.toBeNull();

  const file = await download.path();
  expect(file).toBeTruthy();
  const info = await stat(file!);
  expect(info.size).toBe(expectedBytes.length);

  const bytes = await readFile(file!);
  expect(bytes.equals(expectedBytes)).toBe(true);
  expect(bytes.subarray(0, 4).toString('utf8')).toBe('%PDF');
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

function dashboardFixture(alerts: DashboardAlert[] = []): Dashboard {
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
    current_work: {
      open_books: [
        {
          book_id: BOOK_ID,
          entity_id: ENTITY_ID,
          entity_name: ENTITY_NAME,
          kind: 'AssembleiaGeral',
          purpose: 'Livro import review E2E',
          opening_date: '2026-01-01',
          last_ata_number: 3,
          total_acts: 1,
          open_acts: 0,
          next_ata_number: 4,
          links: {
            entity: `/v1/entities/${ENTITY_ID}`,
            book: `/v1/books/${BOOK_ID}`,
            act: null,
            ledger: null,
          },
        },
      ],
      act_counts_by_state: {
        Draft: 0,
        Review: 0,
        Convened: 0,
        Deliberated: 0,
        TextApproved: 0,
        Signing: 0,
        Sealed: 1,
        Archived: 0,
      },
    },
    alerts,
    reminders: [],
    recent_events: [],
  };
}

function importReviewDashboardAlert(): DashboardAlert {
  return {
    code: IMPORT_REVIEW_ALERT_CODE,
    label: 'ReviewRequired',
    severity: 'Warning',
    category: 'ImportedDocumentReview',
    message: 'legacy-minutes.doc precisa de revisão operacional.',
    params: { filename: 'legacy-minutes.doc', act_title: ACT_TITLE },
    target: {
      entity_id: ENTITY_ID,
      book_id: BOOK_ID,
      act_id: ACT_ID,
      links: {
        entity: `/v1/entities/${ENTITY_ID}`,
        book: `/v1/books/${BOOK_ID}`,
        act: `/v1/acts/${ACT_ID}`,
        ledger: null,
      },
    },
    source: 'documents.imported.operator_review',
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
      download: ACT_PDF_PATH,
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

function importedDocumentCanonicalConversionPreflight(
  reviewState: string,
): ImportedDocumentView['canonical_conversion_preflight'] {
  return {
    report_kind: 'legacy_imported_document_canonical_conversion_preflight',
    scope: 'local_metadata_only',
    status: 'blocked',
    source_format: 'legacy_word_doc',
    review_state: reviewState,
    bounded_evidence_status: 'metadata_only_legacy_doc_preflight',
    evidence_basis: [
      'ole_cfb_magic_detected',
      'legacy_word_doc_metadata_or_extension_detected',
      'original_bytes_preserved',
    ],
    blockers: [
      'non_canonical_import_only',
      'operator_conversion_review_required',
      'no_canonical_conversion_workflow_executed',
    ],
    next_step: 'separate_operator_review_required_before_any_canonical_conversion_workflow',
    local_metadata_only: true,
    original_bytes_preserved: true,
    canonical_conversion_performed: false,
    canonical_pdfa_generated: false,
    signature_validation_performed: false,
    ocr_performed: false,
    legal_acceptance_claimed: false,
    external_provider_contacted: false,
    canonical_record_replaced: false,
  };
}

function importedDocumentPreservationPolicy(
  reviewState: string,
  requiresOperatorReview: boolean,
): ImportedDocumentView['preservation_policy'] {
  return {
    review_state: reviewState,
    requires_operator_review: requiresOperatorReview,
    requires_ocr_review: false,
    canonical_record_status: 'not_canonical_record',
    signed_artifact_status: 'not_signed_artifact',
    review_guardrail_checklist: IMPORTED_REVIEW_GUARDRAIL_IDS,
    canonical_conversion_status: 'not_performed_non_canonical_original_only',
    original_bytes_preservation_status: 'preserved_original_bytes',
    preservation_action: 'preserve_original_bytes_as_non_canonical_evidence_if_needed',
    canonical_conversion_performed: false,
    canonical_pdfa_generated: false,
    legal_acceptance_claimed: false,
  };
}

function importedDocumentReviewHistoryEntry(
  decisionIndex: number,
  reviewStatus: ImportedDocumentView['operator_review_status'],
  reviewedAt: string,
  reviewedBy: string,
  reviewNote: string | null,
  acknowledgedGuardrails: ImportedDocumentReviewBody['acknowledged_guardrail_ids'],
): ImportedDocumentView['review_history'][number] {
  return {
    decision_index: decisionIndex,
    review_status: reviewStatus,
    reviewed_at: reviewedAt,
    reviewed_by: reviewedBy,
    review_note: reviewNote,
    acknowledged_guardrail_ids: acknowledgedGuardrails,
    bytes_in_payload: false,
    ocr_performed: false,
    canonical_conversion_performed: false,
    canonical_pdfa_generated: false,
    signed_artifact_created_or_validated: false,
    legal_acceptance_claimed: false,
    certification_claimed: false,
  };
}

function reviewedImportedDocumentFixture(
  currentDocument: ImportedDocumentView,
  body: ImportedDocumentReviewBody,
): ImportedDocumentView {
  return {
    ...currentDocument,
    operator_review_status: body.review_status,
    operator_reviewed_at: REVIEWED_AT,
    operator_reviewed_by: REVIEWED_BY,
    operator_review_note: body.review_note ?? null,
    acknowledged_guardrail_ids: body.acknowledged_guardrail_ids,
    review_history: [
      importedDocumentReviewHistoryEntry(
        1,
        'reviewed_non_canonical_original_only',
        '2026-07-09T11:00:00.000Z',
        'ana.reviewer',
        INITIAL_HISTORY_NOTE,
        body.acknowledged_guardrail_ids,
      ),
      importedDocumentReviewHistoryEntry(
        2,
        body.review_status,
        REVIEWED_AT,
        REVIEWED_BY,
        body.review_note ?? null,
        body.acknowledged_guardrail_ids,
      ),
    ],
    canonical_conversion_preflight: importedDocumentCanonicalConversionPreflight(body.review_status),
    preservation_policy: importedDocumentPreservationPolicy(body.review_status, false),
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
    acknowledged_guardrail_ids: [],
    review_history: [],
    operator_review_notice: REVIEW_NOTICE,
    non_canonical: true,
    requires_ocr_review: false,
    canonical_record_status: 'not_canonical_record',
    signed_artifact_status: 'not_signed_artifact',
    review_guardrail_checklist: IMPORTED_REVIEW_GUARDRAIL_IDS,
    canonical_conversion_status: 'not_performed_non_canonical_original_only',
    canonical_conversion_performed: false,
    canonical_conversion_preflight: importedDocumentCanonicalConversionPreflight(
      'operator_review_required',
    ),
    legal_acceptance_claimed: false,
    preservation_policy: importedDocumentPreservationPolicy('operator_review_required', true),
    legal_notice: LEGAL_NOTICE,
    bytes_download: IMPORT_BYTES_PATH,
  };
}
