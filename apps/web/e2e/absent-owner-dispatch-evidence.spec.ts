/**
 * Focused browser proof for generated absent-owner communication dispatch evidence.
 * The API is route-stubbed so this pins the UI workflow without claiming provider
 * send, delivery confirmation, legal sufficiency, or legal notice completion.
 */
import { expect, test, type Download, type Page, type Route } from './fixtures';
import { readFile, stat } from 'node:fs/promises';
import { Buffer } from 'node:buffer';
import type {
  ActView,
  BookView,
  ComplianceReport,
  Dashboard,
  DashboardReminder,
  Entity,
  GeneratedDocumentDispatchEvidenceList,
  GeneratedDocumentDispatchEvidenceRecord,
  GeneratedDocumentDispatchEvidenceRequest,
  GeneratedDocumentDispatchEvidenceResponse,
  GeneratedDocumentView,
  ImportedDocumentView,
  NotificationTriageEntry,
  PermissionGrant,
  Settings,
  SignatureStatusView,
  UserView,
} from '../src/api/types';

const ACT_ID = '4a70ca71-1000-4000-8000-00000000a001';
const BOOK_ID = '4a70ca71-1000-4000-8000-00000000a002';
const ENTITY_ID = '4a70ca71-1000-4000-8000-00000000a003';
const USER_ID = '4a70ca71-1000-4000-8000-00000000a004';
const GENERATED_DOCUMENT_ID = 'generated-absent-browser-1';
const IMPORTED_DOCUMENT_ID = 'imported-dispatch-evidence-1';

const ENTITY_NAME = 'Condomínio Rua das Flores 10';
const ACT_TITLE = 'Ata da assembleia de condóminos';
const TEMPLATE_ID = 'condominio-comunicacao-ausentes/v1';
const GENERATED_DOCUMENT_PATH = `/v1/documents/generated/${GENERATED_DOCUMENT_ID}`;
const DISPATCH_EVIDENCE_PATH = `${GENERATED_DOCUMENT_PATH}/dispatch-evidence`;
const PDF_FILENAME =
  'condominio-rua-das-flores-10-ata-12-generated-condominio-comunicacao-ausentes-v1-generated-absent-browser-1.pdf';
const GENERATED_PDF_BYTES = Buffer.from(
  '%PDF-1.7\n% Chancela absent-owner dispatch evidence browser proof PDF\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n',
  'utf8',
);
const RECORDED_NOTE = 'Recibo postal arquivado localmente; evidência operacional apenas.';

test.use({ timezoneId: 'Europe/Lisbon' });

test('dashboard reminder opens generated absent-owner dispatch evidence and records metadata only', async ({
  page,
}) => {
  await installBrowserDownloadFallback(page);
  const recordedBodies: GeneratedDocumentDispatchEvidenceRequest[] = [];
  const downloadedPaths: string[] = [];

  await routeAbsentOwnerDispatchFixtures(page, {
    recordedBodies,
    downloadedPaths,
  });

  await page.goto('/dashboard/queue');

  const queue = page.getByRole('list', { name: 'Fila de trabalho do painel' });
  await expect(queue).toBeVisible();
  await expect(
    queue.getByRole('link', {
      name: `Evidência de expedição pendente: ${ACT_TITLE}`,
    }),
  ).toHaveAttribute(
    'href',
    `/acts/${ACT_ID}?generated_document_id=${GENERATED_DOCUMENT_ID}&focus=dispatch-evidence#generated-dispatch-evidence`,
  );
  await expect(queue).toContainText('Fonte Evidência de expedição a condómino ausente');
  await expect(queue).toContainText('O lembrete é apenas consultivo.');

  await Promise.all([
    page.waitForURL(`**/acts/${ACT_ID}?generated_document_id=${GENERATED_DOCUMENT_ID}**`),
    queue
      .getByRole('link', {
        name: `Evidência de expedição pendente: ${ACT_TITLE}`,
      })
      .click(),
  ]);

  const generatedSection = page.getByRole('region', {
    name: 'Comunicações geradas para ausentes',
  });
  await expect(generatedSection).toBeVisible();
  await expect(generatedSection).toContainText('Comunicações geradas');
  await expect(generatedSection).toContainText('Sem reivindicação de conclusão');

  const form = page.getByRole('form', {
    name: 'Registar evidência da comunicação gerada',
  });
  await expect(form).toBeFocused();
  await expect(form).toContainText('Registo de evidência pelo operador');
  await expect(form).toContainText(
    'Registe apenas metadados de evidência. A Chancela não enviou, não confirmou entrega e não completou aviso legal.',
  );

  const generatedList = page.getByRole('list', { name: 'Comunicações geradas' });
  await expect(generatedList).toContainText(TEMPLATE_ID);
  await expect(generatedList).toContainText(GENERATED_DOCUMENT_ID);
  await expect(generatedList).toContainText(GENERATED_DOCUMENT_PATH);
  await expect(generatedList).toContainText('operator_evidence_partial');

  const [download, pdfResponse] = await Promise.all([
    page.waitForEvent('download'),
    waitForApiResponse(page, GENERATED_DOCUMENT_PATH, 'GET'),
    generatedList.getByRole('button', { name: 'Descarregar comunicação' }).click(),
  ]);
  expect(pdfResponse.status()).toBe(200);
  await expectDownloadPayload(download, PDF_FILENAME, GENERATED_PDF_BYTES);
  expect(downloadedPaths).toEqual([GENERATED_DOCUMENT_PATH]);

  const status = page.getByRole('group', {
    name: 'Estado da evidência de comunicação gerada',
  });
  await expect(status).toContainText('operator_evidence_partial');
  await expect(status).toContainText('1/2 destinatários');
  await expect(status).toContainText('dispatch_completed');
  await expect(status).toContainText('false');
  await expect(status).toContainText('none');
  await expect(status).toContainText(
    'A Chancela não enviou, não confirmou entrega e não completou aviso legal; mostra apenas evidência registada pelo operador e cobertura de destinatários.',
  );

  const evidenceRows = page.getByRole('list', { name: 'Linhas de evidência registadas' });
  await expect(evidenceRows).toContainText('operator.dispatch');
  await expect(evidenceRows.locator('time[datetime="2026-07-11T10:05:00.000Z"]')).toBeVisible();
  await expect(evidenceRows).toContainText('Carta registada');
  await expect(evidenceRows).toContainText('RL-123');
  await expect(evidenceRows).toContainText('scan-page-4');
  await expect(evidenceRows).toContainText('Fração B');
  await expect(evidenceRows).toContainText('Envelope entregue no balcão postal.');
  await expect(evidenceRows.getByRole('button', { name: 'recibo-postal.pdf' })).toBeVisible();
  await expect(evidenceRows).toContainText(
    'Envio pela Chancela=false; confirmação de entrega=false; suficiência legal=false; reivindicação de conclusão=false; bytes no payload=false.',
  );

  await form.getByLabel('Data/hora registada').fill('2026-07-12T09:45');
  await form.getByLabel('Canal').selectOption('RegisteredLetterAR');
  await form.getByLabel('Referência', { exact: true }).fill('AR-789');
  await form.getByLabel('Referência da evidência').fill('scan-ar-789');
  await form.getByLabel('Documento importado').selectOption(IMPORTED_DOCUMENT_ID);
  await form.getByLabel('Fração C').uncheck();
  await form.getByLabel('Nota do operador').fill(RECORDED_NOTE);

  const recordResponse = waitForApiResponse(page, DISPATCH_EVIDENCE_PATH, 'POST');
  await form.getByRole('button', { name: 'Registar evidência' }).click();
  expect((await recordResponse).status()).toBe(201);

  expect(recordedBodies).toEqual([
    {
      actor: 'web-operator',
      dispatched_at: '2026-07-12T08:45:00.000Z',
      channel: 'RegisteredLetterAR',
      reference: 'AR-789',
      recipients: ['Fração B'],
      evidence_reference: 'scan-ar-789',
      imported_document_id: IMPORTED_DOCUMENT_ID,
      operator_note: RECORDED_NOTE,
    },
  ]);

  await expect(evidenceRows).toContainText('web-operator');
  await expect(evidenceRows.locator('time[datetime="2026-07-12T09:46:00.000Z"]')).toBeVisible();
  await expect(evidenceRows).toContainText('Carta registada com aviso de receção');
  await expect(evidenceRows).toContainText('AR-789');
  await expect(evidenceRows).toContainText('scan-ar-789');
  await expect(evidenceRows).toContainText(RECORDED_NOTE);
  await expect(page.locator('body')).not.toContainText('Aviso legal concluído');
  await expect(page.locator('body')).not.toContainText('Entrega confirmada');
  await expect(page.locator('body')).not.toContainText('Envio efetuado pela Chancela');
});

type AbsentOwnerRouteOptions = {
  recordedBodies: GeneratedDocumentDispatchEvidenceRequest[];
  downloadedPaths: string[];
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

async function routeAbsentOwnerDispatchFixtures(
  page: Page,
  options: AbsentOwnerRouteOptions,
): Promise<void> {
  const triageEntries: NotificationTriageEntry[] = [];
  const evidenceRows = [initialEvidenceRow()];
  let dispatchStatus = generatedCommunicationFixture().dispatch_evidence_status!;

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
      await fulfillJson(route, {
        entries: triageEntries,
        durable: true,
        max_entries_per_owner: 500,
      });
      return;
    }
    if (method === 'GET' && pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 11 });
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
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/documents/generated`) {
      await fulfillJson(route, [
        {
          ...generatedCommunicationFixture(),
          dispatch_evidence_status: dispatchStatus,
        },
      ]);
      return;
    }
    if (method === 'GET' && pathname === GENERATED_DOCUMENT_PATH) {
      options.downloadedPaths.push(pathname);
      await fulfillBytes(route, GENERATED_PDF_BYTES, 'application/pdf');
      return;
    }
    if (method === 'GET' && pathname === DISPATCH_EVIDENCE_PATH) {
      await fulfillJson(route, generatedDispatchEvidenceFixture(dispatchStatus, evidenceRows));
      return;
    }
    if (method === 'POST' && pathname === DISPATCH_EVIDENCE_PATH) {
      const body = request.postDataJSON() as GeneratedDocumentDispatchEvidenceRequest;
      options.recordedBodies.push(body);
      const row = recordedEvidenceRow(body);
      evidenceRows.push(row);
      dispatchStatus = {
        ...dispatchStatus,
        status: 'operator_evidence_partial',
        evidence_attached: true,
        recorded_recipients: ['Fração B'],
        missing_recipients: ['Fração C'],
      };
      const response: GeneratedDocumentDispatchEvidenceResponse = {
        evidence: row,
        dispatch_evidence_status: dispatchStatus,
      };
      await fulfillJson(route, response, 201);
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
      await fulfillJson(route, [importedDocumentFixture()]);
      return;
    }
    if (method === 'GET' && pathname === `/v1/documents/imported/${IMPORTED_DOCUMENT_ID}`) {
      await fulfillJson(route, importedDocumentFixture());
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled absent-owner dispatch e2e route: ${method} ${pathname}` },
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
    username: 'operator.dispatch',
    display_name: 'Operator Dispatch',
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

function dashboardFixture(): Dashboard {
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
    ledger_length: 11,
    ledger_valid: true,
    current_work: {
      open_books: [
        {
          book_id: BOOK_ID,
          entity_id: ENTITY_ID,
          entity_name: ENTITY_NAME,
          kind: 'Condominio',
          purpose: 'Livro de atas do condomínio',
          opening_date: '2026-01-01',
          last_ata_number: 12,
          total_acts: 1,
          open_acts: 0,
          next_ata_number: 13,
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
    alerts: [],
    reminders: [absentOwnerReminderFixture()],
    recent_events: [],
  };
}

function absentOwnerReminderFixture(): DashboardReminder {
  return {
    due_date: '',
    severity: 'Advisory',
    status: 'Pending',
    reason: 'Backend fallback must not be rendered when localized copy exists.',
    entity_id: ENTITY_ID,
    entity_name: ENTITY_NAME,
    source_rule: 'absent-owner-dispatch-evidence',
    source_profile: 'condominium-generated-communication',
    params: {
      act_id: ACT_ID,
      act_title: ACT_TITLE,
      book_id: BOOK_ID,
      document_id: GENERATED_DOCUMENT_ID,
      template_id: TEMPLATE_ID,
      dispatch_evidence_status: 'operator_evidence_partial',
      required_recipient_count: '2',
      recorded_recipient_count: '1',
      missing_recipient_count: '1',
      missing_recipients: 'Fração C',
    },
    action: {
      kind: 'open_absent_owner_dispatch_evidence',
      label_key: 'notifications.reminder.absentOwnerDispatch.action',
      api_href: DISPATCH_EVIDENCE_PATH,
      route: `/acts/${ACT_ID}`,
    },
    i18n: {
      title_key: 'notifications.reminder.absentOwnerDispatch.title',
      body_key: 'notifications.reminder.absentOwnerDispatch.body',
      action_key: 'notifications.reminder.absentOwnerDispatch.action',
    },
  };
}

function entityFixture(): Entity {
  return {
    id: ENTITY_ID,
    name: ENTITY_NAME,
    nipc: '503004642',
    nipc_validated: true,
    seat: 'Lisboa',
    family: 'Condominium',
    kind: 'Condominio',
    profile: {
      family: 'Condominium',
      rule_pack_id: 'condominio-pt/v1',
      allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
      signature_policy: 'Simple',
      template_family: 'condominium',
      calendar_presets: [],
    },
    statute: null,
  };
}

function bookFixture(): BookView {
  return {
    id: BOOK_ID,
    entity_id: ENTITY_ID,
    kind: 'Condominio',
    state: 'Open',
    purpose: 'Livro de atas do condomínio',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 12,
    predecessor: null,
    required_signatories_abertura: ['Administrador'],
    required_signatories_encerramento: null,
  };
}

function actFixture(): ActView {
  return {
    id: ACT_ID,
    book_id: BOOK_ID,
    title: ACT_TITLE,
    channel: 'Physical',
    meeting_date: '2026-06-30',
    meeting_time: '18:00',
    place: 'Lisboa',
    mesa: { presidente: 'Amélia Marques', secretarios: ['Rui Secretário'] },
    agenda: [{ number: 1, text: 'Aprovação de obras comuns' }],
    attendance_reference: 'Lista de presenças do condomínio',
    members_present: 8,
    members_represented: 2,
    referenced_documents: [],
    deliberations: 'Deliberação comunicada aos condóminos ausentes.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Amélia Marques', capacity: 'Chair' }],
    state: 'Sealed',
    ata_number: 12,
    payload_digest: 'ab'.repeat(32),
    seal_event_seq: 11,
    seal_metadata: null,
    retifies: null,
  };
}

function complianceFixture(): ComplianceReport {
  return {
    rule_pack: 'condominio-pt/v1',
    family: 'Condominium',
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
      id: 'doc-condominio-ata-12',
      template_id: 'condominio-ata/v1',
      pdf_digest: 'cd'.repeat(32),
      profile: 'application/pdf; profile=PDF/A-2u',
      created_at: '2026-06-30T19:00:00.000Z',
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

function generatedCommunicationFixture(): GeneratedDocumentView {
  return {
    id: GENERATED_DOCUMENT_ID,
    act_id: ACT_ID,
    template_id: TEMPLATE_ID,
    pdf_digest: 'ef'.repeat(32),
    profile: 'application/pdf; profile=PDF/A-2u',
    created_at: '2026-07-11T09:15:00.000Z',
    download: GENERATED_DOCUMENT_PATH,
    dispatch_evidence_status: {
      status: 'operator_evidence_partial',
      required: true,
      evidence_attached: true,
      dispatch_completed: false,
      completion_basis: 'none',
      required_recipients: ['Fração B', 'Fração C'],
      recorded_recipients: ['Fração B'],
      missing_recipients: ['Fração C'],
      note: 'operator-recorded evidence only',
    },
  };
}

function generatedDispatchEvidenceFixture(
  dispatchStatus: GeneratedDocumentView['dispatch_evidence_status'],
  evidenceRows: GeneratedDocumentDispatchEvidenceRecord[],
): GeneratedDocumentDispatchEvidenceList {
  return {
    document_id: GENERATED_DOCUMENT_ID,
    act_id: ACT_ID,
    template_id: TEMPLATE_ID,
    dispatch_evidence_status: dispatchStatus!,
    evidence: evidenceRows,
  };
}

function initialEvidenceRow(): GeneratedDocumentDispatchEvidenceRecord {
  return {
    document_id: GENERATED_DOCUMENT_ID,
    idempotency_key: 'initial-evidence-row',
    act_id: ACT_ID,
    template_id: TEMPLATE_ID,
    actor: 'operator.dispatch',
    dispatched_at: '2026-07-11T10:00:00.000Z',
    channel: 'RegisteredLetter',
    reference: 'RL-123',
    evidence_reference: 'scan-page-4',
    imported_document_id: IMPORTED_DOCUMENT_ID,
    recipients: ['Fração B'],
    operator_note: 'Envelope entregue no balcão postal.',
    recorded_at: '2026-07-11T10:05:00.000Z',
    sending_performed_by_chancela: false,
    delivery_confirmed: false,
    legal_sufficiency_claimed: false,
    legal_notice_completion_claimed: false,
    bytes_in_payload: false,
  };
}

function recordedEvidenceRow(
  body: GeneratedDocumentDispatchEvidenceRequest,
): GeneratedDocumentDispatchEvidenceRecord {
  return {
    document_id: GENERATED_DOCUMENT_ID,
    idempotency_key: 'recorded-evidence-row',
    act_id: ACT_ID,
    template_id: TEMPLATE_ID,
    actor: body.actor,
    dispatched_at: body.dispatched_at,
    channel: body.channel ?? null,
    reference: body.reference ?? null,
    evidence_reference: body.evidence_reference ?? null,
    imported_document_id: body.imported_document_id ?? null,
    recipients: body.recipients ?? [],
    operator_note: body.operator_note ?? null,
    recorded_at: '2026-07-12T09:46:00.000Z',
    sending_performed_by_chancela: false,
    delivery_confirmed: false,
    legal_sufficiency_claimed: false,
    legal_notice_completion_claimed: false,
    bytes_in_payload: false,
  };
}

function importedDocumentFixture(): ImportedDocumentView {
  return {
    id: IMPORTED_DOCUMENT_ID,
    act_id: ACT_ID,
    filename: 'recibo-postal.pdf',
    size_bytes: 4096,
    sha256: '12'.repeat(32),
    declared_content_type: 'application/pdf',
    detected_content_type: 'application/pdf',
    evidence_family: 'pdf',
    classification: 'imported_pdf_non_canonical_evidence',
    imported_at: '2026-07-11T10:03:00.000Z',
    imported_by: 'operator.dispatch',
    operator_review_status: 'reviewed_non_canonical_original_only',
    operator_reviewed_at: '2026-07-11T10:04:00.000Z',
    operator_reviewed_by: 'operator.dispatch',
    operator_review_note: 'Recibo usado como referência operacional.',
    operator_review_notice:
      'Operator review records a preservation workflow decision only; it does not run OCR, convert bytes, replace the canonical PDF/A, or claim legal acceptance.',
    non_canonical: true,
    requires_ocr_review: false,
    canonical_conversion_status: 'not_performed_non_canonical_original_only',
    canonical_conversion_performed: false,
    legal_acceptance_claimed: false,
    legal_notice:
      'Imported document preserved as non-canonical evidence only; it does not replace the generated PDF/A or signed PDF, and no legal validity, PDF/A conformance, or signature validity is claimed.',
    bytes_download: `/v1/documents/imported/${IMPORTED_DOCUMENT_ID}/bytes`,
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
