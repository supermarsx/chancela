/**
 * Focused browser hardening for generated export save behavior. These tests pin the
 * user-visible save/download path with mocked API bytes so they stay deterministic and
 * do not depend on a full domain journey.
 */
import { expect, test, type Download, type Page, type Route } from './fixtures';
import { readFile, stat } from 'node:fs/promises';
import { Buffer } from 'node:buffer';

const ENTITY_ID = '8d4420b3-7aa0-4ef6-8f43-3ad3f64a9c01';
const BOOK_ID = '8d4420b3-7aa0-4ef6-8f43-3ad3f64a9c02';
const ACT_ID = '8d4420b3-7aa0-4ef6-8f43-3ad3f64a9c03';
const USER_ID = '8d4420b3-7aa0-4ef6-8f43-3ad3f64a9c04';
const ENTITY_NAME = 'Export Save E2E, S.A.';
const ACT_TITLE = 'Ata export save E2E';
const ACT_PDF_PATH = `/v1/acts/${ACT_ID}/document`;
const BOOK_PACKAGE_PATH = `/v1/books/${BOOK_ID}/archive/package`;
const PDF_FILENAME = 'export-save-e2e-s-a-ata-7.pdf';
const ZIP_FILENAME = `chancela-preservation-book-${BOOK_ID}.zip`;
const PDF_BYTES = Buffer.from(
  '%PDF-1.7\n% Chancela explicit save e2e PDF\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n',
  'utf8',
);
const ZIP_BYTES = Buffer.concat([
  Buffer.from([0x50, 0x4b, 0x03, 0x04]),
  Buffer.from('Chancela explicit preservation package e2e\n', 'utf8'),
]);

test('sealed act PDF export starts a browser download with the expected file metadata', async ({
  page,
}) => {
  await installBrowserDownloadFallback(page);
  const mutations = await routeExportFixtures(page);

  await page.goto(`/atas/${ACT_ID}`);
  await expect(sealedActNotice(page)).toBeVisible();

  const downloadButton = page.getByRole('button', { name: 'Descarregar PDF' });
  await expect(downloadButton).toBeEnabled();

  const [download, response] = await Promise.all([
    page.waitForEvent('download'),
    waitForApiResponse(page, ACT_PDF_PATH),
    downloadButton.click(),
  ]);

  expect(response.request().method()).toBe('GET');
  expect(response.status()).toBe(200);
  expect(await response.headerValue('content-type')).toContain('application/pdf');
  await expectDownloadPayload(download, PDF_FILENAME, 'application/pdf', PDF_BYTES);
  await expect(
    page.getByText(`Transferência iniciada pelo navegador: ${PDF_FILENAME}.`, { exact: false }),
  ).toBeVisible();
  expect(mutations).toEqual([]);
});

test('book preservation package export starts a zip browser download', async ({ page }) => {
  await installBrowserDownloadFallback(page);
  const mutations = await routeExportFixtures(page);

  await page.goto(`/livros/${BOOK_ID}`);
  await expect(page.getByText('Livro export/save E2E')).toBeVisible();

  const downloadButton = page.getByRole('button', { name: 'Pacote de preservação Chancela' });
  await expect(downloadButton).toBeEnabled();

  const [download, response] = await Promise.all([
    page.waitForEvent('download'),
    waitForApiResponse(page, BOOK_PACKAGE_PATH),
    downloadButton.click(),
  ]);

  expect(response.request().method()).toBe('GET');
  expect(response.status()).toBe(200);
  expect(await response.headerValue('content-type')).toContain('application/zip');
  await expectDownloadPayload(download, ZIP_FILENAME, 'application/zip', ZIP_BYTES);
  await expect(
    page.getByText(`Transferência iniciada pelo navegador: ${ZIP_FILENAME}.`, { exact: false }),
  ).toBeVisible();
  expect(mutations).toEqual([]);
});

test('act PDF export failure stays visible and does not mutate act state', async ({ page }) => {
  await installBrowserDownloadFallback(page);
  const mutations = await routeExportFixtures(page, { failActPdf: true });

  await page.goto(`/atas/${ACT_ID}`);
  await expect(sealedActNotice(page)).toBeVisible();
  await expect(page.getByLabel('Data da reunião')).toBeDisabled();

  const downloadButton = page.getByRole('button', { name: 'Descarregar PDF' });
  await expect(downloadButton).toBeEnabled();

  const unexpectedDownload = page
    .waitForEvent('download', { timeout: 1_000 })
    .then((download) => download.suggestedFilename())
    .catch(() => null);

  const [response] = await Promise.all([
    waitForApiResponse(page, ACT_PDF_PATH),
    downloadButton.click(),
  ]);

  expect(response.request().method()).toBe('GET');
  expect(response.status()).toBe(503);
  await expect(
    page.getByRole('alert').filter({ hasText: 'Falha deliberada ao gerar PDF/A E2E.' }),
  ).toBeVisible();
  await expect(page.getByText(/^Transferência iniciada pelo navegador:/)).toHaveCount(0);
  expect(await unexpectedDownload).toBeNull();
  await expect(downloadButton).toBeEnabled();
  await expect(sealedActNotice(page)).toBeVisible();
  await expect(page.getByLabel('Data da reunião')).toBeDisabled();
  expect(mutations).toEqual([]);
});

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

async function routeExportFixtures(
  page: Page,
  options: { failActPdf?: boolean } = {},
): Promise<string[]> {
  const mutations: string[] = [];

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const url = new URL(request.url());
    const pathname = url.pathname;

    if (isMutationMethod(method)) {
      mutations.push(`${method} ${pathname}`);
      await fulfillJson(
        route,
        { error: `Unexpected write during export save e2e: ${method}` },
        500,
      );
      return;
    }

    if (method !== 'GET') {
      await route.continue();
      return;
    }

    if (pathname === '/v1/session') {
      await fulfillJson(route, sessionFixture());
      return;
    }
    if (pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: [rosterUserFixture()],
      });
      return;
    }
    if (pathname === '/v1/users') {
      await fulfillJson(route, [userFixture()]);
      return;
    }
    if (pathname === '/v1/settings') {
      await fulfillJson(route, settingsFixture());
      return;
    }
    if (pathname === '/v1/dashboard') {
      await fulfillJson(route, dashboardFixture());
      return;
    }
    if (pathname === '/v1/notifications/triage') {
      await fulfillJson(route, { entries: [], durable: true, max_entries_per_owner: 500 });
      return;
    }
    if (pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 4 });
      return;
    }
    if (pathname === `/v1/entities/${ENTITY_ID}`) {
      await fulfillJson(route, entityFixture());
      return;
    }
    if (pathname === `/v1/books/${BOOK_ID}`) {
      await fulfillJson(route, bookFixture());
      return;
    }
    if (pathname === `/v1/books/${BOOK_ID}/acts`) {
      await fulfillJson(route, [actFixture()]);
      return;
    }
    if (pathname === `/v1/books/${BOOK_ID}/legal-hold`) {
      await fulfillJson(route, {
        legal_hold: false,
        reason: null,
        actor: null,
        set_at: null,
      });
      return;
    }
    if (pathname === '/v1/books/paper-import') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === `/v1/acts/${ACT_ID}`) {
      await fulfillJson(route, actFixture());
      return;
    }
    if (pathname === `/v1/acts/${ACT_ID}/compliance`) {
      await fulfillJson(route, complianceFixture());
      return;
    }
    if (pathname === `/v1/acts/${ACT_ID}/document/bundle`) {
      await fulfillJson(route, documentBundleFixture());
      return;
    }
    if (pathname === `/v1/acts/${ACT_ID}/signature`) {
      await fulfillJson(route, signatureStatusFixture());
      return;
    }
    if (pathname === '/v1/signature/providers') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/documents/imported') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === ACT_PDF_PATH) {
      if (options.failActPdf) {
        await fulfillJson(route, { error: 'Falha deliberada ao gerar PDF/A E2E.' }, 503);
        return;
      }
      await fulfillBytes(route, PDF_BYTES, 'application/pdf');
      return;
    }
    if (pathname === BOOK_PACKAGE_PATH) {
      await fulfillBytes(route, ZIP_BYTES, 'application/zip');
      return;
    }

    await fulfillJson(route, { error: `Unhandled export save e2e route: ${pathname}` }, 500);
  });

  return mutations;
}

async function waitForApiResponse(page: Page, pathname: string) {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === pathname;
  });
}

function sealedActNotice(page: Page) {
  return page.getByRole('note').filter({ hasText: 'Ata selada' }).first();
}

async function expectDownloadPayload(
  download: Download,
  filename: string,
  contentType: string,
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
  if (contentType === 'application/pdf') {
    expect(bytes.subarray(0, 4).toString('utf8')).toBe('%PDF');
  }
  if (contentType === 'application/zip') {
    expect(bytes.subarray(0, 2).toString('utf8')).toBe('PK');
  }
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

function isMutationMethod(method: string): boolean {
  return method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE';
}

function userFixture() {
  return {
    id: USER_ID,
    username: 'export.e2e',
    display_name: 'Export E2E',
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
    permissions: ['book.export', 'settings.manage'].map((permission) => ({
      permission,
      scope: { kind: 'global' },
      source: 'role',
    })),
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
    ledger_length: 4,
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
    purpose: 'Livro export/save E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-02-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 7,
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
    seal_event_seq: 4,
    retifies: null,
    channel: 'Physical',
    meeting_date: '2026-03-15',
    meeting_time: '10:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presenças export save E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Export E2E', secretarios: ['Secretário E2E'] },
    agenda: [{ number: 1, text: 'Aprovação de exportação' }],
    referenced_documents: [],
    deliberations: 'Deliberação selada para endurecer o fluxo de descarregamento.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Export E2E', capacity: 'Chair' }],
    ata_number: 7,
    payload_digest: 'ab'.repeat(32),
    document_digest: 'cd'.repeat(32),
    signed_document_digest: null,
    created_at: '2026-03-15T10:00:00.000Z',
    updated_at: '2026-03-15T10:00:00.000Z',
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
      id: 'doc-export-save-e2e',
      template_id: 'ata-commercial-v1',
      pdf_digest: 'cd'.repeat(32),
      profile: 'PDF/A-3',
      created_at: '2026-03-15T10:00:00.000Z',
    },
    pdf: {
      media_type: 'application/pdf',
      byte_length: PDF_BYTES.length,
      download: ACT_PDF_PATH,
    },
    attachments_manifest: [],
    validation_report: null,
  };
}

function signatureStatusFixture() {
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
