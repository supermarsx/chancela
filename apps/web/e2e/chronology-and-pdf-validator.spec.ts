import { Buffer } from 'node:buffer';
import { expect, test, type Page, type Route } from './fixtures';

const ENTITY_ID = '9c8f6a8d-62e4-42ea-bf20-chronology01';
const USER_ID = '9c8f6a8d-62e4-42ea-bf20-user0000001';
const ENTITY_NAME = 'Cronologia Browser E2E, Lda.';
const PDF_BYTES = Buffer.from('%PDF-1.7\n%%EOF', 'utf8');
const VALIDATION_PATH = '/v1/signature/pdf/validate';

test('entity detail loads route-stubbed chronology rows, visualization paths, and copyable Mermaid source', async ({
  page,
}) => {
  await installClipboardStub(page);
  const state = await routeAppFixtures(page);

  await page.goto(`/entities/${ENTITY_ID}`);

  await expect(page.getByRole('heading', { name: ENTITY_NAME })).toBeVisible();
  await page.getByRole('button', { name: 'Cronologia e grafo' }).click();
  await expect(page).toHaveURL(new RegExp(`/entities/${ENTITY_ID}/chronology$`));
  await expect(page.getByText('Constituição por pacto social').first()).toBeVisible();
  await expect(page.getByText('Aumento de capital registado').first()).toBeVisible();
  await expect(page.getByText('Maria Silva, João Costa').first()).toBeVisible();
  await expect(page.getByText('Insc. 2').first()).toBeVisible();
  await expect(page.locator('.chronology-rail__item')).toHaveCount(2);
  await expectChronologyPath(page, 'Cronologia Browser E2E -> Maria Silva (Quota EUR 5000)');
  await expectChronologyPath(page, 'Cronologia Browser E2E -> João Costa (Quota EUR 2500)');
  await expectChronologyPath(page, 'Cronologia Browser E2E -> Certidão permanente');

  const shareholders = page.getByLabel('Código Mermaid: Sócios e quotas');
  await expect(shareholders).toHaveValue(/entity -->\|"Quota EUR 5000"\| s0/);
  await shareholders.locator('..').getByRole('button', { name: 'Copiar Mermaid' }).click();
  await expect(page.getByRole('button', { name: 'Copiado' })).toBeVisible();
  await expectCopiedText(page, 'entity -->|"Quota EUR 5000"| s0');

  expect(state.requests).toContain(`GET /v1/entities/${ENTITY_ID}/chronology`);
  expect(state.mutations).toEqual([]);
});

test('PDF validator shows technical JSON actions after a report body and downloads/copies it', async ({
  page,
}) => {
  await installClipboardStub(page);
  await installBrowserDownloadFallback(page);
  const state = await routeAppFixtures(page, { pdfValidation: 'valid' });

  await page.goto('/tools/pdf');
  await expect(page.getByRole('button', { name: 'Copiar JSON' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Guardar JSON' })).toHaveCount(0);

  await page.setInputFiles('#pdf-signature-validator-file', {
    name: 'signed.pdf',
    mimeType: 'application/pdf',
    buffer: PDF_BYTES,
  });

  await Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname === VALIDATION_PATH),
    page.getByRole('button', { name: /validar pdf/i }).click(),
  ]);

  await expect(page.getByText('Tecnicamente válido')).toBeVisible();
  await expect(page.getByText('pades_valid_local_technical')).toBeVisible();
  const report = page.locator('.pdf-validator-report');
  await expect(report.getByRole('button', { name: 'Copiar JSON' })).toBeVisible();
  await expect(report.getByRole('button', { name: 'Guardar JSON' })).toBeVisible();

  await report.getByRole('button', { name: 'Copiar JSON' }).click();
  const copied = await copiedText(page);
  expect(copied).toContain('"report_kind": "pdf_signature_validation"');
  expect(copied).toContain('technical PDF/PAdES evidence validation only');
  expect(JSON.parse(copied)).toMatchObject({
    report_kind: 'pdf_signature_validation',
    filename: 'signed.pdf',
    status: 'valid',
  });

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    report.getByRole('button', { name: 'Guardar JSON' }).click(),
  ]);
  expect(download.suggestedFilename()).toBe('signed-validation-report.json');
  await expect(download.failure()).resolves.toBeNull();

  expect(state.pdfValidationBodies).toHaveLength(1);
  expect(state.pdfValidationBodies[0]).toMatchObject({
    content_base64: 'JVBERi0xLjcKJSVFT0Y=',
    filename: 'signed.pdf',
    declared_size_bytes: PDF_BYTES.length,
  });
  expect(state.pdfValidationBodies[0]?.declared_sha256).toMatch(/^[a-f0-9]{64}$/);
});

test('PDF validator fail-closed refusals do not expose technical JSON actions', async ({
  page,
}) => {
  await installClipboardStub(page);
  const state = await routeAppFixtures(page, { pdfValidation: 'fail-closed' });

  await page.goto('/tools/pdf');
  await page.setInputFiles('#pdf-signature-validator-file', {
    name: 'mismatch.pdf',
    mimeType: 'application/pdf',
    buffer: PDF_BYTES,
  });

  await Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname === VALIDATION_PATH),
    page.getByRole('button', { name: /validar pdf/i }).click(),
  ]);

  await expect(page.getByText('Validação recusada')).toBeVisible();
  await expect(page.getByText(/recusa segura/i)).toBeVisible();
  await expect(page.getByText(/declared PDF SHA-256 digest does not match/i)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Copiar JSON' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Guardar JSON' })).toHaveCount(0);

  expect(state.pdfValidationBodies).toHaveLength(1);
  expect(state.pdfValidationBodies[0]).toMatchObject({
    filename: 'mismatch.pdf',
    declared_size_bytes: PDF_BYTES.length,
  });
});

type PdfValidationMode = 'valid' | 'fail-closed';

interface RouteState {
  requests: string[];
  mutations: string[];
  pdfValidationBodies: Record<string, unknown>[];
}

async function routeAppFixtures(
  page: Page,
  options: { pdfValidation?: PdfValidationMode } = {},
): Promise<RouteState> {
  const state: RouteState = { requests: [], mutations: [], pdfValidationBodies: [] };

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;
    state.requests.push(`${method} ${pathname}`);

    if (method === 'POST' && pathname === VALIDATION_PATH) {
      state.pdfValidationBodies.push(request.postDataJSON() as Record<string, unknown>);
      if (options.pdfValidation === 'fail-closed') {
        await fulfillJson(
          route,
          { error: 'declared PDF SHA-256 digest does not match the received bytes' },
          422,
        );
        return;
      }
      await fulfillJson(route, pdfValidationReportFixture());
      return;
    }

    if (isMutationMethod(method)) {
      state.mutations.push(`${method} ${pathname}`);
      await fulfillJson(route, { error: `Unexpected write in browser fixture: ${method}` }, 500);
      return;
    }

    if (method !== 'GET') {
      await fulfillJson(route, { error: `Unhandled method in browser fixture: ${method}` }, 500);
      return;
    }

    if (pathname === '/v1/session') {
      await fulfillJson(route, sessionFixture());
      return;
    }
    if (pathname === '/v1/session/roster') {
      await fulfillJson(route, { onboarding_required: false, users: [rosterUserFixture()] });
      return;
    }
    if (pathname === '/v1/session/permissions') {
      await fulfillJson(route, sessionFixture().permissions);
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
      await fulfillJson(route, { valid: true, length: 2 });
      return;
    }
    if (pathname === `/v1/entities/${ENTITY_ID}`) {
      await fulfillJson(route, entityFixture());
      return;
    }
    if (pathname === `/v1/entities/${ENTITY_ID}/chronology`) {
      await fulfillJson(route, chronologyFixture());
      return;
    }
    if (pathname === `/v1/entities/${ENTITY_ID}/registry`) {
      await fulfillJson(route, { error: 'not found' }, 404);
      return;
    }
    if (pathname === '/v1/books') {
      await fulfillJson(route, []);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled browser fixture route: ${method} ${pathname}` },
      500,
    );
  });

  return state;
}

async function installClipboardStub(page: Page): Promise<void> {
  await page.addInitScript(() => {
    Object.defineProperty(window.navigator, 'clipboard', {
      configurable: true,
      value: {
        async writeText(value: string) {
          (window as Window & { __chancelaCopiedText?: string }).__chancelaCopiedText =
            String(value);
        },
        async readText() {
          return (window as Window & { __chancelaCopiedText?: string }).__chancelaCopiedText ?? '';
        },
      },
    });
  });
}

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

async function copiedText(page: Page): Promise<string> {
  return page.evaluate(() =>
    String((window as Window & { __chancelaCopiedText?: string }).__chancelaCopiedText ?? ''),
  );
}

async function expectCopiedText(page: Page, expectedSubstring: string): Promise<void> {
  await expect.poll(() => copiedText(page)).toContain(expectedSubstring);
}

async function expectChronologyPath(page: Page, expectedPath: string): Promise<void> {
  await expect
    .poll(() =>
      page.locator('.chronology-paths li').evaluateAll((rows) =>
        rows.map(
          (row) =>
            row.textContent
              ?.replace(/\s*->\s*/g, ' -> ')
              .replace(/\s+/g, ' ')
              .trim() ?? '',
        ),
      ),
    )
    .toContain(expectedPath);
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function isMutationMethod(method: string): boolean {
  return method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE';
}

function userFixture() {
  return {
    id: USER_ID,
    username: 'chronology.pdf.e2e',
    display_name: 'Chronology PDF E2E',
    created_at: '2026-07-10T00:00:00.000Z',
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
      'entity.read',
      'entity.update',
      'book.create',
      'settings.manage',
      'trust.read',
      'signature.validate',
    ].map((permission) => ({
      permission,
      scope: { kind: 'global' },
      source: 'role',
    })),
  };
}

function settingsFixture() {
  return {
    schema_version: 1,
    organization: { name: 'Chancela E2E', default_actor: 'browser-e2e' },
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
    onboarding: { completed: true, completed_at: '2026-07-10T00:00:00.000Z' },
  };
}

function dashboardFixture() {
  return {
    entities: 1,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: 2,
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
    kind: 'SociedadePorQuotas',
    fiscal_year_end: null,
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

function chronologyFixture() {
  return {
    events: [
      {
        date: '2020-01-15',
        kind: 'Constitution',
        description: 'Constituição por pacto social',
        source_inscription: '1',
        actors: ['Maria Silva'],
      },
      {
        date: '2024-05-20',
        kind: 'CapitalIncrease',
        description: 'Aumento de capital registado',
        source_inscription: '2',
        actors: ['Maria Silva', 'João Costa'],
      },
    ],
    mermaid: {
      shareholders:
        'graph LR\n  entity["Cronologia Browser E2E"]\n  s0["Maria Silva"]\n  entity -->|"Quota EUR 5000"| s0\n  s1["João Costa"]\n  entity -->|"Quota EUR 2500"| s1',
      organs: 'timeline\n  2020 : Gerência nomeada\n  2024 : Reforço de capital',
      relationships:
        'graph LR\n  Entidade[Cronologia Browser E2E] --> Registo[Certidão permanente]',
    },
  };
}

function pdfValidationReportFixture() {
  return {
    report_kind: 'pdf_signature_validation',
    scope: 'local_technical_pdf_pades_evidence',
    legal_notice:
      'Local technical PDF/PAdES evidence validation only. No AMA integration, live trusted-list validation, live revocation validation, qualified-status decision, or legal-validity conclusion is performed or claimed.',
    status: 'valid',
    filename: 'signed.pdf',
    sha256: '1'.repeat(64),
    size_bytes: PDF_BYTES.length,
    declared_sha256: '1'.repeat(64),
    declared_size_bytes: PDF_BYTES.length,
    structure: {
      is_pdf: true,
      header_offset: 0,
      version: '1.7',
      has_eof_marker: true,
      has_startxref: true,
    },
    signature: {
      status: 'valid',
      validation_performed: true,
      validation_error: null,
      signed_pdf_signal: true,
      signature_marker_count: 1,
      byte_range_marker_count: 1,
      has_contents_marker: true,
      pades_profile: 'PAdES-B-T',
      byte_range: {
        byte_range: [0, 10, 20, 30],
        covered_len: 40,
        total_len: 42,
        signed_revision_len: 42,
        excluded_len: 2,
        covers_whole_file_except_contents: true,
        covers_signed_revision_except_contents: true,
        has_later_incremental_updates: false,
        digest_sha256: '2'.repeat(64),
      },
      cades: {
        status: 'valid',
        attrs_ok: true,
        signing_certificate_v2_present: true,
        signer_cert_sha256: '3'.repeat(64),
        signer_cert_subject: 'CN=Browser E2E Signer',
        signing_time: '2026-07-10T10:00:00Z',
      },
      timestamp: { signature_timestamp_present: true, status_scope: 'technical_evidence_only' },
      dss: {
        present: true,
        vri_count: 1,
        vri_tu_count: 1,
        vri_tu_keys: ['DSS-VRI-TU-1'],
        vri_has_tu: true,
        certificate_count: 2,
        ocsp_count: 1,
        crl_count: 0,
        revocation_evidence_present: true,
        certificate_sha256: ['4'.repeat(64)],
        ocsp_sha256: ['5'.repeat(64)],
        crl_sha256: [],
        status_scope: 'technical_evidence_only',
      },
      doc_timestamp: {
        present: true,
        count: 1,
        token_count: 1,
        token_sha256: ['6'.repeat(64)],
        all_imprints_valid: true,
        validations: [
          {
            index: 0,
            object_id: '12 0 R',
            byte_range: [0, 10, 20, 30],
            document_digest_sha256: '7'.repeat(64),
            token_imprint_sha256: '7'.repeat(64),
            token_hash_algorithm: 'sha256',
            status: 'valid',
            failure_reason: null,
          },
        ],
        status_scope: 'technical_evidence_only',
      },
      local_technical_renewal_plan: {
        status: 'available',
        scope: 'local_technical_evidence_only',
        notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
        signature_timestamp_present: true,
        dss_revocation_evidence_present: true,
        dss_validation_time_present: false,
        doc_timestamp_present: true,
        doc_timestamp_imprints_valid: true,
        missing_inputs: ['dss_validation_time'],
        next_action: 'record_dss_validation_time',
        has_local_evidence_gap: true,
        all_local_planning_inputs_present: false,
        production_long_term_profile_claimed: false,
        legal_ltv_claimed: false,
      },
      multi_signature_local_renewal_plan: {
        status: 'available',
        scope: 'local_technical_evidence_only',
        notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
        signature_count: 1,
        signatures: [
          {
            index: 0,
            object_id: '8 0 R',
            signed_revision_len: 42,
            vri_key_sha256: '8'.repeat(64),
            dss_vri_present: true,
            dss_vri_validation_time_present: false,
            local_technical_renewal_plan: {
              status: 'available',
              scope: 'local_technical_evidence_only',
              notice: 'Local embedded evidence planning only; not a B-LT/B-LTA or legal LTV claim.',
              signature_timestamp_present: true,
              dss_revocation_evidence_present: true,
              dss_validation_time_present: false,
              doc_timestamp_present: true,
              doc_timestamp_imprints_valid: true,
              missing_inputs: ['signature_dss_validation_time'],
              next_action: 'record_signature_dss_validation_time',
              has_local_evidence_gap: true,
              all_local_planning_inputs_present: false,
              production_long_term_profile_claimed: false,
              legal_ltv_claimed: false,
            },
          },
        ],
        signatures_with_local_evidence_gaps: [0],
        next_action: 'record_signature_dss_validation_time',
        has_local_evidence_gap: true,
        all_local_planning_inputs_present: false,
        production_long_term_profile_claimed: false,
        legal_ltv_claimed: false,
      },
    },
    trust: {
      status: 'not_performed',
      performed: false,
      live_trusted_list_validation_performed: false,
      ama_integration_performed: false,
      message: 'trust validation not performed',
    },
    revocation: {
      status: 'not_performed',
      live_fetch_performed: false,
      freshness_validation_performed: false,
      embedded_evidence_inspected: true,
      embedded_revocation_evidence_present: true,
      message: 'revocation freshness not performed',
    },
    qualification: {
      status: 'not_performed',
      qualified_status_claimed: false,
      legal_validity_claimed: false,
      legal_effect_assessed: false,
      message: 'qualification not assessed',
    },
    findings: [
      {
        severity: 'info',
        code: 'pades_valid_local_technical',
        message: 'PAdES/CAdES cryptographic validation succeeded locally',
      },
    ],
  };
}
