/**
 * Adversarial browser coverage for network and hostile-content edges. These stay at the
 * browser layer because the failure modes are about real fetch responses, disabled controls,
 * DOM escaping, and binary download handling.
 */
import { expect, test, type Page, type Route } from './fixtures';
import { signInAt } from './auth';
import { routeShellPolling } from './shell-routes';

const ENTITY_ID = '2f1c8e40-0000-4000-8000-00000000e2e1';
const DEGRADED_ENTITY_ID = '2f1c8e40-0000-4000-8000-00000000d001';
const DEGRADED_BOOK_ID = '2f1c8e40-0000-4000-8000-00000000d002';
const DEGRADED_ACT_ID = '2f1c8e40-0000-4000-8000-00000000d003';
const ENTITY_PROFILE = {
  family: 'CommercialCompany',
  rule_pack_id: 'csc-art63/v2',
  allowed_channels: ['Physical', 'Hybrid', 'Telematic', 'WrittenResolution'],
  signature_policy: 'QualifiedPreferred',
  template_family: 'csc-commercial',
  calendar_presets: [
    {
      id: 'csc-art376-annual',
      label: 'Assembleia geral anual (CSC art. 376.º)',
      months_after_fiscal_year_end: 3,
    },
  ],
};

test('HTML returned from /v1/dashboard is surfaced as a typed inline error', async ({ page }) => {
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  // Install the stub BEFORE signing in. `NotificationBell` lives in the global shell and calls
  // `useDashboard()`, so the first page load already fetches /v1/dashboard; with `staleTime`
  // 30 s and no refetch on focus, a stub installed afterwards would never be reached and
  // clicking `Painel` would just re-render the real (empty, valid) response from cache.
  await page.route('**/v1/dashboard', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/html',
      body: '<!doctype html><title>stale shell</title><main>not json</main>',
    });
  });
  await signInAt(page, '/ferramentas?tool=legislacao');

  await tab(page, 'Painel').click();

  await expect(page.getByText('Resposta inesperada do servidor')).toBeVisible();
  await expect(page.getByText('HTML em vez de JSON')).toBeVisible();
  await expect(page.getByText('/v1/dashboard')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Ocorreu um erro' })).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

test('slow entity create keeps the submit button disabled while the POST is in flight', async ({
  page,
}) => {
  await signInAt(page, '/entidades/nova');

  let releasePost!: () => void;
  const postMayFinish = new Promise<void>((resolve) => {
    releasePost = resolve;
  });
  let postCount = 0;

  await page.route('**/v1/entities', async (route) => {
    if (route.request().method() !== 'POST') {
      await route.continue();
      return;
    }

    postCount += 1;
    await postMayFinish;
    await fulfillJson(route, entityFixture({ name: 'Entidade lenta E2E' }), 201);
  });

  await page.getByLabel('Denominação').fill('Entidade lenta E2E');
  await page.getByLabel('NIPC', { exact: true }).fill('503004642');
  await page.getByLabel('Sede').fill('Lisboa');
  await page.getByLabel('Forma jurídica').selectOption('SociedadeAnonima');

  const create = page.getByRole('button', { name: 'Criar entidade' });
  const click = create.click();

  await expect.poll(() => postCount).toBe(1);
  await expect(page.getByRole('button', { name: 'A criar…' })).toBeDisabled();
  expect(postCount).toBe(1);

  releasePost();
  await click;
});

test('malicious and long entity text is escaped on mobile without executing dialogs', async ({
  page,
}) => {
  const dialogs: string[] = [];
  const attack = `<script>alert("xss")</script><img src=x onerror="alert('xss')">`;
  const longTail = Array.from({ length: 18 }, (_, i) => `segmento-${i + 1}`).join(' ');
  const maliciousName = `${attack} ${longTail}`;

  page.on('dialog', async (dialog) => {
    dialogs.push(dialog.message());
    await dialog.dismiss();
  });

  await signInAt(page, '/configuracoes');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route('**/v1/entities', async (route) => {
    if (
      route.request().method() === 'GET' &&
      new URL(route.request().url()).pathname === '/v1/entities'
    ) {
      await fulfillJson(route, [entityFixture({ name: maliciousName, seat: longTail })]);
      return;
    }
    await route.continue();
  });

  await tab(page, 'Entidades').click();

  const row = page.getByRole('row').filter({ hasText: '<script>alert("xss")</script>' });
  await expect(row).toBeVisible();
  await expect(row).toContainText(attack);
  await expect(row.locator('script, img')).toHaveCount(0);

  const html = await row
    .locator('td')
    .first()
    .evaluate((node) => node.innerHTML);
  expect(html).toContain('&lt;script&gt;');
  expect(html).not.toContain('<script');

  await page.waitForTimeout(250);
  expect(dialogs).toEqual([]);

  const pageOverflow = await page.locator('.app-scroll').evaluate((node) => {
    return node.scrollWidth - node.clientWidth;
  });
  expect(pageOverflow).toBeLessThanOrEqual(2);
});

test('aborted archive PDF download shows an error and no fake success', async ({ page }) => {
  const downloads: string[] = [];
  page.on('download', (download) => downloads.push(download.suggestedFilename()));

  await signInAt(page, '/arquivo');
  await expect(page.getByRole('heading', { name: 'Arquivo — registo cronológico' })).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);

  await page.route('**/v1/ledger/archive/document**', async (route) => {
    await route.abort('failed');
  });

  await page.getByRole('button', { name: 'Exportar arquivo' }).click();

  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByText('PDF/A do arquivo descarregado.')).toHaveCount(0);
  await page.waitForTimeout(250);
  expect(downloads).toEqual([]);
});

test('degraded backend shows recovery affordance and blocks ordinary create/archive writes', async ({
  page,
}) => {
  const pageErrors: string[] = [];
  let createAttempts = 0;
  let archiveAttempts = 0;

  page.on('pageerror', (error) => pageErrors.push(error.message));

  await routeAuthenticatedShell(page, [
    'act.archive',
    'ledger.recover',
    'signing.perform',
    'settings.manage',
    'settings.read',
  ]);
  await routeSettings(page);
  await routeDegradedHealth(page);
  await routeBrokenIntegrity(page);
  await routeLedger(page);
  await routeDegradedDomainReads(page);

  await page.route('**/v1/entities', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (pathname !== '/v1/entities') {
      await route.continue();
      return;
    }

    if (request.method() === 'GET') {
      await fulfillJson(route, [entityFixture({ id: DEGRADED_ENTITY_ID })]);
      return;
    }

    if (request.method() === 'POST') {
      createAttempts += 1;
      await fulfillJson(route, degradedWriteError('entity.create'), 503);
      return;
    }

    await route.continue();
  });

  await page.route(`**/v1/acts/${DEGRADED_ACT_ID}/archive`, async (route) => {
    if (route.request().method() === 'POST') {
      archiveAttempts += 1;
      await fulfillJson(route, degradedWriteError('act.archive'), 503);
      return;
    }
    await route.continue();
  });

  await page.goto('/entidades/nova');

  await expect(
    page.getByRole('alert').filter({ hasText: 'Sistema em modo só-leitura' }),
  ).toBeVisible();
  await expect(page.getByText('A cadeia de integridade está quebrada.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Nova entidade' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Ocorreu um erro' })).toHaveCount(0);

  await page.getByLabel('Denominação').fill('Criação bloqueada E2E, S.A.');
  await page.getByLabel('NIPC', { exact: true }).fill('503004642');
  await page.getByLabel('Sede').fill('Lisboa');
  await page.getByLabel('Forma jurídica').selectOption('SociedadeAnonima');
  await page.getByRole('button', { name: 'Criar entidade' }).click();

  await expect.poll(() => createAttempts).toBe(1);
  await expect(page).toHaveURL(/\/entidades\/nova$/);
  await expect(page.getByRole('button', { name: 'Criar entidade' })).toBeEnabled();

  await page.goto(`/atas/${DEGRADED_ACT_ID}`);

  await expect(page.getByText('Ata selada', { exact: true })).toBeVisible();
  const archiveButton = page.getByRole('button', { name: 'Arquivar ata' });
  await expect(archiveButton).toBeVisible();
  await archiveButton.click();

  await expect.poll(() => archiveAttempts).toBe(1);
  await expect(
    page.getByRole('main').getByText('Modo só-leitura: act.archive bloqueado até recuperação.'),
  ).toBeVisible();
  await expect(page.getByText('Ata arquivada.', { exact: true })).toHaveCount(0);
  await expect(archiveButton).toBeEnabled();

  await page.getByRole('link', { name: 'Abrir Livros & Integridade' }).click();

  await expect(page).toHaveURL(/\/configuracoes\?sec=integridade$/);
  await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();
  await expect(page.getByText('Modo só-leitura ativo')).toBeVisible();
  await expect(page.getByText('hash mismatch at seq 3')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Restaurar de cópia de segurança' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Re-ancorar cadeia' })).toBeEnabled();
  await expect(page.getByRole('heading', { name: 'Ocorreu um erro' })).toHaveCount(0);
  expect(pageErrors).toEqual([]);
});

test('dashboard recent feed sorts newest first and caps at ten rows', async ({ page }) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeDashboard(page, dashboardFixture(dashboardEdgeEvents()));

  // The ledger feed is no longer the landing panel's neighbour: address it by section.
  await page.goto('/?painel=events');

  await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();
  const rows = panelByTitle(page, 'Últimos eventos do registo').locator('tbody tr');

  await expect(rows).toHaveCount(10);
  const rowTexts = await rows.evaluateAll((trs) => trs.map((tr) => tr.textContent ?? ''));

  expect(rowTexts[0]).toContain('edge.event.12');
  expect(rowTexts[1]).toContain('edge.event.11');
  expect(rowTexts[9]).toContain('edge.event.03');
  expect(rowTexts.join('\n')).not.toContain('edge.event.02');
  expect(rowTexts.join('\n')).not.toContain('edge.event.01');
});

test('dirty settings preview reverts and does not autosave after navigating away', async ({
  page,
}) => {
  let settingsPutCount = 0;

  await routeAuthenticatedShell(page, ['settings.manage']);
  await routeSettings(page, settingsFixture(), async (route, body) => {
    settingsPutCount += 1;
    await fulfillJson(route, body);
  });
  await routeDashboard(page, dashboardFixture());

  await page.goto('/configuracoes');
  await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();

  const html = page.locator('html');
  await expect(html).not.toHaveAttribute('data-theme', /.*/);

  const unexpectedSave = page
    .waitForRequest(
      (request) => request.method() === 'PUT' && new URL(request.url()).pathname === '/v1/settings',
      { timeout: 1_000 },
    )
    .then(() => 'put' as const)
    .catch(() => 'none' as const);

  await page.getByLabel('Tema').selectOption('dark');
  await expect(html).toHaveAttribute('data-theme', 'dark');

  await tab(page, 'Painel').click();
  await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();
  await expect(html).not.toHaveAttribute('data-theme', /.*/);

  expect(await unexpectedSave).toBe('none');
  expect(settingsPutCount).toBe(0);
});

test('settings without manage permission are disabled with an explicit denial note', async ({
  page,
}) => {
  await routeAuthenticatedShell(page, ['settings.read']);
  await routeSettings(page);

  await page.goto('/configuracoes?sec=identidade');

  await expect(page.getByText('Sem permissão', { exact: true })).toBeVisible();
  await expect(page.getByText('Não tem permissão para realizar esta operação.')).toBeVisible();
  await expect(page.getByLabel('Nome da organização')).toBeDisabled();

  await page.getByRole('button', { name: 'Aparência' }).click();
  await expect(page.getByLabel('Tema')).toBeDisabled();
});

test('trust catalog search renders a deterministic empty state', async ({ page }) => {
  await routeAuthenticatedShell(page);
  await routeSettings(page);
  await routeTrustCatalog(page);

  await page.goto('/ferramentas?tool=trust');

  const catalog = panelByTitle(page, 'Catálogo de confiança');
  await expect(catalog).toBeVisible();

  await page.getByLabel('Procurar na lista de confiança TSL').fill('semresultado-tsl');

  await expect(catalog.getByText('Sem resultados')).toBeVisible();
  await expect(
    catalog.getByText('Nenhum prestador ou serviço corresponde a “semresultado-tsl”.'),
  ).toBeVisible();
  await expect(catalog.getByText('Nenhum item selecionado')).toBeVisible();
  await expect(page).toHaveURL(/[?&]trustQ=semresultado-tsl/);
});

function tab(page: Page, name: string) {
  return page.getByTestId('tab-bar').getByRole('link', { name, exact: true });
}

function panelByTitle(page: Page, title: string) {
  return page.locator('.panel').filter({ has: page.getByRole('heading', { name: title }) });
}

async function routeAuthenticatedShell(
  page: Page,
  permissions = ['settings.manage'],
): Promise<void> {
  // First, so a spec's own stub for the same URL (registered later) still wins.
  await routeShellPolling(page);

  const user = userFixture();
  const session = {
    user,
    permissions: permissions.map((permission) => ({
      permission,
      scope: { kind: 'global' },
      source: 'role',
    })),
  };

  await page.route('**/v1/session**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, session);
      return;
    }
    if (request.method() === 'GET' && pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: [
          {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            has_secret: false,
          },
        ],
      });
      return;
    }

    await route.continue();
  });

  await page.route('**/v1/users', async (route) => {
    const request = route.request();
    if (request.method() === 'GET' && new URL(request.url()).pathname === '/v1/users') {
      await fulfillJson(route, [user]);
      return;
    }

    await route.continue();
  });

  await page.route('**/v1/ledger/verify', async (route) => {
    const request = route.request();
    if (request.method() === 'GET' && new URL(request.url()).pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 0 });
      return;
    }

    await route.continue();
  });
}

async function routeSettings(
  page: Page,
  settings = settingsFixture(),
  onPut?: (route: Route, body: unknown) => Promise<void>,
): Promise<void> {
  await page.route('**/v1/settings', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (pathname !== '/v1/settings') {
      await route.continue();
      return;
    }

    if (request.method() === 'GET') {
      await fulfillJson(route, settings);
      return;
    }
    if (request.method() === 'PUT') {
      const body = request.postDataJSON() as unknown;
      if (onPut) {
        await onPut(route, body);
      } else {
        await fulfillJson(route, body);
      }
      return;
    }

    await route.continue();
  });
}

async function routeDashboard(page: Page, dashboard: unknown): Promise<void> {
  await page.route('**/v1/dashboard', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, dashboard);
      return;
    }
    await route.continue();
  });
}

async function routeTrustCatalog(page: Page): Promise<void> {
  const summary = trustSummaryFixture();
  await page.route('**/v1/trust/**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }

    if (pathname === '/v1/trust/status') {
      await fulfillJson(route, summary);
      return;
    }
    if (pathname === '/v1/trust/catalog') {
      await fulfillJson(route, { summary, providers: [] });
      return;
    }
    if (pathname === '/v1/trust/tsa') {
      await fulfillJson(route, tsaCatalogFixture(summary.source));
      return;
    }

    await route.continue();
  });
}

async function routeDegradedHealth(page: Page): Promise<void> {
  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'broken', degraded: true });
  });
}

async function routeBrokenIntegrity(page: Page): Promise<void> {
  await page.route('**/v1/ledger/integrity', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, brokenIntegrityFixture());
      return;
    }
    await route.continue();
  });
}

async function routeLedger(page: Page): Promise<void> {
  await page.route('**/v1/ledger/events**', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, []);
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/ledger/verify', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, { valid: false, length: 5 });
      return;
    }
    await route.continue();
  });
}

async function routeDegradedDomainReads(page: Page): Promise<void> {
  const entity = entityFixture({ id: DEGRADED_ENTITY_ID, name: 'Degradada E2E, S.A.' });
  const book = bookFixture();
  const act = actFixture();

  await page.route('**/v1/books**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() !== 'GET') {
      await route.continue();
      return;
    }
    if (pathname === '/v1/books') {
      await fulfillJson(route, [book]);
      return;
    }
    if (pathname === `/v1/books/${DEGRADED_BOOK_ID}`) {
      await fulfillJson(route, book);
      return;
    }
    await route.continue();
  });

  await page.route(`**/v1/entities/${DEGRADED_ENTITY_ID}`, async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, entity);
      return;
    }
    await route.continue();
  });

  await page.route(`**/v1/acts/${DEGRADED_ACT_ID}`, async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, act);
      return;
    }
    await route.continue();
  });

  await page.route(`**/v1/acts/${DEGRADED_ACT_ID}/compliance`, async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, complianceFixture());
      return;
    }
    await route.continue();
  });

  await page.route(`**/v1/acts/${DEGRADED_ACT_ID}/document/bundle`, async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, documentBundleFixture());
      return;
    }
    await route.continue();
  });

  await page.route(`**/v1/acts/${DEGRADED_ACT_ID}/signature`, async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, signatureStatusFixture());
      return;
    }
    await route.continue();
  });

  await page.route(`**/v1/acts/${DEGRADED_ACT_ID}/signature/external-invites`, async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, []);
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/signature/providers', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, []);
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/documents/imported**', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, []);
      return;
    }
    await route.continue();
  });
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function entityFixture(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: ENTITY_ID,
    name: 'Encosto Estratégico, S.A.',
    nipc: '503004642',
    nipc_validated: true,
    seat: 'Lisboa',
    family: 'CommercialCompany',
    kind: 'SociedadeAnonima',
    profile: ENTITY_PROFILE,
    statute: null,
    ...overrides,
  };
}

function bookFixture() {
  return {
    id: DEGRADED_BOOK_ID,
    entity_id: DEGRADED_ENTITY_ID,
    kind: 'AssembleiaGeral',
    state: 'Open',
    purpose: 'Livro degradado E2E',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 1,
    predecessor: null,
    required_signatories_abertura: null,
    required_signatories_encerramento: null,
  };
}

function actFixture() {
  return {
    id: DEGRADED_ACT_ID,
    book_id: DEGRADED_BOOK_ID,
    title: 'Ata selada degradada E2E',
    state: 'Sealed',
    seal_event_seq: 4,
    retifies: null,
    channel: 'Physical',
    meeting_date: '2026-01-15',
    meeting_time: '10:00',
    place: 'Lisboa',
    attendance_reference: 'Lista de presenças E2E',
    members_present: 3,
    members_represented: 0,
    mesa: { presidente: 'Operador E2E', secretarios: ['Secretário E2E'] },
    agenda: [{ number: 1, text: 'Ponto único' }],
    referenced_documents: [],
    deliberations: 'Deliberação selada para testar arquivo em modo degradado.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Operador E2E', capacity: 'Chair' }],
    ata_number: 1,
    payload_digest: 'ab'.repeat(32),
    document_digest: 'cd'.repeat(32),
    signed_document_digest: null,
    created_at: '2026-01-15T10:00:00.000Z',
    updated_at: '2026-01-15T10:00:00.000Z',
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
    act_id: DEGRADED_ACT_ID,
    document: {
      id: 'doc-degraded-e2e',
      template_id: 'ata-commercial-v1',
      pdf_digest: 'cd'.repeat(32),
      profile: 'PDF/A-3',
      created_at: '2026-01-15T10:00:00.000Z',
    },
    pdf: {
      media_type: 'application/pdf',
      byte_length: 1024,
      download: `/v1/acts/${DEGRADED_ACT_ID}/document`,
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

function userFixture() {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    username: 'e2e.operator',
    display_name: 'Operador E2E',
    created_at: '2026-01-01T00:00:00.000Z',
    active: true,
    has_secret: false,
    has_attestation_key: false,
    has_recovery_phrase: false,
  };
}

function brokenIntegrityFixture() {
  return {
    healthy: false,
    degraded: true,
    global: {
      chain: 'global',
      genesis_kind: null,
      length: 5,
      head: 'aa'.repeat(32),
      verified: false,
      first_break: {
        chain: 'global',
        kind: 'HashMismatch',
        global_seq: 3,
        chain_seq: 3,
        event_id: 'bb'.repeat(16),
        expected_hash: 'cc'.repeat(32),
        actual_hash: 'dd'.repeat(32),
        message: 'hash mismatch at seq 3',
      },
    },
    chains: [],
    reanchored_segments: [],
  };
}

function degradedWriteError(operation: string) {
  return {
    error: `Modo só-leitura: ${operation} bloqueado até recuperação.`,
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

function dashboardFixture(recentEvents: unknown[] = []) {
  return {
    entities: 0,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: recentEvents.length,
    ledger_valid: true,
    // DashboardPage reads `current_work.act_counts_by_state` unguarded, so the fixture must
    // carry it — the shell only reaches the dashboard now that the poll stubs keep it signed in.
    current_work: {
      open_books: [],
      act_counts_by_state: {
        Draft: 0,
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
    recent_events: recentEvents,
  };
}

function dashboardEdgeEvents() {
  const seqs = [1, 7, 12, 3, 10, 5, 11, 9, 4, 8, 2, 6];
  return seqs.map((seq) => {
    const day = seq >= 11 ? 12 : seq;
    return ledgerEvent(
      seq,
      `edge.event.${String(seq).padStart(2, '0')}`,
      `2026-01-${String(day).padStart(2, '0')}T10:00:00.000Z`,
    );
  });
}

function ledgerEvent(seq: number, kind: string, timestamp: string) {
  const hex = String(seq).padStart(64, '0');
  return {
    id: `edge-event-${seq}`,
    seq,
    actor: 'api',
    justification: null,
    timestamp,
    scope: 'global',
    kind,
    payload_digest: hex,
    prev_hash: hex,
    hash: hex,
    chains: ['global'],
    attestation: null,
  };
}

function trustSummaryFixture() {
  return {
    source: { kind: 'Fixture', path: null, note: 'E2E trust fixture' },
    scheme_operator_name: 'Operador TSL E2E',
    scheme_name: 'Lista de confiança E2E',
    scheme_territory: 'PT',
    sequence_number: 1,
    issue_date_time: '2026-01-01T00:00:00.000Z',
    next_update: '2026-02-01T00:00:00.000Z',
    stale: false,
    validation: {
      checked_at: '2026-01-01T00:00:00.000Z',
      signature: 'Valid',
      error: null,
    },
    providers: 0,
    services: 0,
    ca_qc_services: 0,
    qualified_esignature_services: 0,
    trusted_esignature_services: 0,
  };
}

function tsaCatalogFixture(source: unknown) {
  return {
    summary: {
      configured_url: null,
      status: 'Unconfigured',
      status_message: 'TSA não configurada para o teste.',
      profile: {
        protocol: 'RFC3161',
        hash_algorithm: 'sha256',
        request_content_type: 'application/timestamp-query',
        response_content_type: 'application/timestamp-reply',
        nonce_policy: 'required',
        cert_req_default: true,
        accepted_policy: 'any',
      },
      accepted_hash: {
        algorithm: 'sha256',
        input: 'fixture',
        digest: '0'.repeat(64),
      },
      timestamp: null,
      last_probe: {
        kind: 'Fixture',
        status: 'Passed',
        checked_at: '2026-01-01T00:00:00.000Z',
        request_der_sha256: '1'.repeat(64),
        response_der_sha256: '2'.repeat(64),
        request_matches_fixture: true,
        error: null,
      },
      tsl: {
        source,
        signature: 'Valid',
        error: null,
      },
      records: 0,
      granted_records: 0,
      trusted_records: 0,
      policy_analysis: {
        accepted_policy: 'any',
        fixture_policy: null,
        fixture_policy_accepted: true,
        qualified_timestamp_records: 0,
        trusted_qualified_timestamp_records: 0,
        advisory: false,
      },
    },
    records: [],
  };
}
