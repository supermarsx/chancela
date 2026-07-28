/**
 * Route-stubbed browser proof for the Settings > Privacidade DPIA surface (t15, rewritten by t55).
 * Three things are asserted end-to-end:
 *
 *   1. A DPIA record edits on its OWN PAGE, at its own address. t15 put this editor in a
 *      `role="dialog"` modal; t55 replaced that with `/settings/privacy/dpias/{id}`, because a
 *      modal that closes on Escape and on a backdrop click with no confirmation is the wrong
 *      container for a nine-field compliance record. The row's affordances are now links, the
 *      page opens seeded from the record the address names, a change saves through
 *      `PATCH /v1/privacy/dpias/{id}`, and the operator lands back on the list with the new value.
 *   2. That address is a real, cold deep link — a pasted URL resolves the record on its own,
 *      without first visiting the list. This is the feature, so it is proven in a real browser.
 *   3. The DPIA guidance template renders TRANSLATED. Its wire copy is English; the panel resolves
 *      each stable section/checklist/prompt/operator-action id to the pt-PT catalog key, so the
 *      reader sees Portuguese. The `field_type` wire identifier and the no_claims flags stay
 *      verbatim.
 */
import { expect, test, type Locator, type Page, type Route } from './fixtures';
import {
  DEFAULT_SETTINGS,
  type Dashboard,
  type DpiaRecordView,
  type DpiaTemplateView,
  type PatchDpiaRecordBody,
  type PermissionGrant,
  type SessionPermissions,
  type Settings,
  type UserView,
} from '../src/api/types';

const USER_ID = '9a1c7f04-4d2b-4a7e-b3c1-77d2c9a10f42';

type RouteState = {
  requests: string[];
  dpiaPatches: { id: string; body: PatchDpiaRecordBody }[];
  dpias: DpiaRecordView[];
};

test('Settings Privacidade edits a DPIA on its own page and shows the guidance template translated', async ({
  page,
}) => {
  const routes = await routePrivacyDpiaFixtures(page);
  const consoleErrors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => consoleErrors.push(String(error)));

  await page.goto('/settings/privacy');

  await expect(page).toHaveURL(/\/settings\/privacy/);
  await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();
  await expect(settingsSectionButton(page, 'Privacidade')).toHaveAttribute('aria-pressed', 'true');

  // --- 1. Edit a DPIA record on its own page --------------------------------------------------
  const dpiaPanel = panelByTitle(page, 'DPIAs');
  await expect(dpiaPanel).toBeVisible();

  // 🔒 The modal is gone for good. Nothing dialog-shaped, and no authoring form on the list.
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByLabel('Título da DPIA')).toHaveCount(0);

  const dpiaRow = dpiaPanel.locator('tbody tr').filter({ hasText: 'High-risk profiling' });
  await expect(dpiaRow).toHaveCount(1);

  // Two affordances on the row, one address: the primary cell and the explicit action.
  await expect(
    dpiaRow.getByRole('link', { name: 'High-risk profiling', exact: true }),
  ).toHaveAttribute('href', '/settings/privacy/dpias/dpia-1');
  await dpiaRow.getByRole('link', { name: 'Editar', exact: true }).click();

  // The editor is a page with an address, reachable by Back.
  await expect(page).toHaveURL(/\/settings\/privacy\/dpias\/dpia-1$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Editar AIPD' })).toBeVisible();

  // It opened seeded from the record the ADDRESS names — not from a blank create form.
  const titleInput = page.getByLabel('Título da DPIA');
  await expect(titleInput).toHaveValue('High-risk profiling');

  await titleInput.fill('High-risk profiling (revisto)');
  await page.getByRole('button', { name: 'Guardar alterações' }).click();

  // The change persisted through PATCH /v1/privacy/dpias/{id} with the edited title — and it is a
  // PATCH of the addressed record, never a POST that would leave the original untouched.
  await expect.poll(() => routes.dpiaPatches.length).toBe(1);
  expect(routes.dpiaPatches[0].id).toBe('dpia-1');
  expect(routes.dpiaPatches[0].body.title).toBe('High-risk profiling (revisto)');
  expect(routes.requests.filter((entry) => entry === 'POST /v1/privacy/dpias')).toEqual([]);

  // A successful save returns to the list — with no unsaved-changes prompt — and the row shows it.
  await expect(page).toHaveURL(/\/settings\/privacy$/);
  await expect(
    panelByTitle(page, 'DPIAs')
      .locator('tbody tr')
      .filter({ hasText: 'High-risk profiling (revisto)' }),
  ).toHaveCount(1);

  // --- 2. The address is a cold deep link -----------------------------------------------------
  await page.goto('/settings/privacy/dpias/dpia-1');
  await expect(page.getByRole('heading', { level: 1, name: 'Editar AIPD' })).toBeVisible();
  await expect(page.getByLabel('Título da DPIA')).toHaveValue('High-risk profiling (revisto)');
  // Both exits lead back to the list, and both are real links.
  await expect(page.getByRole('link', { name: 'Cancelar', exact: true })).toHaveCount(2);

  // A stale id says so by name instead of quietly offering a blank create form.
  await page.goto('/settings/privacy/dpias/dpia-desaparecida');
  await expect(
    page.getByText('Não foi encontrada nenhuma AIPD com este identificador.'),
  ).toBeVisible();
  await expect(page.getByLabel('Título da DPIA')).toHaveCount(0);

  // The create address is its own page, titled as a complete pt-PT sentence.
  await page.goto('/settings/privacy/dpias/new');
  await expect(page.getByRole('heading', { level: 1, name: 'Nova AIPD' })).toBeVisible();
  await expect(page.getByLabel('Título da DPIA')).toHaveValue('');

  await page.goto('/settings/privacy');

  // --- 3. Guidance template renders translated ------------------------------------------------
  await privacySubTab(page, 'Orientação').click();
  await expect(privacySubTab(page, 'Orientação')).toHaveAttribute('aria-pressed', 'true');

  const guidancePanel = panelByTitle(page, 'Modelo DPIA local');
  await expect(guidancePanel).toBeVisible();

  // pt-PT copy, resolved from the English wire ids — not the backend's English strings.
  await expect(guidancePanel.getByText('Perguntas de risco')).toBeVisible();
  await expect(guidancePanel).not.toContainText('Risk prompts');
  await expect(
    guidancePanel.getByText('Que impactos nos direitos e liberdades devem ser revistos?'),
  ).toBeVisible();
  await expect(guidancePanel.getByText(/Nota de revisão humana do risco/)).toBeVisible();
  await expect(
    guidancePanel.getByText(
      'Preencha os marcadores localmente com notas redigidas por pessoas, fora da resposta deste modelo.',
    ),
  ).toBeVisible();
  await expect(guidancePanel).not.toContainText(
    'Fill placeholders locally with human-written notes.',
  );

  // The `field_type` wire identifier stays verbatim (shown in mono, never translated).
  await expect(guidancePanel.getByText('review_note')).toBeVisible();

  // The no_claims flag identifiers stay verbatim behind their disclosure.
  await guidancePanel.getByText('Flags sem alegação').click();
  await expect(guidancePanel.getByText('cnpd_filing_completed')).toBeVisible();

  // Render verification, not just assertion: a missing i18n key or an unguarded read throws at
  // render time and shows up here even when every locator above still matched.
  expect(consoleErrors).toEqual([]);
});

function settingsSectionButton(page: Page, name: string): Locator {
  return page
    .getByRole('group', { name: 'Secções de configuração' })
    .getByRole('button', { name, exact: true });
}

function privacySubTab(page: Page, name: string): Locator {
  return page
    .getByRole('group', { name: 'Áreas de privacidade' })
    .getByRole('button', { name, exact: true });
}

function panelByTitle(page: Page, title: string): Locator {
  return page.locator('.panel').filter({ has: page.getByRole('heading', { name: title }) });
}

async function routePrivacyDpiaFixtures(page: Page): Promise<RouteState> {
  const state: RouteState = {
    requests: [],
    dpiaPatches: [],
    dpias: [dpiaRecordFixture()],
  };

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;
    state.requests.push(`${method} ${pathname}`);

    const dpiaPatch = pathname.match(/^\/v1\/privacy\/dpias\/([^/]+)$/);
    if (method === 'PATCH' && dpiaPatch) {
      const id = dpiaPatch[1];
      const body = JSON.parse(request.postData() ?? '{}') as PatchDpiaRecordBody;
      state.dpiaPatches.push({ id, body });
      state.dpias = state.dpias.map((record) =>
        record.id === id ? applyDpiaPatch(record, body) : record,
      );
      const updated = state.dpias.find((record) => record.id === id);
      await fulfillJson(route, updated ?? { error: `Unknown DPIA: ${id}` }, updated ? 200 : 404);
      return;
    }

    if (method !== 'GET') {
      await fulfillJson(
        route,
        { error: `Unexpected write in DPIA e2e: ${method} ${pathname}` },
        500,
      );
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
      await fulfillJson(route, sessionPermissionsFixture());
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
      await fulfillJson(route, { valid: true, length: 12 });
      return;
    }
    if (pathname === '/v1/privacy/processors') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/dpias') {
      await fulfillJson(route, state.dpias);
      return;
    }
    if (pathname === '/v1/privacy/dpia-template') {
      await fulfillJson(route, dpiaTemplateFixture());
      return;
    }
    if (pathname === '/v1/privacy/breach-playbooks') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/transfer-controls') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/retention-policies') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/retention-due-candidates') {
      await fulfillJson(route, {
        generated_at: '2026-07-12T10:00:00.000Z',
        scope: '',
        category: '',
        candidate_count: 0,
        suppressed_candidate_count: 0,
        suppressed_by_bounded_evidence_count: 0,
        suppression_summary: { suppressed_by_bounded_evidence_count: 0, note: '' },
        candidates: [],
      });
      return;
    }
    if (pathname === '/v1/privacy/retention-executions') {
      await fulfillJson(route, []);
      return;
    }

    await fulfillJson(route, { error: `Unhandled DPIA e2e route: ${method} ${pathname}` }, 500);
  });

  return state;
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function applyDpiaPatch(record: DpiaRecordView, body: PatchDpiaRecordBody): DpiaRecordView {
  return {
    ...record,
    title: body.title ?? record.title,
    purpose: body.purpose ?? record.purpose,
    legal_basis: body.legal_basis ?? record.legal_basis,
    data_categories: body.data_categories ?? record.data_categories,
    subprocessors: body.subprocessors ?? record.subprocessors,
    risk_level: body.risk_level ?? record.risk_level,
    status: body.status ?? record.status,
    updated_at: '2026-07-12T11:00:00.000Z',
    updated_by: 'dpia.e2e',
  };
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'dpia.e2e',
    display_name: 'DPIA E2E',
    created_at: '2026-07-12T09:00:00.000Z',
    active: true,
    has_secret: false,
    has_attestation_key: false,
    has_recovery_phrase: false,
    has_totp: false,
    two_factor_required: false,
    language: 'auto',
    role_assignments: [{ role_id: 'owner', scope: { kind: 'global' } }],
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
      'ledger.read',
      'privacy.manage',
      'settings.read',
      'settings.manage',
      'user.manage',
    ].map(permissionGrant),
  };
}

function sessionPermissionsFixture(): SessionPermissions {
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
    ...DEFAULT_SETTINGS,
    organization: {
      ...DEFAULT_SETTINGS.organization,
      name: 'Chancela DPIA E2E',
      default_actor: 'dpia-e2e',
    },
    documents: {
      ...DEFAULT_SETTINGS.documents,
      locale: 'pt-PT',
      numbering_scheme_default: 'Sequential',
    },
    onboarding: { completed: true, completed_at: '2026-07-12T09:00:00.000Z' },
  };
}

function dashboardFixture(): Dashboard {
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
    ledger_length: 12,
    ledger_valid: true,
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
    recent_events: [],
  };
}

function dpiaRecordFixture(): DpiaRecordView {
  return {
    id: 'dpia-1',
    title: 'High-risk profiling',
    purpose: 'Fraud triage',
    legal_basis: 'Legitimate interests',
    data_categories: ['Behaviour'],
    subprocessors: ['Signals Ltd'],
    risk_level: 'high',
    status: 'under_review',
    evidence_receipts: [],
    advisory_review: {
      status: 'overdue',
      last_reviewed_at: '2026-06-01T10:00:00.000Z',
      next_review_due_at: '2026-07-01',
      days_until_due: -4,
      review_interval_days: 365,
      receipt_count: 1,
      review_receipt_count: 1,
      drill_receipt_count: 0,
      local_advisory_only: true,
      authority_notification_claimed: false,
      subject_notification_claimed: false,
      transfer_approval_claimed: false,
      transfer_execution_claimed: false,
      external_delivery_configured: false,
      legal_completion_claimed: false,
      authority_filing_claimed: false,
      legal_acceptance_claimed: false,
      legal_certification_claimed: false,
      external_delivery_claimed: false,
      completion_claimed: false,
      compliance_certification_claimed: false,
    },
    created_at: '2026-07-01T09:00:00.000Z',
    created_by: 'owner',
    updated_at: '2026-07-02T09:00:00.000Z',
    updated_by: 'owner',
  };
}

/**
 * Guidance template with REAL backend section/checklist ids so the client resolves them to the
 * pt-PT catalog keys. The English strings here are the wire copy the panel deliberately overrides.
 */
function dpiaTemplateFixture(): DpiaTemplateView {
  return {
    schema: 'chancela-privacy-dpia-template/v1',
    template_id: 'privacy-dpia-guidance/v1',
    title: 'DPIA guidance',
    version: 1,
    language: 'en',
    scope: 'local_offline_guidance_only',
    local_offline_guidance_only: true,
    sections: [
      {
        id: 'risk_prompts',
        title: 'Risk prompts',
        description: 'Human review prompts only.',
        prompts: ['What rights and freedoms impacts should be reviewed?'],
        checklist: [
          {
            id: 'risk_review_note',
            label: 'Human risk review note',
            field_type: 'review_note',
            required: true,
          },
        ],
      },
    ],
    operator_actions: ['Fill placeholders locally with human-written notes.'],
    no_claims: {
      authority_filing_completed: false,
      authority_approval_obtained: false,
      cnpd_filing_completed: false,
      edpb_filing_completed: false,
      cnpd_or_edpb_approval_obtained: false,
      legal_review_accepted: false,
      legal_validation_completed: false,
      external_validation_completed: false,
      external_legal_validation_completed: false,
      external_delivery_completed: false,
      dpia_completed: false,
      dpia_completion_certified: false,
      compliance_certification_completed: false,
      transfer_approval_claimed: false,
      transfer_execution_claimed: false,
      authority_notification_claimed: false,
      subject_notification_claimed: false,
      automated_risk_scoring_performed: false,
      risk_score_authority_claimed: false,
      automated_legal_decision_made: false,
      register_mutation_performed: false,
      external_call_performed: false,
      raw_register_contents_included: false,
      processor_names_included: false,
      data_subjects_included: false,
      recipients_included: false,
      personal_data_included: false,
      secrets_included: false,
    },
  };
}
