/**
 * Route-stubbed browser proof for local-only privacy control review reminders.
 * The fixtures model advisory review state only; they do not contact providers,
 * notify authorities/data subjects, approve transfers, execute transfers, or
 * complete DPIAs/privacy compliance.
 */
import { expect, test, type Locator, type Page, type Route } from './fixtures';
import {
  DEFAULT_SETTINGS,
  type BreachPlaybookView,
  type Dashboard,
  type DpiaRecordView,
  type PermissionGrant,
  type PrivacyAdvisoryReviewStatus,
  type PrivacyAdvisoryReviewSummary,
  type RetentionDueCandidatesReport,
  type SessionPermissions,
  type Settings,
  type TransferControlView,
  type UserView,
} from '../src/api/types';

const USER_ID = 'd7e7ce4d-cc50-48bc-a0df-8705f7f42691';
const PRIVACY_SETTINGS_ROUTE = '/configuracoes?sec=privacidade';
const PRIVACY_DPIA_REVIEW_RULE = 'privacy-dpia-review';
const PRIVACY_BREACH_REVIEW_RULE = 'privacy-breach-playbook-review';
const PRIVACY_TRANSFER_REVIEW_RULE = 'privacy-transfer-control-review';

type RouteState = {
  requests: string[];
  settingsPuts: Settings[];
  privacyRecordMutations: string[];
  storedSettings: Settings;
};

test('privacy control review reminders stay local and follow the settings source toggle', async ({
  page,
}) => {
  const routes = await routePrivacyReviewReminderFixtures(page);

  await page.goto(PRIVACY_SETTINGS_ROUTE);

  await expect(page).toHaveURL(/[?&]sec=privacidade/);
  await expect(page.getByTestId('session-trigger')).toContainText('Privacy Review E2E');
  await expect(settingsSectionButton(page, 'Privacidade')).toHaveAttribute('aria-pressed', 'true');

  const dpiaPanel = panelByTitle(page, 'DPIAs');
  await expect(dpiaPanel).toContainText('Biometric access DPIA');
  await expect(dpiaPanel).toContainText('Revisão breve');
  await expect(dpiaPanel).toContainText('Próxima revisão local: 2026-07-20.');
  await expect(dpiaPanel).toContainText('Sem submissão à autoridade');
  await expect(dpiaPanel).toContainText('Sem certificação de conformidade');

  const breachPanel = panelByTitle(page, 'Playbooks de resposta a violações');
  await expect(breachPanel).toContainText('Supplier token breach playbook');
  await expect(breachPanel).toContainText('Revisão vencida');
  await expect(breachPanel).toContainText('Sem notificação à autoridade');
  await expect(breachPanel).toContainText('Sem notificação aos titulares');

  const transferPanel = panelByTitle(page, 'Controlos de transferência');
  await expect(transferPanel).toContainText('UK support access transfer review');
  await expect(transferPanel).toContainText('Em revisão local');
  await expect(transferPanel).toContainText('Estado local em revisão, sem conclusão legal.');
  await expect(transferPanel).toContainText('Sem aprovação');
  await expect(transferPanel).toContainText('Sem execução de transferência');

  await page.goto('/?painel=queue');
  const initialQueue = await dashboardQueue(page);
  await expect(initialQueue).toContainText('Biometric access DPIA');
  await expect(initialQueue).toContainText('Supplier token breach playbook');
  await expect(initialQueue).toContainText('UK support access transfer review');
  await expect(initialQueue).toContainText(
    `Fonte ${PRIVACY_DPIA_REVIEW_RULE} / privacy-dpia`,
  );
  await expect(initialQueue).toContainText(
    `Fonte ${PRIVACY_BREACH_REVIEW_RULE} / breach:breach-review-e2e`,
  );
  await expect(initialQueue).toContainText(
    `Fonte ${PRIVACY_TRANSFER_REVIEW_RULE} / transfer:transfer-review-e2e`,
  );
  await expect(initialQueue.getByRole('link', { name: 'Biometric access DPIA' })).toHaveAttribute(
    'href',
    PRIVACY_SETTINGS_ROUTE,
  );
  await expect(
    initialQueue.getByRole('link', { name: 'Supplier token breach playbook' }),
  ).toHaveAttribute('href', PRIVACY_SETTINGS_ROUTE);
  await expect(
    initialQueue.getByRole('link', { name: 'UK support access transfer review' }),
  ).toHaveAttribute('href', PRIVACY_SETTINGS_ROUTE);

  const privacyGetsBeforeToggle = privacyRecordGetCount(routes);

  await page.goto('/configuracoes?sec=gestao');
  const privacyReviewSource = page.getByRole('switch', { name: 'Revisões de privacidade' });
  await expect(privacyReviewSource).toBeChecked();
  await page.getByText('Revisões de privacidade', { exact: true }).click();
  await expect(privacyReviewSource).not.toBeChecked();

  await expect.poll(() => routes.settingsPuts.length).toBe(1);
  expect(routes.settingsPuts[0].workflow.reminders.sources.privacy_control_reviews).toBe(false);
  expect(routes.storedSettings.workflow.reminders.sources.privacy_control_reviews).toBe(false);

  await page.goto('/?painel=queue');
  await expect(page.getByText('Sem trabalho pendente derivado do painel.')).toBeVisible();
  await expect(page.getByText(PRIVACY_DPIA_REVIEW_RULE)).toHaveCount(0);
  await expect(page.getByText(PRIVACY_BREACH_REVIEW_RULE)).toHaveCount(0);
  await expect(page.getByText(PRIVACY_TRANSFER_REVIEW_RULE)).toHaveCount(0);

  expect(privacyRecordGetCount(routes)).toBe(privacyGetsBeforeToggle);
  expect(routes.privacyRecordMutations).toEqual([]);
});

function settingsSectionButton(page: Page, name: string): Locator {
  return page
    .getByRole('group', { name: 'Secções de configuração' })
    .getByRole('button', { name, exact: true });
}

function panelByTitle(page: Page, title: string): Locator {
  return page.locator('.panel').filter({ has: page.getByRole('heading', { name: title }) });
}

async function dashboardQueue(page: Page): Promise<Locator> {
  return page.getByRole('list', { name: 'Fila de trabalho do painel' });
}

function privacyRecordGetCount(routes: RouteState): number {
  return routes.requests.filter((entry) =>
    /^GET \/v1\/privacy\/(dpias|breach-playbooks|transfer-controls)$/.test(entry),
  ).length;
}

async function routePrivacyReviewReminderFixtures(page: Page): Promise<RouteState> {
  const state: RouteState = {
    requests: [],
    settingsPuts: [],
    privacyRecordMutations: [],
    storedSettings: settingsFixture(),
  };

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;
    state.requests.push(`${method} ${pathname}`);

    if (method === 'PUT' && pathname === '/v1/settings') {
      const body = JSON.parse(request.postData() ?? '{}') as Settings;
      state.settingsPuts.push(body);
      state.storedSettings = body;
      await fulfillJson(route, body);
      return;
    }

    if (isPrivacyRecordMutation(method, pathname)) {
      state.privacyRecordMutations.push(`${method} ${pathname}`);
      await fulfillJson(route, { error: `Unexpected privacy record write: ${method}` }, 500);
      return;
    }

    if (isMutationMethod(method)) {
      await fulfillJson(
        route,
        { error: `Unexpected write in privacy reminder e2e: ${method}` },
        500,
      );
      return;
    }

    if (method !== 'GET') {
      await fulfillJson(route, { error: `Unhandled privacy reminder e2e method: ${method}` }, 500);
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
      await fulfillJson(route, state.storedSettings);
      return;
    }
    if (pathname === '/v1/dashboard') {
      await fulfillJson(route, dashboardFixture(state.storedSettings));
      return;
    }
    if (pathname === '/v1/notifications/triage') {
      await fulfillJson(route, { entries: [], durable: true, max_entries_per_owner: 500 });
      return;
    }
    if (pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 24 });
      return;
    }
    if (pathname === '/v1/registry/lookup') {
      await fulfillJson(route, registryAutoUpdatePlanFixture(state.storedSettings));
      return;
    }
    if (pathname === '/v1/privacy/processors') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/dpias') {
      await fulfillJson(route, [dpiaFixture()]);
      return;
    }
    if (pathname === '/v1/privacy/breach-playbooks') {
      await fulfillJson(route, [breachPlaybookFixture()]);
      return;
    }
    if (pathname === '/v1/privacy/transfer-controls') {
      await fulfillJson(route, [transferControlFixture()]);
      return;
    }
    if (pathname === '/v1/privacy/retention-policies') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/retention-due-candidates') {
      await fulfillJson(route, emptyRetentionDueCandidatesReport());
      return;
    }
    if (pathname === '/v1/privacy/retention-executions') {
      await fulfillJson(route, []);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled privacy reminder e2e route: ${method} ${pathname}` },
      500,
    );
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

function isMutationMethod(method: string): boolean {
  return method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE';
}

function isPrivacyRecordMutation(method: string, pathname: string): boolean {
  return (
    isMutationMethod(method) &&
    /^\/v1\/privacy\/(dpias|breach-playbooks|transfer-controls)(?:\/|$)/.test(pathname)
  );
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'privacy.review.e2e',
    display_name: 'Privacy Review E2E',
    created_at: '2026-07-13T09:00:00.000Z',
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
    permissions: ['ledger.read', 'settings.read', 'settings.manage', 'user.manage'].map(
      permissionGrant,
    ),
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
      name: 'Chancela Privacy Review E2E',
      default_actor: 'privacy-review-e2e',
    },
    documents: {
      ...DEFAULT_SETTINGS.documents,
      locale: 'pt-PT',
      numbering_scheme_default: 'Sequential',
    },
    workflow: {
      ...DEFAULT_SETTINGS.workflow,
      reminders: {
        ...DEFAULT_SETTINGS.workflow.reminders,
        sources: {
          ...DEFAULT_SETTINGS.workflow.reminders.sources,
          privacy_control_reviews: true,
        },
      },
    },
    onboarding: { completed: true, completed_at: '2026-07-13T09:00:00.000Z' },
  };
}

function dashboardFixture(settings: Settings): Dashboard {
  const privacyReviewsEnabled =
    settings.workflow.reminders.enabled &&
    settings.workflow.reminders.sources.privacy_control_reviews;

  return {
    entities: 0,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    ledger_length: 24,
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
    reminders: privacyReviewsEnabled
      ? [
          {
            due_date: '2026-07-20',
            severity: 'Info',
            status: 'DueSoon',
            reason:
              'Local review reminder for DPIA evidence only; no authority filing, legal acceptance, external delivery, completion, or compliance certification is claimed.',
            entity_id: 'dpia-review-e2e',
            entity_name: 'Biometric access DPIA',
            source_rule: PRIVACY_DPIA_REVIEW_RULE,
            source_profile: 'privacy-dpia',
            action: {
              kind: 'open_settings_privacy',
              label_key: 'settings.privacy.title',
              api_href: '/v1/privacy/dpias',
              route: PRIVACY_SETTINGS_ROUTE,
            },
          },
          {
            due_date: '2026-07-10',
            severity: 'Warning',
            status: 'Overdue',
            reason:
              'Local review reminder for breach playbook evidence only; no authority or data-subject notification is claimed.',
            entity_id: 'breach-review-e2e',
            entity_name: 'Supplier token breach playbook',
            source_rule: PRIVACY_BREACH_REVIEW_RULE,
            source_profile: 'breach:breach-review-e2e',
            action: {
              kind: 'open_settings_privacy',
              label_key: 'settings.privacy.title',
              api_href: '/v1/privacy/breach-playbooks/breach-review-e2e',
              route: PRIVACY_SETTINGS_ROUTE,
            },
          },
          {
            due_date: '',
            severity: 'Advisory',
            status: 'Pending',
            reason:
              'Local review reminder for transfer-control evidence only; no transfer approval or execution is claimed.',
            entity_id: 'transfer-review-e2e',
            entity_name: 'UK support access transfer review',
            source_rule: PRIVACY_TRANSFER_REVIEW_RULE,
            source_profile: 'transfer:transfer-review-e2e',
            action: {
              kind: 'open_settings_privacy',
              label_key: 'settings.privacy.title',
              api_href: '/v1/privacy/transfer-controls/transfer-review-e2e',
              route: PRIVACY_SETTINGS_ROUTE,
            },
          },
        ]
      : [],
    recent_events: [],
  };
}

function advisoryReviewSummary(
  status: PrivacyAdvisoryReviewStatus,
  overrides: Partial<PrivacyAdvisoryReviewSummary> = {},
): PrivacyAdvisoryReviewSummary {
  return {
    status,
    last_reviewed_at: '2026-07-01T09:00:00Z',
    next_review_due_at: '2026-07-20',
    days_until_due: 7,
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
    ...overrides,
  };
}

function dpiaFixture(): DpiaRecordView {
  return {
    id: 'dpia-review-e2e',
    title: 'Biometric access DPIA',
    purpose: 'Local review of biometric access processing.',
    legal_basis: 'Local operator review basis.',
    data_categories: ['Identificação', 'Dados biométricos'],
    subprocessors: ['Access Processor SA'],
    risk_level: 'high',
    status: 'under_review',
    evidence_receipts: [
      {
        id: 'dpia-receipt-e2e',
        evidence_type: 'review',
        recorded_at: '2026-07-01T09:00:00Z',
        recorded_by: 'privacy.review.e2e',
        notes: 'Local DPIA review reminder fixture only.',
        authority_filing_completed: false,
        legal_review_accepted: false,
        legal_certification_completed: false,
        external_delivery_completed: false,
        dpia_completed: false,
        compliance_certification_completed: false,
      },
    ],
    advisory_review: {
      ...advisoryReviewSummary('due_soon'),
      authority_filing_claimed: false,
      legal_acceptance_claimed: false,
      legal_certification_claimed: false,
      external_delivery_claimed: false,
      completion_claimed: false,
      compliance_certification_claimed: false,
    },
    created_at: '2026-07-01T09:00:00Z',
    created_by: 'privacy.review.e2e',
    updated_at: '2026-07-01T09:00:00Z',
    updated_by: 'privacy.review.e2e',
  };
}

function breachPlaybookFixture(): BreachPlaybookView {
  return {
    id: 'breach-review-e2e',
    title: 'Supplier token breach playbook',
    scope: 'supplier-token-access',
    detection_channels: ['SIEM alert'],
    containment_steps: ['Disable supplier token'],
    notification_roles: ['DPO'],
    authority_notification_window: 'Assess separately when required.',
    subject_notification_guidance: 'Assess separately for high-risk cases.',
    risk_level: 'critical',
    status: 'active',
    review_notes: 'Local review is overdue.',
    evidence_receipts: [
      {
        id: 'breach-receipt-e2e',
        evidence_type: 'drill',
        recorded_at: '2026-05-01T10:00:00Z',
        recorded_by: 'privacy.review.e2e',
        notes: 'Local tabletop drill only.',
        authority_notified: false,
        subjects_notified: false,
      },
    ],
    advisory_review: advisoryReviewSummary('overdue', {
      last_reviewed_at: undefined,
      last_drill_at: '2026-05-01T10:00:00Z',
      next_review_due_at: '2026-07-10',
      days_until_due: -3,
      review_receipt_count: 0,
      drill_receipt_count: 1,
    }),
    created_at: '2026-05-01T10:00:00Z',
    created_by: 'privacy.review.e2e',
    updated_at: '2026-05-01T10:00:00Z',
    updated_by: 'privacy.review.e2e',
  };
}

function transferControlFixture(): TransferControlView {
  return {
    id: 'transfer-review-e2e',
    name: 'UK support access transfer review',
    purpose: 'Support ticket investigation.',
    legal_basis: 'Contract.',
    data_categories: ['Support metadata'],
    recipient: 'Support Processor Ltd',
    destination_country: 'United Kingdom',
    transfer_mechanism: 'SCC review placeholder',
    safeguards: ['Access review', 'Ticket minimisation'],
    risk_level: 'high',
    status: 'under_review',
    review_notes: 'Local review in progress.',
    evidence_receipts: [
      {
        id: 'transfer-receipt-e2e',
        recorded_at: '2026-07-12T11:00:00Z',
        recorded_by: 'privacy.review.e2e',
        reviewed_at: '2026-07-12T11:00:00Z',
        notes: 'Local transfer-control review only.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    ],
    advisory_review: advisoryReviewSummary('under_review', {
      next_review_due_at: undefined,
      days_until_due: undefined,
    }),
    created_at: '2026-07-12T11:00:00Z',
    created_by: 'privacy.review.e2e',
    updated_at: '2026-07-12T11:00:00Z',
    updated_by: 'privacy.review.e2e',
  };
}

function emptyRetentionDueCandidatesReport(): RetentionDueCandidatesReport {
  return {
    generated_at: '2026-07-13T09:00:00.000Z',
    scope: 'book_archive',
    category: 'documents',
    candidate_count: 0,
    suppressed_candidate_count: 0,
    suppressed_by_bounded_evidence_count: 0,
    candidates: [],
  };
}

function registryAutoUpdatePlanFixture(settings: Settings) {
  return {
    generated_at: '2026-07-13T09:00:00.000Z',
    dry_run_only: true,
    config: settings.registry_auto_update,
    due: [],
    skipped: {
      disabled: 0,
      fresh: 0,
      backoff: 0,
      running: 0,
      orphaned: 0,
      capped: 0,
    },
    notes: [],
  };
}
