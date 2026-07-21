/**
 * Route-stubbed browser proof for the Settings > Privacidade retention due-candidate
 * suppression surface. The fixtures model only the read-only privacy retention contract.
 */
import { expect, test, type Locator, type Page, type Route } from './fixtures';
import {
  DEFAULT_SETTINGS,
  type CloseRetentionExecutionReviewBody,
  type Dashboard,
  type PermissionGrant,
  type RetentionDueCandidate,
  type RetentionDueCandidatesReport,
  type RetentionExecutionOutcome,
  type RetentionExecutionRecord,
  type RetentionPolicyView,
  type SessionPermissions,
  type Settings,
  type UserView,
} from '../src/api/types';

const USER_ID = '4d5b3f26-25bc-4e45-a6d9-30d76328c101';
const SUPPRESSION_SUMMARY_NOTE =
  'Due candidates with prior safe bounded archive/no-action evidence are omitted from the active candidate list; execution history remains queryable for review.';

type RouteState = {
  requests: string[];
  dryRunPosts: string[];
  retentionLifecycleMutations: string[];
  reviewClosurePosts: {
    id: string;
    pathname: string;
    body: CloseRetentionExecutionReviewBody;
  }[];
  retentionExecutions: RetentionExecutionRecord[];
};

test('Settings Privacidade suppresses retention candidates already covered by bounded evidence', async ({
  page,
}) => {
  const routes = await routePrivacyRetentionFixtures(page);

  await page.goto('/settings/privacy');

  await expect(page).toHaveURL(/\/settings\/privacy/);
  await expect(page.getByTestId('session-trigger')).toContainText('Retention E2E');
  await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();
  await expect(settingsSectionButton(page, 'Privacidade')).toHaveAttribute('aria-pressed', 'true');

  // Privacidade opens on «Registos»; the retention surfaces live under the «Retenção» sub-tab.
  await privacySubTab(page, 'Retenção').click();
  await expect(privacySubTab(page, 'Retenção')).toHaveAttribute('aria-pressed', 'true');

  const candidatesPanel = panelByTitle(page, 'Candidatos de retenção vencidos');
  await expect(candidatesPanel).toBeVisible();
  await expect(candidatesPanel).toContainText('2 candidato(s) ativo(s)');
  await expect(candidatesPanel).toContainText('2 suprimido(s) por evidência delimitada');
  await expect(candidatesPanel).toContainText(
    'Candidatos suprimidos por evidência delimitada não são listados',
  );
  await expect(candidatesPanel).toContainText(SUPPRESSION_SUMMARY_NOTE);

  const activeRows = candidatesPanel.locator('tbody tr');
  await expect(activeRows).toHaveCount(2);
  await expect(activeRows.filter({ hasText: 'archive-doc-blocked' })).toHaveCount(1);
  await expect(activeRows.filter({ hasText: 'doc-456' })).toHaveCount(0);
  await expect(activeRows.filter({ hasText: 'doc-789' })).toHaveCount(0);
  await expect(
    candidatesPanel.getByRole('button', { name: 'Registar evidência de arquivo' }),
  ).toHaveCount(0);
  await expect(
    candidatesPanel.getByRole('button', { name: 'Registar evidência sem ação' }),
  ).toHaveCount(0);

  const executionQueue = panelByTitle(page, 'Fila de revisão de execução');
  await expect(executionQueue).toBeVisible();
  const doc456Execution = executionQueue.locator('tbody tr').filter({ hasText: 'doc-456' });
  const doc789Execution = executionQueue.locator('tbody tr').filter({ hasText: 'doc-789' });
  await expect(doc456Execution).toContainText('bounded_archive_recorded');
  await expect(doc456Execution).toContainText('Bounded archive evidence for doc-456');
  await expect(doc789Execution).toContainText('bounded_no_action_recorded');
  await expect(doc789Execution).toContainText('Bounded no-action evidence for doc-789');

  const dueCandidateGetsBeforeClosure = countRouteRequests(
    routes,
    'GET /v1/privacy/retention-due-candidates',
  );
  const executionHistoryGetsBeforeClosure = countRouteRequests(
    routes,
    'GET /v1/privacy/retention-executions',
  );

  await doc456Execution.getByRole('button', { name: 'Registar revisão operacional' }).click();

  await expect.poll(() => routes.reviewClosurePosts.length).toBe(1);
  expect(routes.reviewClosurePosts[0]).toEqual({
    id: 'retention-exec-doc-456',
    pathname: '/v1/privacy/retention-executions/retention-exec-doc-456/review-closure',
    body: {
      review_closure_decision: 'bounded_evidence_acknowledged',
      review_closure_note:
        'Revisão operacional registada para evidência delimitada; esta ação não altera registos fonte.',
      review_closure_evidence: [
        {
          label: 'fila_operacional',
          value: 'registo revisto na interface de configuracoes',
        },
        {
          label: 'alvo',
          value: 'doc-456',
        },
      ],
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      legal_hold_mutated: false,
      retention_policy_mutated: false,
    },
  });
  expectClosureBodyStaysNonLegal(routes.reviewClosurePosts[0].body);

  await expect
    .poll(() => countRouteRequests(routes, 'GET /v1/privacy/retention-executions'))
    .toBeGreaterThan(executionHistoryGetsBeforeClosure);
  await expect(doc456Execution).toContainText('Revisão operacional registada por retention.e2e');
  await expect(doc456Execution).toContainText(
    'Revisão operacional registada para evidência delimitada; esta ação não altera registos fonte.',
  );
  await expect(doc456Execution).toContainText(
    'fila_operacional: registo revisto na interface de configuracoes',
  );
  await expect(doc456Execution).toContainText('alvo: doc-456');
  await expect(
    doc456Execution.getByRole('button', { name: 'Registar revisão operacional' }),
  ).toHaveCount(0);
  await expect(doc789Execution).not.toContainText('Revisão operacional registada por retention.e2e');
  await expect(
    doc789Execution.getByRole('button', { name: 'Registar revisão operacional' }),
  ).toBeVisible();

  await expect(candidatesPanel).toContainText('2 candidato(s) ativo(s)');
  await expect(candidatesPanel).toContainText('2 suprimido(s) por evidência delimitada');
  expect(countRouteRequests(routes, 'GET /v1/privacy/retention-due-candidates')).toBe(
    dueCandidateGetsBeforeClosure,
  );

  expect(routes.dryRunPosts).toEqual([]);
  expect(routes.retentionLifecycleMutations).toEqual([]);
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

function countRouteRequests(routes: RouteState, request: string): number {
  return routes.requests.filter((entry) => entry === request).length;
}

async function routePrivacyRetentionFixtures(page: Page): Promise<RouteState> {
  const state: RouteState = {
    requests: [],
    dryRunPosts: [],
    retentionLifecycleMutations: [],
    reviewClosurePosts: [],
    retentionExecutions: retentionExecutionsFixture(),
  };

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const pathname = new URL(request.url()).pathname;
    state.requests.push(`${method} ${pathname}`);

    if (method === 'POST' && pathname === '/v1/privacy/retention-policies/dry-run') {
      state.dryRunPosts.push(`${method} ${pathname}`);
    }
    if (isMutationMethod(method) && isRetentionLifecycleMutationPath(pathname)) {
      state.retentionLifecycleMutations.push(`${method} ${pathname}`);
    }
    if (method === 'POST' && isReviewClosurePath(pathname)) {
      const body = JSON.parse(request.postData() ?? '{}') as CloseRetentionExecutionReviewBody;
      const id = pathname.match(REVIEW_CLOSURE_PATH_PATTERN)?.[1] ?? '';
      const recordIndex = state.retentionExecutions.findIndex((record) => record.id === id);
      state.reviewClosurePosts.push({ id, pathname, body });
      if (recordIndex === -1) {
        await fulfillJson(route, { error: `Unknown retention execution: ${id}` }, 404);
        return;
      }
      const updated = closeRetentionExecutionReviewFixture(
        state.retentionExecutions[recordIndex],
        body,
      );
      state.retentionExecutions = state.retentionExecutions.map((record, index) =>
        index === recordIndex ? updated : record,
      );
      await fulfillJson(route, updated);
      return;
    }
    if (isMutationMethod(method)) {
      await fulfillJson(route, { error: `Unexpected write in retention e2e: ${method}` }, 500);
      return;
    }

    if (method !== 'GET') {
      await fulfillJson(route, { error: `Unhandled retention e2e method: ${method}` }, 500);
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
      await fulfillJson(route, { valid: true, length: 18 });
      return;
    }
    if (pathname === '/v1/privacy/processors') {
      await fulfillJson(route, []);
      return;
    }
    if (pathname === '/v1/privacy/dpias') {
      await fulfillJson(route, []);
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
      await fulfillJson(route, retentionPoliciesFixture());
      return;
    }
    if (pathname === '/v1/privacy/retention-due-candidates') {
      await fulfillJson(route, retentionDueCandidatesReportFixture());
      return;
    }
    if (pathname === '/v1/privacy/retention-executions') {
      await fulfillJson(route, state.retentionExecutions);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled retention suppression e2e route: ${method} ${pathname}` },
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

const REVIEW_CLOSURE_PATH_PATTERN =
  /^\/v1\/privacy\/retention-executions\/([^/]+)\/review-closure$/;

function isReviewClosurePath(pathname: string): boolean {
  return REVIEW_CLOSURE_PATH_PATTERN.test(pathname);
}

function isRetentionLifecycleMutationPath(pathname: string): boolean {
  if (isReviewClosurePath(pathname)) return false;
  return (
    pathname.includes('/retention-executions') ||
    pathname.includes('/retention-policies') ||
    pathname.includes('/deletion') ||
    pathname.includes('/delete') ||
    pathname.includes('/disposal') ||
    pathname.includes('/erasure') ||
    pathname.includes('/legal-hold')
  );
}

function expectClosureBodyStaysNonLegal(body: CloseRetentionExecutionReviewBody): void {
  const closureText = [
    body.review_closure_note ?? '',
    ...(body.review_closure_evidence ?? []).flatMap((evidence) => [
      evidence.label,
      evidence.value,
    ]),
  ]
    .join(' ')
    .toLowerCase();

  expect(closureText).not.toMatch(
    /legal|jur[ií]dic|aprova[cç][aã]o|elimina[cç][aã]o|apag|destrui|erasure|delete|disposal|legal-hold/,
  );
  expect(body.destructive_disposal_completed).toBe(false);
  expect(body.full_erasure_completed).toBe(false);
  expect(body.legal_hold_mutated).toBe(false);
  expect(body.retention_policy_mutated).toBe(false);
}

function permissionGrant(permission: string): PermissionGrant {
  return { permission, scope: { kind: 'global' }, source: 'role' };
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'retention.e2e',
    display_name: 'Retention E2E',
    created_at: '2026-07-12T09:00:00.000Z',
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
      name: 'Chancela Retention E2E',
      default_actor: 'retention-e2e',
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
    ledger_length: 18,
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

function retentionPoliciesFixture(): RetentionPolicyView[] {
  return [
    retentionPolicyFixture({
      id: 'retention-review',
      name: 'Revisão documental',
      disposal_action: 'review',
    }),
    retentionPolicyFixture({
      id: 'retention-archive',
      name: 'Arquivo delimitado',
      disposal_action: 'archive',
    }),
    retentionPolicyFixture({
      id: 'retention-no-action',
      name: 'Conservação sem ação',
      disposal_action: 'no_action',
    }),
  ];
}

function retentionPolicyFixture(overrides: Partial<RetentionPolicyView> = {}): RetentionPolicyView {
  return {
    id: 'retention-review',
    name: 'Revisão documental',
    scope: 'book_archive',
    category: 'documents',
    schedule_id: 'book-archive-documents-v1',
    retention_period: 'P2Y',
    legal_basis: 'Arquivo contabilístico e societário delimitado.',
    disposal_action: 'review',
    status: 'active',
    active: true,
    notes: 'Read-only browser proof fixture.',
    created_at: '2026-07-12T09:00:00.000Z',
    created_by: 'retention.e2e',
    updated_at: '2026-07-12T09:00:00.000Z',
    updated_by: 'retention.e2e',
    ...overrides,
  };
}

function retentionDueCandidatesReportFixture(): RetentionDueCandidatesReport {
  return {
    generated_at: '2026-07-12T10:00:00.000Z',
    scope: 'book_archive',
    category: 'documents',
    candidate_count: 2,
    suppressed_candidate_count: 2,
    suppressed_by_bounded_evidence_count: 2,
    suppression_summary: {
      suppressed_by_bounded_evidence_count: 2,
      note: SUPPRESSION_SUMMARY_NOTE,
    },
    candidates: [activeReviewCandidate(), activeBlockedCandidate()],
  };
}

function baseCandidate(overrides: Partial<RetentionDueCandidate> = {}): RetentionDueCandidate {
  return {
    candidate_id: 'retention-candidate-review',
    scope: 'book_archive',
    category: 'documents',
    record_id: 'archive-doc-review',
    book_id: 'book-archive-review',
    entity_id: 'entity-retention',
    closing_date: '2024-06-01',
    due_date: '2026-06-01',
    overdue: true,
    policy_id: 'retention-review',
    policy_name: 'Revisão documental',
    schedule_id: 'book-archive-documents-v1',
    retention_period: 'P2Y',
    disposal_action: 'review',
    destructive_action: false,
    legal_hold_blockers: [],
    required_approvals: [
      {
        code: 'retention_manual_review',
        required_from: 'privacy_or_settings_manager',
        reason: 'review evidence only before any separate operational process',
      },
    ],
    blockers: [],
    findings: [],
    outcome: 'manual_review_required',
    status: 'awaiting_manual_review',
    candidate_evidence_state: 'review_queued',
    evidence_next_step: 'Review evidence only; no deletion or anonymization is performed.',
    would_execute: false,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    next_step: 'Review evidence only; no deletion or anonymization is performed.',
    ...overrides,
  };
}

function activeReviewCandidate(): RetentionDueCandidate {
  return baseCandidate();
}

function activeBlockedCandidate(): RetentionDueCandidate {
  return baseCandidate({
    candidate_id: 'retention-candidate-unsupported',
    record_id: 'archive-doc-blocked',
    book_id: 'book-archive-blocked',
    entity_id: 'entity-blocked',
    policy_id: 'retention-unsupported',
    policy_name: 'Unsupported archival period',
    schedule_id: 'archive-unsupported-v1',
    retention_period: 'PXBROKEN',
    legal_hold_blockers: [
      {
        policy_id: 'retention-unsupported',
        name: 'Board preservation hold',
        reason: 'legal hold active on archived book',
      },
    ],
    required_approvals: [
      {
        code: 'unsupported_period_review',
        required_from: 'privacy_or_settings_manager',
        reason: 'unsupported period must be corrected before operational review',
      },
    ],
    blockers: [
      {
        code: 'unsupported_retention_period',
        message: 'Retention period PXBROKEN is not supported.',
      },
    ],
    findings: [
      {
        code: 'unsupported_retention_period',
        message: 'Retention period PXBROKEN is not supported.',
        severity: 'warning',
      },
    ],
    outcome: 'blocked_unsupported_period',
    status: 'blocked',
    candidate_evidence_state: 'blocked',
    evidence_next_step: 'Correct the retention schedule; this scan records evidence only.',
    next_step: 'Correct the retention schedule; this scan records evidence only.',
  });
}

function retentionExecutionsFixture(): RetentionExecutionRecord[] {
  return [
    retentionExecutionFixture('doc-456', 'bounded_archive_recorded'),
    retentionExecutionFixture('doc-789', 'bounded_no_action_recorded'),
  ];
}

function retentionExecutionFixture(
  recordId: string,
  outcome: Extract<
    RetentionExecutionOutcome,
    'bounded_archive_recorded' | 'bounded_no_action_recorded'
  >,
): RetentionExecutionRecord {
  const isArchive = outcome === 'bounded_archive_recorded';
  const disposalAction = isArchive ? 'archive' : 'no_action';
  const policyId = isArchive ? 'retention-archive' : 'retention-no-action';
  const policyName = isArchive ? 'Arquivo delimitado' : 'Conservação sem ação';
  const evidenceText = isArchive
    ? `Bounded archive evidence for ${recordId} remains visible in execution history.`
    : `Bounded no-action evidence for ${recordId} remains visible in execution history.`;
  const action = isArchive ? 'bounded_archive_evidence' : 'bounded_no_action_evidence';

  return {
    id: `retention-exec-${recordId}`,
    requested_at: '2026-07-12T10:05:00.000Z',
    actor: 'retention.e2e',
    execution_intent: 'execute_supported',
    execution_status: 'executed',
    operator_review_decision: 'execution_recorded',
    decision_state: 'open',
    review_closure_evidence: [],
    requested_policy: {
      id: policyId,
      found: true,
      name: policyName,
      scope: 'book_archive',
      category: 'documents',
      schedule_id: 'book-archive-documents-v1',
      retention_period: 'P2Y',
      disposal_action: disposalAction,
      status: 'active',
      active: true,
      stale: false,
      matches_candidate: true,
      destructive_action: false,
    },
    candidate: { scope: 'book_archive', category: 'documents', record_id: recordId },
    matched_records_summary: {
      scope: 'book_archive',
      category: 'documents',
      record_id: recordId,
      record_count: 1,
      policy_match_count: 1,
      destructive_policy_count: 0,
      policy_ids: [policyId],
    },
    legal_hold_blockers: [],
    operator_notes: evidenceText,
    audit_evidence: [{ label: 'bounded evidence', value: `sha256:${recordId}-fixture` }],
    outcome,
    block_reason: evidenceText,
    evidence_state: outcome,
    evidence_next_step: evidenceText,
    workflow: {
      status: 'awaiting_manual_review',
      blockers: [],
      required_approvals: [],
      next_step: evidenceText,
    },
    execution_result: {
      bounded_executor: true,
      executed_at: '2026-07-12T10:06:00.000Z',
      executed_by: 'retention.e2e',
      targets_considered: [
        {
          target_type: 'retention_candidate_record',
          target_id: recordId,
          action,
          reason_code: 'target_considered',
          detail: `Candidate ${recordId} evaluated for bounded evidence only.`,
        },
      ],
      targets_acted: [
        {
          target_type: 'retention_candidate_record',
          target_id: recordId,
          action,
          reason_code: outcome,
          detail: evidenceText,
        },
      ],
      targets_skipped: [],
      reason_codes: [outcome],
      next_step: evidenceText,
      destructive_disposal_completed: false,
      full_erasure_completed: false,
      blocker_metadata: [],
    },
    would_execute: false,
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    legal_hold_mutated: false,
    retention_policy_mutated: false,
  };
}

function closeRetentionExecutionReviewFixture(
  record: RetentionExecutionRecord,
  body: CloseRetentionExecutionReviewBody,
): RetentionExecutionRecord {
  return {
    ...record,
    decision_state: 'review_closed',
    review_closure_decision: body.review_closure_decision,
    review_closure_note: body.review_closure_note,
    review_closure_evidence: body.review_closure_evidence ?? [],
    review_closed_by: 'retention.e2e',
    review_closed_at: '2026-07-12T10:07:00.000Z',
    destructive_disposal_completed: false,
    full_erasure_completed: false,
    legal_hold_mutated: false,
    retention_policy_mutated: false,
  };
}
