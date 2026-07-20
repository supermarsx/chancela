/**
 * Focused browser proof for generated Convocatoria document dispatch evidence.
 * The API is route-stubbed and records operator metadata only: no provider send,
 * delivery confirmation, legal notice completion, registry/provider acceptance,
 * or PDF replacement is asserted.
 */
import { expect, test, type Page, type Route } from '@playwright/test';
import {
  DEFAULT_SETTINGS,
  type ActView,
  type BookView,
  type ComplianceReport,
  type Dashboard,
  type DashboardReminder,
  type Entity,
  type GeneratedDocumentDispatchEvidenceList,
  type GeneratedDocumentDispatchEvidenceRecord,
  type GeneratedDocumentDispatchEvidenceRequest,
  type GeneratedDocumentDispatchEvidenceResponse,
  type GeneratedDocumentView,
  type PermissionGrant,
  type Settings,
  type SignatureStatusView,
  type TemplateSummary,
  type UserView,
} from '../src/api/types';

const ACT_ID = '72e3d0a1-1000-4000-8000-00000000d001';
const BOOK_ID = '72e3d0a1-1000-4000-8000-00000000d002';
const ENTITY_ID = '72e3d0a1-1000-4000-8000-00000000d003';
const USER_ID = '72e3d0a1-1000-4000-8000-00000000d004';
const GENERATED_DOCUMENT_ID = 'generated-convening-browser-1';

const ENTITY_NAME = 'Chancela Convocatoria E2E, S.A.';
const ACT_TITLE = 'Assembleia Geral Convocada';
const TEMPLATE_ID = 'csc-convocatoria-ag/v1';
const GENERATED_DOCUMENT_PATH = `/v1/documents/generated/${GENERATED_DOCUMENT_ID}`;
const DISPATCH_EVIDENCE_PATH = `${GENERATED_DOCUMENT_PATH}/dispatch-evidence`;
const OPERATOR_NOTE =
  'Metadados operacionais do operador para a convocatória gerada; referência externa local.';

test.use({ timezoneId: 'Europe/Lisbon' });

test('dashboard reminder opens generated convening notice evidence and records metadata only', async ({
  page,
}) => {
  const recordedBodies: GeneratedDocumentDispatchEvidenceRequest[] = [];
  await routeGeneratedConveningDispatchFixtures(page, recordedBodies);

  await page.goto('/?painel=queue');

  const queue = page.getByRole('list', { name: 'Fila de trabalho do painel' });
  await expect(queue).toBeVisible();
  await expect(queue).toContainText('generated-convening-dispatch-evidence');
  await expect(queue).toContainText('generated-convening-notice');
  await expect(queue).toContainText('no sending, delivery, legal notice completion');

  const action = queue.getByRole('link', { name: ENTITY_NAME });
  await expect(action).toHaveAttribute(
    'href',
    `/atas/${ACT_ID}?generated_document_id=${GENERATED_DOCUMENT_ID}&focus=dispatch-evidence#generated-dispatch-evidence`,
  );

  await Promise.all([
    page.waitForURL(`**/atas/${ACT_ID}?generated_document_id=${GENERATED_DOCUMENT_ID}**`),
    action.click(),
  ]);

  await expect(page.getByText('Minutas geradas')).toBeVisible();
  const generatedList = page.getByRole('list', { name: 'Comunicações geradas' });
  await expect(generatedList).toContainText(TEMPLATE_ID);
  await expect(generatedList).toContainText(GENERATED_DOCUMENT_ID);

  const form = page.getByRole('form', {
    name: 'Registar evidência da comunicação gerada',
  });
  await expect(form).toBeVisible();
  await expect(form).toBeFocused();
  await expect(form).toContainText('Registo de evidência pelo operador');
  await expect(form).toContainText(
    'Registe apenas metadados de evidência. A Chancela não enviou, não confirmou entrega e não completou aviso legal.',
  );

  const status = page.getByRole('group', {
    name: 'Estado da evidência de comunicação gerada',
  });
  await expect(status).toContainText('required_pending');
  await expect(status).toContainText('0/2 destinatários');
  await expect(status).toContainText('dispatch_completed');
  await expect(status).toContainText('false');
  await expect(status).toContainText('none');

  await form.getByLabel('Data/hora registada').fill('2026-07-12T09:45');
  await form.getByLabel('Canal').selectOption('Email');
  await form.getByLabel('Referência', { exact: true }).fill('MSG-789');
  await form.getByLabel('Referência da evidência').fill('mailbox:convocatoria-789');
  await form.getByLabel('Bruno Sócio').uncheck();
  await form.getByLabel('Nota do operador').fill(OPERATOR_NOTE);

  const recordResponse = waitForApiResponse(page, DISPATCH_EVIDENCE_PATH, 'POST');
  await form.getByRole('button', { name: 'Registar evidência' }).click();
  expect((await recordResponse).status()).toBe(201);

  expect(recordedBodies).toEqual([
    {
      actor: 'web-operator',
      dispatched_at: '2026-07-12T08:45:00.000Z',
      channel: 'Email',
      reference: 'MSG-789',
      recipients: ['Ana Sócia'],
      evidence_reference: 'mailbox:convocatoria-789',
      imported_document_id: null,
      operator_note: OPERATOR_NOTE,
    },
  ]);

  const evidenceRows = page.getByRole('list', { name: 'Linhas de evidência registadas' });
  await expect(evidenceRows).toContainText('web-operator');
  await expect(evidenceRows).toContainText('Correio eletrónico');
  await expect(evidenceRows).toContainText('MSG-789');
  await expect(evidenceRows).toContainText('Ana Sócia');
  await expect(evidenceRows).toContainText(OPERATOR_NOTE);
  await expect(evidenceRows).toContainText(
    'Envio pela Chancela=false; confirmação de entrega=false; suficiência legal=false; reivindicação de conclusão=false; bytes no payload=false.',
  );

  const visibleCopy = page.locator('body');
  await expect(visibleCopy).not.toContainText(
    /email enviado|sms enviado|entrega confirmada|aviso legal concluído|suficiência legal confirmada|workflow concluído|registo\/DRE aceite|aceitação por prestador confirmada|pdf substituído|PDF\/A substituído/i,
  );
});

async function routeGeneratedConveningDispatchFixtures(
  page: Page,
  recordedBodies: GeneratedDocumentDispatchEvidenceRequest[],
): Promise<void> {
  const evidenceRows: GeneratedDocumentDispatchEvidenceRecord[] = [];
  let dispatchStatus = generatedConveningDocumentFixture().dispatch_evidence_status!;

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/**', async (route) => {
    const request = route.request();
    const method = request.method();
    const url = new URL(request.url());
    const pathname = url.pathname;

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
        entries: [],
        durable: true,
        max_entries_per_owner: 500,
      });
      return;
    }
    if (method === 'GET' && pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 9 });
      return;
    }
    if (method === 'GET' && pathname === '/v1/templates') {
      await fulfillJson(
        route,
        url.searchParams.get('stage') === 'Convocatoria' ? [convocatoriaTemplateFixture()] : [],
      );
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
    if (method === 'GET' && pathname === `/v1/acts/${ACT_ID}/documents/generated`) {
      await fulfillJson(route, [
        {
          ...generatedConveningDocumentFixture(),
          dispatch_evidence_status: dispatchStatus,
        },
      ]);
      return;
    }
    if (method === 'GET' && pathname === DISPATCH_EVIDENCE_PATH) {
      await fulfillJson(route, generatedDispatchEvidenceFixture(dispatchStatus, evidenceRows));
      return;
    }
    if (method === 'POST' && pathname === DISPATCH_EVIDENCE_PATH) {
      const body = request.postDataJSON() as GeneratedDocumentDispatchEvidenceRequest;
      recordedBodies.push(body);
      const row = recordedEvidenceRow(body);
      evidenceRows.push(row);
      dispatchStatus = {
        ...dispatchStatus,
        status: 'operator_evidence_partial',
        evidence_attached: true,
        recorded_recipients: ['Ana Sócia'],
        missing_recipients: ['Bruno Sócio'],
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
      await fulfillJson(route, []);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled generated-convening dispatch e2e route: ${method} ${pathname}` },
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
    username: 'operator.generated.convening',
    display_name: 'Operator Generated Convening',
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
    ...DEFAULT_SETTINGS,
    organization: { ...DEFAULT_SETTINGS.organization, name: 'Generated Convening E2E' },
    documents: { ...DEFAULT_SETTINGS.documents, locale: 'pt-PT' },
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
    acts_sealed: 0,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: 9,
    ledger_valid: true,
    current_work: {
      open_books: [
        {
          book_id: BOOK_ID,
          entity_id: ENTITY_ID,
          entity_name: ENTITY_NAME,
          kind: 'AssembleiaGeral',
          purpose: 'Livro de atas da assembleia geral',
          opening_date: '2026-01-01',
          last_ata_number: 3,
          total_acts: 1,
          open_acts: 1,
          next_ata_number: 4,
          links: {
            entity: `/v1/entities/${ENTITY_ID}`,
            book: `/v1/books/${BOOK_ID}`,
            act: `/v1/acts/${ACT_ID}`,
            ledger: null,
          },
        },
      ],
      act_counts_by_state: {
        Draft: 0,
        Review: 1,
        Convened: 0,
        Deliberated: 0,
        TextApproved: 0,
        Signing: 0,
        Sealed: 0,
        Archived: 0,
      },
    },
    alerts: [],
    reminders: [generatedConveningReminderFixture()],
    recent_events: [],
  };
}

function generatedConveningReminderFixture(): DashboardReminder {
  return {
    due_date: '',
    severity: 'Advisory',
    status: 'Pending',
    reason:
      'Generated convening notice evidence is required_pending; no sending, delivery, legal notice completion, or legal sufficiency is claimed.',
    entity_id: ENTITY_ID,
    entity_name: ENTITY_NAME,
    source_rule: 'generated-convening-dispatch-evidence',
    source_profile: 'generated-convening-notice',
    params: {
      act_id: ACT_ID,
      act_title: ACT_TITLE,
      book_id: BOOK_ID,
      generated_document_id: GENERATED_DOCUMENT_ID,
      template_id: TEMPLATE_ID,
      dispatch_evidence_status: 'required_pending',
      required_recipient_count: '2',
      recorded_recipient_count: '0',
      missing_recipient_count: '2',
      missing_recipients: 'Ana Sócia, Bruno Sócio',
      dispatch_completed: 'false',
      completion_basis: 'none',
      sending_performed_by_chancela: 'false',
      delivery_confirmed: 'false',
      legal_notice_completion_claimed: 'false',
      legal_sufficiency_claimed: 'false',
    },
    action: {
      kind: 'open_generated_convening_dispatch_evidence',
      label_key: 'notifications.reminder.absentOwnerDispatch.action',
      api_href: DISPATCH_EVIDENCE_PATH,
      route: `/atas/${ACT_ID}`,
    },
    i18n: null,
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
      template_family: 'csc',
      calendar_presets: [],
    },
    statute: {
      quorum: null,
      majority: null,
      convocation_notice_days: 30,
    },
  };
}

function bookFixture(): BookView {
  return {
    id: BOOK_ID,
    entity_id: ENTITY_ID,
    kind: 'AssembleiaGeral',
    state: 'Open',
    purpose: 'Livro de atas da assembleia geral',
    numbering_scheme: 'Sequential',
    opening_date: '2026-01-01',
    closing_date: null,
    closing_reason: null,
    last_ata_number: 3,
    predecessor: null,
    required_signatories_abertura: ['Presidente'],
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
    mesa: { presidente: 'Ana Presidente', secretarios: ['Rui Secretário'] },
    agenda: [{ number: 1, text: 'Aprovação de contas' }],
    attendance_reference: 'Lista de presenças',
    members_present: 10,
    members_represented: 2,
    referenced_documents: [],
    deliberations: 'Contas em apreciação.',
    deliberation_items: [],
    telematic_evidence: null,
    attachments: [],
    signatories: [{ name: 'Ana Presidente', capacity: 'Chair' }],
    state: 'Review',
    ata_number: null,
    payload_digest: null,
    seal_event_seq: null,
    seal_metadata: null,
    retifies: null,
    convening: {
      convener: 'Administração',
      convener_capacity: 'Administrator',
      dispatch_date: '2026-06-01',
      antecedence_days: null,
      channel: 'Email',
      evidence_reference: null,
      recipients: [
        {
          name: 'Ana Sócia',
          contact: 'ana.socia@example.test',
          channel: 'Email',
          reference: null,
          dispatched_at: null,
        },
        {
          name: 'Bruno Sócio',
          contact: 'bruno.socio@example.test',
          channel: 'Email',
          reference: null,
          dispatched_at: null,
        },
      ],
      second_call: null,
    },
  };
}

function complianceFixture(): ComplianceReport {
  return {
    rule_pack: 'csc-art63/v2',
    family: 'CommercialCompany',
    statute_overlay: true,
    issues: [],
    errors: 0,
    warnings: 0,
    seal_allowed: true,
  };
}

function convocatoriaTemplateFixture(): TemplateSummary {
  return {
    id: TEMPLATE_ID,
    family: 'CommercialCompany',
    stage: 'Convocatoria',
    channels: ['Physical'],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: 'csc',
    law_references: [],
    locale: 'pt-PT',
    editable: false,
    source: 'builtin',
  };
}

function generatedConveningDocumentFixture(): GeneratedDocumentView {
  return {
    id: GENERATED_DOCUMENT_ID,
    act_id: ACT_ID,
    template_id: TEMPLATE_ID,
    pdf_digest: 'ef'.repeat(32),
    profile: 'application/pdf; profile=PDF/A-2u',
    created_at: '2026-07-11T09:15:00.000Z',
    download: GENERATED_DOCUMENT_PATH,
    dispatch_evidence_status: {
      status: 'required_pending',
      required: true,
      evidence_attached: false,
      dispatch_completed: false,
      completion_basis: 'none',
      required_recipients: ['Ana Sócia', 'Bruno Sócio'],
      recorded_recipients: [],
      missing_recipients: ['Ana Sócia', 'Bruno Sócio'],
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

function recordedEvidenceRow(
  body: GeneratedDocumentDispatchEvidenceRequest,
): GeneratedDocumentDispatchEvidenceRecord {
  return {
    document_id: GENERATED_DOCUMENT_ID,
    idempotency_key: 'recorded-generated-convening-evidence-row',
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
