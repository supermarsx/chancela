/**
 * Focused browser proof for local convocation/convening dispatch evidence.
 * The API is route-stubbed so this pins dashboard routing and the act endpoint
 * without claiming provider delivery, registry/DRE acceptance, or legal completion.
 */
import { expect, test, type Page, type Route } from '@playwright/test';
import {
  DEFAULT_SETTINGS,
  type ActView,
  type BookView,
  type ComplianceReport,
  type Dashboard,
  type DashboardReminder,
  type DispatchActConveningBody,
  type Entity,
  type PermissionGrant,
  type Settings,
  type UpdateActBody,
  type UserView,
} from '../src/api/types';

const ACT_ID = '62e3d0a1-1000-4000-8000-00000000c001';
const BOOK_ID = '62e3d0a1-1000-4000-8000-00000000c002';
const ENTITY_ID = '62e3d0a1-1000-4000-8000-00000000c003';
const USER_ID = '62e3d0a1-1000-4000-8000-00000000c004';

const ENTITY_NAME = 'Chancela Convening E2E, S.A.';
const ACT_TITLE = 'Assembleia Geral de Aprovação de Contas';
const DISPATCH_PATH = `/v1/acts/${ACT_ID}/convening/dispatch`;
const LOCAL_EVIDENCE_REFERENCE = 'doc:convocatoria-2026-06-01';

test.use({ timezoneId: 'Europe/Lisbon' });

test('dashboard convocation reminder routes to convening guidance and records local dispatch evidence', async ({
  page,
}) => {
  const dispatchBodies: DispatchActConveningBody[] = [];
  const patchBodies: UpdateActBody[] = [];
  await routeConveningDispatchFixtures(page, dispatchBodies, patchBodies);

  await page.goto('/?painel=queue');

  const queue = page.getByRole('list', { name: 'Fila de trabalho do painel' });
  await expect(queue).toBeVisible();
  await expect(queue).toContainText(`Rever convocatória: ${ACT_TITLE}`);
  await expect(queue).toContainText('Fonte act-convening-notice / csc-commercial');
  await expect(queue).toContainText('Aviso consultivo local; não afirma suficiência legal');

  const action = queue.getByRole('link', { name: 'Rever convocatória' });
  await expect(action).toHaveAttribute('href', `/atas/${ACT_ID}#convening-guidance`);

  await Promise.all([page.waitForURL(`**/atas/${ACT_ID}#convening-guidance`), action.click()]);

  const guidance = page.getByTestId('convening-guidance');
  await expect(guidance).toBeVisible();
  await expect(guidance).toContainText('Convocatória');
  await expect(guidance).toContainText('Aviso local da convocatória estatutária');
  await expect(guidance).toContainText(
    'Registe data/meio de expedição, antecedência efetiva e referência da prova conservada.',
  );
  await expect(guidance).toContainText(
    'Apenas metadados locais; não afirma suficiência jurídica, entrega externa válida nem conclusão do workflow.',
  );

  const localEvidence = page.getByLabel('Evidência local de expedição da convocatória');
  await expect(localEvidence).toContainText(
    'Regista apenas evidência local de expedição e proveniência no ledger.',
  );
  await expect(localEvidence).toContainText('Não envia email/SMS');
  await expect(localEvidence).toContainText('não confirma entrega externa');
  await expect(localEvidence).toContainText('aceitação por registo/DRE');
  await expect(localEvidence).toContainText('aceitação por prestador');

  const recordButton = localEvidence.getByRole('button', { name: 'Registar expedição local' });
  await expect(recordButton).toBeDisabled();

  await page.getByRole('button', { name: 'Adicionar destinatário' }).click();
  await page.getByRole('button', { name: 'Adicionar destinatário' }).click();

  const firstRecipient = page.getByRole('group', { name: 'Destinatário 1' });
  await firstRecipient.getByLabel('Nome').fill('Ana Sócia');
  await firstRecipient.getByLabel('Contacto').fill('ana.socia@example.test');
  await firstRecipient.getByLabel('Meio').selectOption('Email');

  const secondRecipient = page.getByRole('group', { name: 'Destinatário 2' });
  await secondRecipient.getByLabel('Nome').fill('Bruno Sócio');
  await secondRecipient.getByLabel('Contacto').fill('bruno.socio@example.test');
  await secondRecipient.getByLabel('Meio').selectOption('Email');

  await expect(recordButton).toBeDisabled();
  const saveResponse = waitForApiResponse(page, `/v1/acts/${ACT_ID}`, 'PATCH');
  await page.getByRole('button', { name: 'Guardar' }).click();
  expect((await saveResponse).status()).toBe(200);
  expect(patchBodies.at(-1)?.convening?.recipients).toEqual([
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
  ]);

  const dispatchResponse = waitForApiResponse(page, DISPATCH_PATH, 'POST');
  await expect(recordButton).toBeEnabled();
  await recordButton.click();
  expect((await dispatchResponse).status()).toBe(200);

  expect(dispatchBodies).toEqual([
    {
      dispatched_at: '2026-06-01',
      channel: 'Email',
      reference: LOCAL_EVIDENCE_REFERENCE,
      recipients: ['Ana Sócia', 'Bruno Sócio'],
    },
  ]);
  await expect(firstRecipient.getByLabel('Contacto')).toHaveValue('ana.socia@example.test');
  await expect(firstRecipient.getByLabel('Referência de expedição')).toHaveValue(
    LOCAL_EVIDENCE_REFERENCE,
  );
  await expect(secondRecipient.getByLabel('Contacto')).toHaveValue('bruno.socio@example.test');
  await expect(secondRecipient.getByLabel('Referência de expedição')).toHaveValue(
    LOCAL_EVIDENCE_REFERENCE,
  );
  await expect(page.getByText('Evidência local de expedição registada.')).toBeVisible();
  await expect(localEvidence).toContainText('Marca 2 destinatário(s) existente(s)');

  const visibleCopy = page.locator('body');
  await expect(visibleCopy).not.toContainText(
    /suficiência (?:legal|jurídica) confirmada|entrega externa confirmada|email enviado|sms enviado|workflow concluído|registo\/DRE aceite|aceitação por registo\/DRE confirmada|aceitação por prestador confirmada|prestador confirmou/i,
  );
});

async function routeConveningDispatchFixtures(
  page: Page,
  dispatchBodies: DispatchActConveningBody[],
  patchBodies: UpdateActBody[],
): Promise<void> {
  let act = actFixture();

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
      await fulfillJson(route, act);
      return;
    }
    if (method === 'PATCH' && pathname === `/v1/acts/${ACT_ID}`) {
      const body = request.postDataJSON() as UpdateActBody;
      patchBodies.push(body);
      act = { ...act, ...(body as Partial<ActView>) };
      await fulfillJson(route, act);
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
    if (method === 'GET' && pathname === '/v1/documents/imported') {
      await fulfillJson(route, []);
      return;
    }
    if (method === 'POST' && pathname === DISPATCH_PATH) {
      const body = request.postDataJSON() as DispatchActConveningBody;
      dispatchBodies.push(body);
      act = recordConveningDispatch(act, body);
      await fulfillJson(route, act);
      return;
    }

    await fulfillJson(
      route,
      { error: `Unhandled convening dispatch e2e route: ${method} ${pathname}` },
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
    username: 'operator.convening',
    display_name: 'Operator Convening',
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
      'act.advance',
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
    organization: { ...DEFAULT_SETTINGS.organization, name: 'Convening Dispatch E2E' },
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
    ledger_length: 7,
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
    reminders: [conveningReminderFixture()],
    recent_events: [],
  };
}

function conveningReminderFixture(): DashboardReminder {
  return {
    due_date: '2026-05-31',
    severity: 'Advisory',
    status: 'Pending',
    reason: 'Raw backend convocation fallback must not render.',
    entity_id: ENTITY_ID,
    entity_name: ENTITY_NAME,
    source_rule: 'act-convening-notice',
    source_profile: 'csc-commercial',
    params: {
      act_id: ACT_ID,
      act_title: ACT_TITLE,
      book_id: BOOK_ID,
      required_notice_days: '30',
      meeting_date: '2026-06-30',
      notice_due_date: '2026-05-31',
      dispatch_date: '2026-06-01',
      evidence_status: 'missing_or_unverifiable_dispatch_evidence',
    },
    action: {
      kind: 'open_act_convening_notice',
      label_key: 'notifications.reminder.act.conveningNotice.action',
      api_href: DISPATCH_PATH,
      route: `/atas/${ACT_ID}`,
    },
    i18n: {
      title_key: 'notifications.reminder.act.conveningNotice.title',
      body_key: 'notifications.reminder.act.conveningNotice.body',
      action_key: 'notifications.reminder.act.conveningNotice.action',
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
      evidence_reference: LOCAL_EVIDENCE_REFERENCE,
      recipients: [],
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

function recordConveningDispatch(act: ActView, body: DispatchActConveningBody): ActView {
  const selected = new Set((body.recipients ?? []).map((name) => name.trim()));
  return {
    ...act,
    convening: act.convening
      ? {
          ...act.convening,
          recipients: act.convening.recipients.map((recipient) => {
            if (!selected.has(recipient.name)) return recipient;
            return {
              ...recipient,
              dispatched_at: body.dispatched_at,
              channel: body.channel ?? recipient.channel,
              reference: body.reference ?? recipient.reference,
            };
          }),
        }
      : act.convening,
  };
}
