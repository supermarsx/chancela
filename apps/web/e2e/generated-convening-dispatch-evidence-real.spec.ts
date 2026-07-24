/**
 * Real-backend browser proof for generated Convocatoria dispatch evidence.
 *
 * This composes the release server, the built SPA, and real HTTP state seeding.
 * It deliberately records operator metadata only: no provider sending, delivery
 * confirmation, legal-notice completion, registry/DRE filing, archive certification,
 * restart persistence, or browser-matrix coverage is claimed here.
 */
import { expect, test, type APIRequestContext, type Page } from './fixtures';
import { OPERATOR, OPERATOR_PASSWORD, signInAt } from './auth';
import type {
  ActView,
  BookView,
  Dashboard,
  Entity,
  GeneratedDocumentDispatchEvidenceList,
  GeneratedDocumentDispatchEvidenceResponse,
  GeneratedDocumentView,
  SessionResult,
} from '../src/api/types';

const TEMPLATE_ID = 'csc-convocatoria-ag/v1';
const ENTITY_NAME = 'Chancela Convocatoria Real E2E, S.A.';
const ACT_TITLE = 'Ata da AG anual convocada por Convocatoria';
const OPERATOR_NOTE =
  'metadata-only generated convening browser proof; no sending or delivery claim';

test.use({ timezoneId: 'Europe/Lisbon' });

test('records generated Convocatoria dispatch evidence against the real backend', async ({
  page,
}) => {
  test.setTimeout(120_000);

  await signInAt(page, '/');
  const session = await createSessionForUsername(page.request, OPERATOR.username);
  const seeded = await seedGeneratedConveningAct(page.request, session.token);

  await signInAt(page, `/acts/${seeded.act.id}`);
  await expect(page).toHaveURL(new RegExp(`/acts/${seeded.act.id}$`));
  await expect(page.getByText('Minutas geradas')).toBeVisible();

  await page.locator('#post-act-template').selectOption(TEMPLATE_ID);
  const generateResponsePromise = waitForApiResponse(
    page,
    `/v1/acts/${seeded.act.id}/document/generate`,
    'POST',
  );
  await page.getByRole('button', { name: 'Gerar documento' }).click();
  const generated = await readJsonResponse<GeneratedDocumentView>(
    await generateResponsePromise,
    'generate Convocatoria document',
    201,
  );
  expect(generated.act_id).toBe(seeded.act.id);
  expect(generated.template_id).toBe(TEMPLATE_ID);
  expect(generated.dispatch_evidence_status?.status).toBe('required_pending');
  expect(generated.dispatch_evidence_status?.dispatch_completed).toBe(false);
  expect(generated.dispatch_evidence_status?.completion_basis).toBe('none');
  expect(generated.dispatch_evidence_status?.required_recipients).toEqual([
    'Ana Sócia',
    'Bruno Sócio',
  ]);

  const generatedList = page.getByRole('list', { name: 'Comunicações geradas' });
  await expect(generatedList).toContainText(TEMPLATE_ID);
  await expect(generatedList).toContainText(generated.id);

  await signInAt(page, '/dashboard/queue');
  const queue = page.getByRole('list', { name: 'Fila de trabalho do painel' });
  await expect(queue).toBeVisible();
  const reminder = queue
    .getByRole('listitem')
    .filter({ hasText: seeded.entity.name })
    .filter({ hasText: 'Fonte Evidência de expedição da convocatória' });
  await expect(reminder).toContainText('Fonte Evidência de expedição da convocatória');
  await expect(reminder).toContainText('required_pending');
  await expect(reminder).toContainText(
    'does not claim sending, delivery, legal notice completion, or legal sufficiency',
  );

  const reminderLink = reminder.getByRole('link', { name: seeded.entity.name });
  await expect(reminderLink).toHaveAttribute(
    'href',
    `/acts/${seeded.act.id}?generated_document_id=${generated.id}&focus=dispatch-evidence#generated-dispatch-evidence`,
  );
  await Promise.all([
    page.waitForURL(
      `**/acts/${seeded.act.id}?generated_document_id=${generated.id}&focus=dispatch-evidence**`,
    ),
    reminderLink.click(),
  ]);

  const form = page.getByRole('form', {
    name: 'Registar evidência da comunicação gerada',
  });
  await expect(form).toBeVisible();
  await expect(form).toBeFocused();
  await expect(form).toContainText('Registo de evidência pelo operador');
  await expect(form).toContainText(
    'A Chancela não enviou, não confirmou entrega e não completou aviso legal.',
  );

  const status = page.getByRole('group', {
    name: 'Estado da evidência de comunicação gerada',
  });
  await expect(status).toContainText('required_pending');
  await expect(status).toContainText('0/2 destinatários');
  await expect(status).toContainText('dispatch_completed');
  await expect(status).toContainText('false');
  await expect(status).toContainText('none');

  await expect(form.getByLabel('Ana Sócia')).toBeChecked();
  await expect(form.getByLabel('Bruno Sócio')).toBeChecked();
  await form.getByLabel('Data/hora registada').fill('2026-03-01T09:00');
  await form.getByLabel('Canal').selectOption('Email');
  await form.getByLabel('Referência', { exact: true }).fill('MSG-1');
  await form
    .getByLabel('Referência da evidência')
    .fill('archive:generated-convening-notice-dispatch');
  await form.getByLabel('Nota do operador').fill(OPERATOR_NOTE);

  const evidencePath = `/v1/documents/generated/${generated.id}/dispatch-evidence`;
  const recordResponsePromise = waitForApiResponse(page, evidencePath, 'POST');
  await form.getByRole('button', { name: 'Registar evidência' }).click();
  const recorded = await readJsonResponse<GeneratedDocumentDispatchEvidenceResponse>(
    await recordResponsePromise,
    'record generated Convocatoria dispatch evidence',
    201,
  );
  assertCoveredMetadataOnlyEvidence(recorded, generated.id, seeded.act.id);

  await expect(status).toContainText('operator_evidence_covered');
  await expect(status).toContainText('2/2 destinatários');
  await expect(status).toContainText('dispatch_completed');
  await expect(status).toContainText('false');
  await expect(status).toContainText('none');

  const evidenceRows = page.getByRole('list', { name: 'Linhas de evidência registadas' });
  await expect(evidenceRows).toContainText(OPERATOR.username);
  await expect(evidenceRows).toContainText('MSG-1');
  await expect(evidenceRows).toContainText('archive:generated-convening-notice-dispatch');
  await expect(evidenceRows).toContainText('Ana Sócia, Bruno Sócio');
  await expect(evidenceRows).toContainText(OPERATOR_NOTE);
  await expect(evidenceRows).toContainText(
    'Envio pela Chancela=false; confirmação de entrega=false; suficiência legal=false; reivindicação de conclusão=false; bytes no payload=false.',
  );

  const evidenceList = await apiJson<GeneratedDocumentDispatchEvidenceList>(
    page.request,
    'GET',
    evidencePath,
    { token: session.token, context: 'read generated Convocatoria dispatch evidence' },
  );
  expect(evidenceList.document_id).toBe(generated.id);
  expect(evidenceList.act_id).toBe(seeded.act.id);
  expect(evidenceList.template_id).toBe(TEMPLATE_ID);
  expect(evidenceList.dispatch_evidence_status.status).toBe('operator_evidence_covered');
  expect(evidenceList.dispatch_evidence_status.dispatch_completed).toBe(false);
  expect(evidenceList.dispatch_evidence_status.completion_basis).toBe('none');
  expect(evidenceList.dispatch_evidence_status.recorded_recipients).toEqual([
    'Ana Sócia',
    'Bruno Sócio',
  ]);
  expect(evidenceList.dispatch_evidence_status.missing_recipients).toEqual([]);
  expect(evidenceList.evidence).toHaveLength(1);
  assertMetadataOnlyRecord(evidenceList.evidence[0], generated.id, seeded.act.id);

  const dashboardAfter = await apiJson<Dashboard>(page.request, 'GET', '/v1/dashboard', {
    token: session.token,
    context: 'dashboard after generated Convocatoria evidence',
  });
  expect(
    dashboardAfter.reminders.some(
      (item) =>
        item.source_rule === 'generated-convening-dispatch-evidence' &&
        item.params?.generated_document_id === generated.id,
    ),
  ).toBe(false);
});

async function createSessionForUsername(
  request: APIRequestContext,
  username: string,
): Promise<SessionResult> {
  // t33-e2: the username goes straight to the server, which resolves it. The unauthenticated
  // roster no longer lists users, and nothing here needs it to.
  return apiJson<SessionResult>(request, 'POST', '/v1/session', {
    data: {
      username,
      password: OPERATOR_PASSWORD,
    },
    context: `session for ${username}`,
  });
}

async function seedGeneratedConveningAct(request: APIRequestContext, token: string) {
  const entity = await apiJson<Entity>(request, 'POST', '/v1/entities', {
    token,
    data: {
      name: ENTITY_NAME,
      nipc: '503004642',
      seat: 'Lisboa',
      kind: 'SociedadeAnonima',
    },
    expectedStatus: 201,
    context: 'create generated Convocatoria entity',
  });
  const book = await apiJson<BookView>(request, 'POST', '/v1/books', {
    token,
    data: {
      entity_id: entity.id,
      kind: 'AssembleiaGeral',
      purpose: 'livro de atas da assembleia geral',
      opening_date: '2026-01-15',
      required_signatories: ['Administrador'],
    },
    expectedStatus: 201,
    context: 'open generated Convocatoria book',
  });
  const act = await apiJson<ActView>(request, 'POST', '/v1/acts', {
    token,
    data: {
      book_id: book.id,
      title: ACT_TITLE,
      channel: 'Physical',
    },
    expectedStatus: 201,
    context: 'draft generated Convocatoria act',
  });
  const patched = await apiJson<ActView>(request, 'PATCH', `/v1/acts/${act.id}`, {
    token,
    data: {
      meeting_date: '2026-03-30',
      meeting_time: '10:00',
      place: 'Sede social',
      mesa: { presidente: 'Ana Presidente', secretarios: ['Rui Secretario'] },
      agenda: [{ number: 1, text: 'Aprovacao das contas' }],
      attendance_reference: 'Lista de presencas',
      deliberations: 'Aprovadas as contas do exercicio.',
      convening: {
        convener: 'Ana Presidente',
        convener_capacity: 'Administrator',
        dispatch_date: '2026-03-01',
        antecedence_days: 21,
        channel: 'Email',
        evidence_reference: 'doc:convocatoria-2026-03-01',
        recipients: [
          {
            name: 'Ana Sócia',
            contact: 'ana@example.test',
            channel: 'Email',
            reference: 'MSG-1',
          },
          {
            name: 'Bruno Sócio',
            contact: 'bruno@example.test',
            channel: 'Email',
            reference: 'MSG-2',
          },
        ],
      },
    },
    context: 'patch generated Convocatoria act contents',
  });
  return { entity, book, act: patched };
}

type ApiMethod = 'GET' | 'POST' | 'PATCH';

async function apiJson<T>(
  request: APIRequestContext,
  method: ApiMethod,
  path: string,
  options: {
    token?: string;
    data?: unknown;
    expectedStatus?: number;
    context?: string;
  } = {},
): Promise<T> {
  const response = await request.fetch(path, {
    method,
    headers: options.token ? sessionHeaders(options.token) : undefined,
    data: options.data,
  });
  return readJsonResponse<T>(
    response,
    options.context ?? `${method} ${path}`,
    options.expectedStatus ?? 200,
  );
}

function sessionHeaders(token: string): Record<string, string> {
  return { 'X-Chancela-Session': token };
}

function waitForApiResponse(page: Page, pathname: string, method: string) {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === pathname && response.request().method() === method;
  });
}

async function readJsonResponse<T>(
  response: { status(): number; text(): Promise<string> },
  context: string,
  expectedStatus: number,
): Promise<T> {
  const text = await response.text();
  expect(response.status(), `${context}: ${text}`).toBe(expectedStatus);
  return JSON.parse(text) as T;
}

function assertCoveredMetadataOnlyEvidence(
  response: GeneratedDocumentDispatchEvidenceResponse,
  documentId: string,
  actId: string,
): void {
  expect(response.dispatch_evidence_status.status).toBe('operator_evidence_covered');
  expect(response.dispatch_evidence_status.dispatch_completed).toBe(false);
  expect(response.dispatch_evidence_status.completion_basis).toBe('none');
  expect(response.dispatch_evidence_status.recorded_recipients).toEqual([
    'Ana Sócia',
    'Bruno Sócio',
  ]);
  expect(response.dispatch_evidence_status.missing_recipients).toEqual([]);
  assertMetadataOnlyRecord(response.evidence, documentId, actId);
}

function assertMetadataOnlyRecord(
  record: GeneratedDocumentDispatchEvidenceList['evidence'][number],
  documentId: string,
  actId: string,
): void {
  expect(record.document_id).toBe(documentId);
  expect(record.act_id).toBe(actId);
  expect(record.template_id).toBe(TEMPLATE_ID);
  expect(record.actor).toBe(OPERATOR.username);
  expect(record.dispatched_at).toBe('2026-03-01T09:00:00Z');
  expect(record.channel).toBe('Email');
  expect(record.reference).toBe('MSG-1');
  expect(record.evidence_reference).toBe('archive:generated-convening-notice-dispatch');
  expect(record.imported_document_id).toBeNull();
  expect(record.recipients).toEqual(['Ana Sócia', 'Bruno Sócio']);
  expect(record.operator_note).toBe(OPERATOR_NOTE);
  expect(record.sending_performed_by_chancela).toBe(false);
  expect(record.delivery_confirmed).toBe(false);
  expect(record.legal_notice_completion_claimed).toBe(false);
  expect(record.legal_sufficiency_claimed).toBe(false);
  expect(record.bytes_in_payload).toBe(false);
}
