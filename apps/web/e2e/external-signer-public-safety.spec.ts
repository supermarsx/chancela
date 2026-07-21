import { expect, test, type Page, type Route } from './fixtures';

const secretToken = 'cxi_e2e_secret_token_history_safety_123';
const revokedToken = 'cxi_e2e_revoked_secret_token_public_404_456';

test('external signer public page scrubs token from URL/history and does not offer PDF downloads', async ({
  page,
}) => {
  const requests: Array<{ path: string; token?: string; decision?: string }> = [];
  const downloads: string[] = [];
  page.on('download', (download) => downloads.push(download.suggestedFilename()));

  await mockExternalSignerInvite(page, requests);

  await page.goto('/external-signature');
  await expect(page.getByText('Ligação sem token')).toBeVisible();

  await page.goto(`/external-signature?token=${encodeURIComponent(secretToken)}`);
  await expect(page.getByRole('heading', { name: 'Convite externo' })).toBeVisible();
  await expect(page.getByText('Ata pública externa')).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  expect(page.url()).not.toContain(secretToken);
  await expect(page.locator('body')).not.toContainText(secretToken);

  await expectNoPdfDownloads(page);

  await page.getByRole('button', { name: 'Aceitar acompanhamento' }).click();
  await expect(page.getByText('Aceite', { exact: true })).toBeVisible();
  await expect(page.getByText(/Este estado não é assinatura qualificada/)).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  expect(page.url()).not.toContain(secretToken);
  await expect(page.locator('body')).not.toContainText(secretToken);

  await page.getByRole('button', { name: 'Pré-visualizar cópia .md' }).click();
  await expect(page.getByTestId('external-working-copy-preview')).toContainText(
    'EXTERNAL SIGNER WORKING COPY',
  );
  await expectNoPdfDownloads(page);
  expect(downloads).toEqual([]);

  await page.reload();
  await expect(page.getByText('Ligação sem token')).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  expect(page.url()).not.toContain(secretToken);

  await page.goBack();
  await expect(page).not.toHaveURL(/token=/);
  expect(page.url()).not.toContain(secretToken);
  await expect(page.locator('body')).not.toContainText(secretToken);

  expect(requests).toEqual([
    { path: '/v1/signature/external-invites/lookup', token: secretToken },
    {
      path: '/v1/signature/external-invites/respond',
      token: secretToken,
      decision: 'accept',
    },
    { path: '/v1/signature/external-invites/document/working-copy', token: secretToken },
  ]);
});

test('external signer unavailable token is scrubbed and exposes no document actions', async ({
  page,
}) => {
  const lookupTokens: string[] = [];
  const unexpectedCalls: string[] = [];
  const downloads: string[] = [];
  page.on('download', (download) => downloads.push(download.suggestedFilename()));

  await page.route('**/v1/signature/external-invites/lookup', async (route) => {
    const body = await readJson(route);
    lookupTokens.push(body.token ?? '');
    await route.fulfill({
      status: 404,
      contentType: 'application/json',
      body: JSON.stringify({
        error: `revoked token ${body.token ?? ''} must not render`,
      }),
    });
  });
  await page.route('**/v1/signature/external-invites/respond', async (route) => {
    unexpectedCalls.push('/v1/signature/external-invites/respond');
    await route.fulfill({ status: 500, body: 'unexpected respond call' });
  });
  await page.route('**/v1/signature/external-invites/document/working-copy', async (route) => {
    unexpectedCalls.push('/v1/signature/external-invites/document/working-copy');
    await route.fulfill({ status: 500, body: 'unexpected document call' });
  });

  await page.goto(`/external-signature?token=${encodeURIComponent(revokedToken)}&utm_source=e2e`);

  await expect(page.getByText('Convite indisponível')).toBeVisible();
  await expect(
    page.getByText(
      'A ligação expirou, foi revogada ou não corresponde a um convite externo ativo.',
    ),
  ).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  expect(page.url()).not.toContain(revokedToken);
  await expect(page.locator('body')).not.toContainText(revokedToken);
  await expectNoPdfDownloads(page);
  await expect(page.getByRole('button', { name: 'Aceitar acompanhamento' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Pré-visualizar cópia .md' })).toHaveCount(0);

  await page.reload();
  await expect(page.getByText('Ligação sem token')).toBeVisible();
  await expect(page).not.toHaveURL(/token=/);
  await expect(page.locator('body')).not.toContainText(revokedToken);

  expect(lookupTokens).toEqual([revokedToken]);
  expect(unexpectedCalls).toEqual([]);
  expect(downloads).toEqual([]);
});

async function mockExternalSignerInvite(
  page: Page,
  requests: Array<{ path: string; token?: string; decision?: string }>,
): Promise<void> {
  await page.route('**/v1/signature/external-invites/lookup', async (route) => {
    const body = await readJson(route);
    requests.push({ path: '/v1/signature/external-invites/lookup', token: body.token });
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(inviteEnvelope('pending')),
    });
  });

  await page.route('**/v1/signature/external-invites/respond', async (route) => {
    const body = await readJson(route);
    requests.push({
      path: '/v1/signature/external-invites/respond',
      token: body.token,
      decision: body.decision,
    });
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        ...inviteEnvelope('accepted'),
        responded_at: '2026-07-09T09:30:00Z',
      }),
    });
  });

  await page.route('**/v1/signature/external-invites/document/working-copy', async (route) => {
    const body = await readJson(route);
    requests.push({
      path: '/v1/signature/external-invites/document/working-copy',
      token: body.token,
    });
    await route.fulfill({
      status: 200,
      contentType: 'text/markdown; charset=utf-8',
      body: '# EXTERNAL SIGNER WORKING COPY\n\nNon-evidentiary preview only.',
    });
  });
}

function inviteEnvelope(status: 'pending' | 'accepted') {
  return {
    invite_id: 'invite-public-e2e',
    act: {
      id: 'act-public-e2e',
      title: 'Ata pública externa',
      state: 'Sealed',
      meeting_date: '2026-03-30',
      ata_number: 7,
      entity_name: 'Chancela E2E, S.A.',
      book_kind: 'AssembleiaGeral',
    },
    document: {
      id: 'doc-public-e2e',
      template_id: 'csc-ata-ag/v1',
      profile: 'application/pdf; profile=PDF/A-2u',
      pdf_digest: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      artifact: {
        kind: 'working_copy_markdown',
        method: 'POST',
        path: '/v1/signature/external-invites/document/working-copy',
        content_type: 'text/markdown; charset=utf-8',
        filename: 'act-public-e2e-external-working-copy.md',
        notice: 'not canonical',
      },
    },
    recipient_name: 'Bruno Dias',
    provider_hint: 'manual-envelope',
    purpose: 'Acompanhar assinatura externa',
    status,
    workflow: 'tracking_only',
    created_at: '2026-07-09T09:00:00Z',
    expires_at: '2026-07-10T09:00:00Z',
    notice: 'tracking only',
  };
}

async function readJson(route: Route): Promise<{ token?: string; decision?: string }> {
  return (route.request().postDataJSON() ?? {}) as { token?: string; decision?: string };
}

async function expectNoPdfDownloads(page: Page): Promise<void> {
  await expect(page.getByRole('button', { name: /descarregar pdf/i })).toHaveCount(0);
  await expect(page.getByRole('link', { name: /descarregar pdf/i })).toHaveCount(0);
  await expect(page.locator('a[download]')).toHaveCount(0);
  await expect(page.locator('a[href*=".pdf" i], a[href*="signed" i]')).toHaveCount(0);
}
