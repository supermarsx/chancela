/**
 * Settings-hosted administration coverage: the users tab is the single roster surface,
 * user lifecycle/access actions work in-browser, RBAC protects the final Owner, and the
 * recovery/data-management confirmation gates render before any destructive submit.
 */
import { test, expect, type Locator, type Page } from './fixtures';
import { OPERATOR, signInAt } from './auth';

test('settings users, RBAC owner guard, and recovery/data confirmation gates', async ({ page }) => {
  test.setTimeout(120_000);

  const suffix = Date.now().toString(36);
  const username = `e2e.rbac.${suffix}`;
  const displayName = `E2E RBAC ${suffix}`;
  const renamed = `E2E RBAC Revisto ${suffix}`;
  const password = 'Forte-Cofre7!Z';

  await test.step('deep link /utilizadores lands on Configuracoes > Utilizadores', async () => {
    await signInAt(page, '/utilizadores');

    await expect(page).toHaveURL(/\/configuracoes\?sec=utilizadores$/);
    await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();
    await expect(settingsSectionButton(page, 'Utilizadores')).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await expect(page.getByRole('heading', { name: 'Utilizadores' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Novo utilizador' })).toBeVisible();
  });

  await test.step('create and edit a user from the settings-hosted roster', async () => {
    await page.getByRole('link', { name: 'Novo utilizador' }).click();
    await expect(page).toHaveURL(/\/configuracoes\?sec=utilizadores&user=novo$/);

    await page.getByLabel('Nome de utilizador').fill(username);
    await page.getByLabel('Nome a apresentar (opcional)').fill(displayName);
    await page.getByLabel('Nova palavra-passe').fill(password);
    await page.getByLabel('Confirmar palavra-passe').fill(password);
    await page.getByRole('button', { name: 'Criar utilizador' }).click();

    await expect(page).toHaveURL(/\/configuracoes\?sec=utilizadores&user=[0-9a-f-]{36}$/);
    await expect(page.getByRole('heading', { name: 'Identidade' })).toBeVisible();
    await expect(page.getByLabel('Nome a apresentar')).toHaveValue(displayName);
    await expect(userRow(page, username)).toContainText(displayName);

    await page.getByLabel('Nome a apresentar').fill(renamed);
    await page.getByRole('button', { name: 'Guardar nome' }).click();
    await expect(page.getByLabel('Nome a apresentar')).toHaveValue(renamed);
    await expect(userRow(page, username)).toContainText(renamed);
  });

  await test.step('self-service password change and recovery phrase work for the new user', async () => {
    await switchCurrentUser(page, renamed, password);
    await expect(page.getByTestId('session-trigger')).toContainText(renamed);

    const access = page.locator('section#acesso');
    await expect(access.getByRole('heading', { name: 'Acesso e auditoria' })).toBeVisible();

    const recoveryBlock = access.locator('.access-manager__block').nth(1);
    await recoveryBlock.getByRole('button', { name: 'Gerar frase de recuperação' }).click();
    // Self-service issuance proves the current password server-side (t51); omitting it makes
    // the POST 401, which the API client treats as a dead session and signs the user out.
    await recoveryBlock.getByLabel('Palavra-passe atual').fill(password);
    await recoveryBlock.getByRole('button', { name: 'Gerar frase' }).click();

    await expect(recoveryBlock.getByText('Guarde esta frase agora')).toBeVisible();
    await expect(recoveryBlock.locator('.access-manager__recovery-phrase code')).toHaveText(
      /.{32,}/,
    );
    await recoveryBlock.getByRole('button', { name: 'Concluído' }).click();
    await expect(recoveryBlock.getByText('Guarde esta frase agora')).toHaveCount(0);

    const passwordBlock = access.locator('.access-manager__block').nth(0);
    await passwordBlock.getByRole('button', { name: 'Alterar' }).click();
    await passwordBlock.getByLabel('Palavra-passe atual').fill(password);
    await passwordBlock.getByLabel('Nova palavra-passe').fill(password);
    await passwordBlock.getByLabel('Confirmar palavra-passe').fill(password);
    await passwordBlock.getByRole('button', { name: 'Guardar' }).click();
    await expect(page.getByText('Palavra-passe definida.')).toBeVisible();
    await expect(passwordBlock.getByLabel('Nova palavra-passe')).toHaveCount(0);
  });

  await test.step('operator can see access badges and deactivate the user from settings', async () => {
    await signInAt(page, '/configuracoes?sec=utilizadores');

    const row = userRow(page, username);
    await expect(row).toContainText(renamed);
    await expect(row).toContainText('Palavra-passe');
    await expect(row).toContainText('Frase de recuperação');

    await row.getByRole('button', { name: 'Desativar' }).click();
    await expect(row).toContainText('Inativo');
    await expect(row.getByRole('button', { name: 'Reativar' })).toBeVisible();
  });

  await test.step('RBAC refuses removing the final Owner assignment', async () => {
    const operatorRow = userRow(page, OPERATOR.username);
    await operatorRow.getByRole('button', { name: 'Editar' }).click();
    await expect(page.getByRole('heading', { name: 'Identidade' })).toBeVisible();
    await expect(page.getByLabel('Nome a apresentar')).toHaveValue(OPERATOR.displayName);

    const assignments = cardByTitle(page, 'Funções atribuídas');
    const ownerRow = assignments.getByRole('row').filter({ hasText: 'Proprietário' });
    await expect(ownerRow).toContainText('Global');

    await ownerRow.getByRole('button', { name: 'Remover' }).click();
    await expect(page.getByText(/último Proprietário/)).toBeVisible();
    await expect(ownerRow).toContainText('Proprietário');
  });

  await test.step('recovery and data-management modals expose their confirmation gates', async () => {
    await page.getByTestId('tab-bar').getByRole('link', { name: 'Configurações' }).click();
    await expect(page.getByRole('heading', { name: 'Configurações' })).toBeVisible();

    await selectSettingsSection(page, 'Livros & Integridade', 'integridade');
    await page.getByRole('button', { name: 'Restaurar de cópia de segurança' }).click();
    const restore = page.getByRole('dialog', { name: 'Restaurar de cópia de segurança' });
    await expect(restore).toBeVisible();
    await expect(restore.getByRole('button', { name: 'Restaurar' })).toBeDisabled();
    await restore.getByLabel('Cópia de segurança (nome ou caminho)').fill('backup-e2e.zip');
    await expect(restore.getByRole('button', { name: 'Restaurar' })).toBeEnabled();
    await restore.getByRole('button', { name: 'Cancelar' }).click();
    await expect(restore).toHaveCount(0);

    await selectSettingsSection(page, 'Gestão de Dados', 'dados');
    await page.getByRole('button', { name: 'Limpar dados' }).click();
    const wipe = page.getByRole('dialog', { name: 'Limpar dados' });
    await expect(wipe).toBeVisible();
    await expect(wipe.getByLabel('Escreva LIMPAR DADOS para confirmar')).toBeVisible();
    await expect(wipe.getByLabel('Palavra-passe')).toBeVisible();
    await expect(wipe.getByText(/arquivo de exportação/)).toBeVisible();
    await expect(wipe.getByRole('button', { name: 'Limpar dados' })).toBeDisabled();
    await wipe.getByLabel('Escreva LIMPAR DADOS para confirmar').fill('LIMPAR');
    await expect(wipe.getByText('O texto não corresponde.')).toBeVisible();
    await wipe.getByLabel('Escreva LIMPAR DADOS para confirmar').fill('LIMPAR DADOS');
    await expect(wipe.getByRole('button', { name: 'Limpar dados' })).toBeDisabled();
    await wipe.getByRole('button', { name: 'Usar frase de recuperação' }).click();
    await expect(wipe.getByLabel('Frase de recuperação')).toBeVisible();
    await wipe.getByRole('button', { name: 'Cancelar' }).click();
    await expect(wipe).toHaveCount(0);

    await page.getByRole('button', { name: 'Reposição de fábrica' }).click();
    const factory = page.getByRole('dialog', { name: 'Reposição de fábrica' });
    await expect(factory).toBeVisible();
    await expect(factory.getByLabel('Exportar antes de apagar (recomendado)')).toBeChecked();
    await factory.getByLabel('Exportar antes de apagar (recomendado)').uncheck();
    await expect(
      factory.getByLabel('Tenho a minha própria cópia de segurança — não exportar'),
    ).toBeVisible();
    await expect(factory.getByRole('button', { name: 'Reposição de fábrica' })).toBeDisabled();
    await factory.getByRole('button', { name: 'Cancelar' }).click();
  });
});

test('data management recovery drill records isolated restore evidence without live restore', async ({
  page,
}) => {
  test.setTimeout(120_000);

  const backupPassphrase = 'browser-drill-passphrase-not-for-dom';
  const custodyLocation = 'Browser proof custody shelf';
  const operatorNotes = 'Browser proof recovery drill only';
  const liveRestoreCalls: string[] = [];

  await page.route('**/v1/backup', async (route, request) => {
    if (request.method() === 'POST' && apiPath(request.url()) === '/v1/backup') {
      await route.continue({
        headers: { ...request.headers(), 'content-type': 'application/json' },
        postData: JSON.stringify({ passphrase: backupPassphrase }),
      });
      return;
    }
    await route.continue();
  });

  page.on('request', (request) => {
    if (request.method() === 'POST' && apiPath(request.url()) === '/v1/ledger/recovery/restore') {
      liveRestoreCalls.push(request.url());
    }
  });

  await signInAt(page, '/configuracoes?sec=dados');
  await selectSettingsSection(page, 'Gestão de Dados', 'dados');
  // Gestão de Dados opens on «Armazenamento»; backup and recovery drills are a sibling sub-tab.
  await dataSubTab(page, 'Cópias e recuperação').click();
  await expect(dataSubTab(page, 'Cópias e recuperação')).toHaveAttribute('aria-pressed', 'true');

  const backupResponsePromise = page.waitForResponse(
    (response) => response.request().method() === 'POST' && apiPath(response.url()) === '/v1/backup',
  );
  const backupButton = page.getByRole('button', { name: 'Criar backup' });
  await expect(backupButton).toBeEnabled();
  await backupButton.click();
  const backupResponse = await backupResponsePromise;
  expect(backupResponse.ok()).toBeTruthy();
  const backupPath = backupPathFromManifest(await backupResponse.json());

  await page.getByLabel('Arquivo do backup para ensaio').fill(backupPath);
  await page.getByLabel('Chave do backup (opcional)').fill(backupPassphrase);
  await page.getByLabel('Local de custódia').fill(custodyLocation);
  await page.getByLabel('Notas do operador').fill(operatorNotes);

  const drillResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      apiPath(response.url()) === '/v1/backup/recovery-drills',
  );
  await page.getByRole('button', { name: 'Registar ensaio sem restauro' }).click();
  const drillResponse = await drillResponsePromise;
  expect(drillResponse.ok()).toBeTruthy();

  const drillBody = JSON.parse(drillResponse.request().postData() ?? '{}') as Record<
    string,
    unknown
  >;
  expect(drillBody).toMatchObject({
    archive: backupPath,
    passphrase: backupPassphrase,
    custody_location: custodyLocation,
    operator_notes: operatorNotes,
  });
  const drillReceipt = (await drillResponse.json()) as Record<string, unknown>;
  expect(drillReceipt.isolated_restore_verified).toBe(true);
  expect(drillReceipt.restore_executed).toBe(false);
  expect(drillReceipt.ledger_restored_appended).toBe(false);
  expect(drillReceipt.legal_archive_certified).toBe(false);

  const receipt = page.getByRole('note').filter({ hasText: 'Recibo de ensaio registado' });
  await expect(receipt).toBeVisible();
  // The receipt now shows a verdict summary; the evidence and its limits are behind the
  // «Evidência técnica» disclosure, so open it before asserting them.
  await receipt.locator('details.recovery-evidence > summary').click();
  await expect(receipt.getByText('Verificação isolada')).toBeVisible();
  await expect(receipt.getByText('Limites do recibo')).toBeVisible();
  await expect(receipt.getByText('Sem restauro ao vivo')).toBeVisible();
  await expect(receipt.getByText('Sem evento ledger.restored')).toBeVisible();
  await expect(receipt.getByText('Sem certificação legal ou de arquivo')).toBeVisible();

  await expect(page.getByLabel('Chave do backup (opcional)')).toHaveValue('');
  await expect(page.locator('body')).not.toContainText(backupPassphrase);
  expect(liveRestoreCalls).toEqual([]);
});

function settingsSectionButton(page: Page, name: string): Locator {
  return page
    .getByRole('group', { name: 'Secções de configuração' })
    .getByRole('button', { name, exact: true });
}

function apiPath(url: string): string {
  return new URL(url).pathname;
}

function backupPathFromManifest(manifest: unknown): string {
  const path =
    manifest && typeof manifest === 'object' ? (manifest as { path?: unknown }).path : undefined;
  if (typeof path !== 'string' || path.length === 0) {
    throw new Error('POST /v1/backup did not return a backup manifest path.');
  }
  return path;
}

async function selectSettingsSection(page: Page, name: string, section: string): Promise<void> {
  await settingsSectionButton(page, name).click();
  await expect(page).toHaveURL(new RegExp(`[?&]sec=${section}`));
}

function dataSubTab(page: Page, name: string): Locator {
  return page
    .getByRole('group', { name: 'Sub-secções da gestão de dados' })
    .getByRole('button', { name, exact: true });
}

function cardByTitle(page: Page, title: string): Locator {
  return page.locator('.panel').filter({ has: page.getByRole('heading', { name: title }) });
}

function userRow(page: Page, username: string): Locator {
  return page.getByRole('row').filter({ hasText: username });
}

async function switchCurrentUser(page: Page, displayName: string, password: string): Promise<void> {
  await page.getByTestId('session-trigger').click();
  await page.getByRole('menuitemradio', { name: new RegExp(escapeRegExp(displayName)) }).click();
  await page.locator('#picker-pw').fill(password);
  await page.getByRole('button', { name: 'Entrar' }).click();
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
