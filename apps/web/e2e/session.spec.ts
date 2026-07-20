/**
 * Browser session checks for the auth-gated shell. The session token is intentionally
 * memory-only, so these tests verify reload/sign-out behavior in a real browser.
 */
import { test, expect, type Page } from './fixtures';
import { OPERATOR, OPERATOR_PASSWORD, signInAt } from './auth';

test('reload drops the in-memory session and password sign-in restores the app', async ({
  page,
}) => {
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
  await expect(page.getByTestId('tab-bar')).toHaveCount(0);

  await pickOperatorFromSignIn(page);
  await page.getByLabel('Palavra-passe', { exact: true }).fill(OPERATOR_PASSWORD);
  await page.getByRole('button', { name: 'Entrar' }).click();

  await expect(page.getByTestId('tab-bar')).toBeVisible();
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);
});

test('wrong password is rejected inline without opening the app', async ({ page }) => {
  await signInAt(page, '/');
  await page.reload();

  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
  await pickOperatorFromSignIn(page);
  await page.getByLabel('Palavra-passe', { exact: true }).fill('wrong-password');
  await page.getByRole('button', { name: 'Entrar' }).click();

  await expect(page.getByRole('alert')).toContainText('Palavra-passe incorreta.');
  await expect(page.getByTestId('tab-bar')).toHaveCount(0);
});

test('sign out returns to the sign-in surface', async ({ page }) => {
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  await page.getByTestId('session-trigger').click();
  await page.getByRole('button', { name: 'Terminar sessão' }).click();

  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
  await expect(page.getByTestId('tab-bar')).toHaveCount(0);
});

test('/utilizadores redirects to the users settings section after sign-in', async ({ page }) => {
  await signInAt(page, '/utilizadores');

  await expect(page).toHaveURL(/\/configuracoes\?sec=utilizadores$/);
  await expect(page.getByRole('button', { name: 'Utilizadores' })).toBeVisible();
});

test('settings-created users require passwords and switch current user with that password', async ({
  page,
}) => {
  const suffix = Date.now().toString(36);
  const username = `e2e.auth.${suffix}`;
  const displayName = `E2E Auth ${suffix}`;
  const password = 'Forte-Cofre7!Z';

  await signInAt(page, '/configuracoes?sec=utilizadores');
  await expect(page.getByRole('heading', { name: 'Utilizadores' })).toBeVisible();

  await page.getByRole('link', { name: 'Novo utilizador' }).click();
  await expect(page).toHaveURL(/\/configuracoes\?sec=utilizadores&user=novo$/);

  await page.getByLabel('Nome de utilizador').fill(username);
  await page.getByLabel('Nome a apresentar (opcional)').fill(displayName);
  const create = page.getByRole('button', { name: 'Criar utilizador' });
  await expect(create).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Ignorar' })).toHaveCount(0);

  await page.getByLabel('Nova palavra-passe').fill(password);
  await expect(create).toBeDisabled();
  await page.getByLabel('Confirmar palavra-passe').fill(`${password}x`);
  await expect(create).toBeDisabled();
  await page.getByLabel('Confirmar palavra-passe').fill(password);
  await expect(create).toBeEnabled();
  await create.click();

  await expect(page).toHaveURL(/\/configuracoes\?sec=utilizadores&user=[0-9a-f-]{36}$/);
  await expect(page.getByLabel('Nome a apresentar')).toHaveValue(displayName);
  await expect(userRow(page, username)).toContainText('Palavra-passe');

  const passwordBlock = page.locator('section#acesso .access-manager__block').first();
  await expect(passwordBlock).toContainText('Definida');
  await expect(passwordBlock.getByRole('button', { name: 'Alterar' })).toBeVisible();
  await expect(passwordBlock.getByRole('button', { name: 'Remover' })).toHaveCount(0);
  await expect(passwordBlock.getByRole('button', { name: 'Definir palavra-passe' })).toHaveCount(
    0,
  );

  await switchCurrentUser(page, displayName, password);
  await expect(page.getByTestId('session-trigger')).toContainText(displayName);

  await signOut(page);
  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
  await pickUserFromSignIn(page, displayName);
  await page.getByLabel('Palavra-passe', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page.getByTestId('session-trigger')).toContainText(displayName);
});

async function pickOperatorFromSignIn(page: Page): Promise<void> {
  await pickUserFromSignIn(page, OPERATOR.displayName);
}

async function pickUserFromSignIn(page: Page, displayName: string): Promise<void> {
  await page.getByRole('listitem').filter({ hasText: displayName }).first().click();
  await expect(page.getByLabel('Palavra-passe', { exact: true })).toBeVisible();
}

function userRow(page: Page, username: string) {
  return page.getByRole('row').filter({ hasText: username });
}

async function switchCurrentUser(page: Page, displayName: string, password: string): Promise<void> {
  await page.getByTestId('session-trigger').click();
  await page.getByRole('menuitemradio', { name: new RegExp(escapeRegExp(displayName)) }).click();
  await page.locator('#picker-pw').fill(password);
  await page.getByRole('button', { name: 'Entrar' }).click();
}

async function signOut(page: Page): Promise<void> {
  await page.getByTestId('session-trigger').click();
  await page.getByRole('button', { name: 'Terminar sessão' }).click();
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
