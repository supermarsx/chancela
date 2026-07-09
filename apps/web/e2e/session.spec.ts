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

async function pickOperatorFromSignIn(page: Page): Promise<void> {
  await page.getByRole('listitem').filter({ hasText: OPERATOR.displayName }).first().click();
  await expect(page.getByLabel('Palavra-passe', { exact: true })).toBeVisible();
}
