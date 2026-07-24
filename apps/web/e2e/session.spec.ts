/**
 * Browser session checks for the auth-gated shell. The session token is intentionally
 * tab-scoped, so these tests verify reload persistence and explicit sign-out in a real browser.
 */
import { test, expect, type Page } from './fixtures';
import { OPERATOR, signInAt } from './auth';

test('reload retains the tab-scoped session', async ({ page }) => {
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  const tokenBeforeReload = await page.evaluate(() =>
    window.sessionStorage.getItem('chancela.session-token'),
  );
  expect(tokenBeforeReload).toBeTruthy();

  await page.reload();
  await expect(page.getByTestId('tab-bar')).toBeVisible();
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);
  await expect
    .poll(() => page.evaluate(() => window.sessionStorage.getItem('chancela.session-token')))
    .toBe(tokenBeforeReload);
});

test('wrong password is rejected inline without opening the app', async ({ page }) => {
  await signInAt(page, '/');
  await signOut(page);

  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
  await pickOperatorFromSignIn(page);
  await page.getByLabel('Palavra-passe', { exact: true }).fill('wrong-password');
  await page.getByRole('button', { name: 'Entrar' }).click();

  await expect(page.getByRole('alert')).toContainText('Utilizador ou palavra-passe incorretos.');
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

test('/users redirects to the users settings section after sign-in', async ({ page }) => {
  await signInAt(page, '/users');

  await expect(page).toHaveURL(/\/settings\/users$/);
  await expect(
    page
      .getByRole('group', { name: 'Áreas de utilizadores' })
      .getByRole('button', { name: 'Utilizadores', exact: true }),
  ).toBeVisible();
});

test('settings-created users require passwords and can sign in with that password', async ({
  page,
}) => {
  const suffix = Date.now().toString(36);
  const username = `e2e.auth.${suffix}`;
  const displayName = `E2E Auth ${suffix}`;
  const password = 'Forte-Cofre7!Z';

  await signInAt(page, '/settings/users');
  await expect(page.getByRole('heading', { name: 'Utilizadores' })).toBeVisible();

  await page.getByRole('link', { name: 'Novo utilizador' }).click();
  await expect(page).toHaveURL(/\/users\/new$/);

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

  await expect(page).toHaveURL(/\/users\/[0-9a-f-]{36}$/);

  await signOut(page);
  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
  await pickUserFromSignIn(page, displayName, username);
  await page.getByLabel('Palavra-passe', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page.getByTestId('session-trigger')).toContainText(displayName);
});

async function pickOperatorFromSignIn(page: Page): Promise<void> {
  await pickUserFromSignIn(page, OPERATOR.displayName, OPERATOR.username);
}

async function pickUserFromSignIn(
  page: Page,
  displayName: string,
  username: string,
): Promise<void> {
  const usernameInput = page.getByLabel('Utilizador', { exact: true });
  if (await usernameInput.isVisible()) {
    await usernameInput.fill(username);
  } else {
    await page.getByRole('listitem').filter({ hasText: displayName }).first().click();
  }
  await expect(page.getByLabel('Palavra-passe', { exact: true })).toBeVisible();
}

async function signOut(page: Page): Promise<void> {
  await page.getByTestId('session-trigger').click();
  await page.getByRole('button', { name: 'Terminar sessão' }).click();
}
