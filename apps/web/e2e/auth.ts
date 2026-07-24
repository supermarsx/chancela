/**
 * Shared E2E auth helper (plan t44). Since t41/t44 the app is auth-gated: a fresh server
 * boots into the onboarding wizard, and every subsequent (signed-out) page load lands on
 * the sign-in surface. Every browser spec must therefore authenticate before it can reach
 * the app chrome.
 *
 * The suite runs serially against ONE shared server (`workers: 1`), so the first spec to
 * run onboards the shared **operador** (now with the mandatory password + recovery phrase);
 * later specs — and each fresh page, whose in-memory token is gone — find users already
 * exist and sign in by typing the identifier (t33-e2: there is no roster to pick from, and
 * the server resolves the username). {@link signInAt} handles both paths, so any spec can
 * call it regardless of order.
 */
import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

export const OPERATOR = { username: 'operador', displayName: 'Operador' };
export const OPERATOR_PASSWORD = 'Str0ng!Vault9';

/**
 * Navigate to `route` and end up signed in as the shared operator, on that route.
 * Fresh server → the guard redirects to `/welcome` and we complete the wizard; otherwise
 * the sign-in surface is showing and we pick the operator.
 */
export async function signInAt(page: Page, route = '/'): Promise<void> {
  await page.goto(route);
  if (await settledOnWizard(page)) {
    await completeOnboarding(page);
    if (route !== '/') {
      // Land on the originally requested route. The tab-scoped session survives navigation.
      await page.goto(route);
      await expect(page.getByTestId('tab-bar')).toBeVisible();
    }
  } else {
    await pickOperator(page);
  }
}

/**
 * Wait for the auth guard to settle into EITHER the wizard (fresh server → redirected to
 * `/welcome`) or the sign-in surface, then report which. Racing the two locators avoids a
 * flake where the client-side redirect has not yet fired right after `page.goto`.
 */
async function settledOnWizard(page: Page): Promise<boolean> {
  const welcome = page.getByRole('button', { name: 'Começar' });
  const signIn = page.getByRole('heading', { name: 'Iniciar sessão' });
  await expect(welcome.or(signIn)).toBeVisible();
  return welcome.isVisible();
}

/** Complete the first-run wizard: organization → operator → password → recovery phrase. */
async function completeOnboarding(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Começar' }).click();
  await page.getByLabel('Nome da organização').fill('Cartório de Testes');
  await page.getByRole('button', { name: 'Seguinte' }).click();
  await page.getByLabel('Nome de utilizador').fill(OPERATOR.username);
  await page.getByLabel('Nome a apresentar (opcional)').fill(OPERATOR.displayName);
  await page.getByRole('button', { name: 'Seguinte' }).click();
  await expect(page.getByRole('heading', { name: 'Palavra-passe obrigatória' })).toBeVisible();
  await page.getByLabel('Palavra-passe', { exact: true }).fill(OPERATOR_PASSWORD);
  await page.getByLabel('Confirmar palavra-passe').fill(OPERATOR_PASSWORD);
  const passwordNext = page.getByRole('button', { name: 'Seguinte' });
  await expect(passwordNext).toBeEnabled();
  await passwordNext.click();
  await expect(
    page.getByRole('heading', { name: 'Frase de recuperação obrigatória' }),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Entrar no Chancela' })).toBeDisabled();
  await page.getByRole('button', { name: 'Gerar frase de recuperação' }).click();
  await expect(page.locator('.access-manager__recovery-phrase code')).toBeVisible();
  await page.getByRole('button', { name: 'Entrar no Chancela' }).click();
  // Landed in the app.
  await expect(page.getByTestId('tab-bar')).toBeVisible();
}

/** On the sign-in surface, enter the operator identifier and shared password. */
async function pickOperator(page: Page): Promise<void> {
  const username = page.getByLabel('Utilizador', { exact: true });
  if (await username.isVisible()) {
    await username.fill(OPERATOR.username);
  } else {
    await page.getByRole('listitem').filter({ hasText: OPERATOR.displayName }).first().click();
  }
  const password = page.getByLabel('Palavra-passe', { exact: true });
  await expect(password).toBeVisible();
  await password.fill(OPERATOR_PASSWORD);
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page.getByTestId('tab-bar')).toBeVisible();
}
