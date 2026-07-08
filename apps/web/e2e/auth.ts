/**
 * Shared E2E auth helper (plan t44). Since t41/t44 the app is auth-gated: a fresh server
 * boots into the onboarding wizard, and every subsequent (signed-out) page load lands on
 * the sign-in surface. Every browser spec must therefore authenticate before it can reach
 * the app chrome.
 *
 * The suite runs serially against ONE shared server (`workers: 1`), so the first spec to
 * run onboards the shared **operador** (a passwordless first user); later specs — and each
 * fresh page, whose in-memory token is gone — find users already exist and just pick the
 * operator from the roster (a passwordless one-click sign-in). {@link signInAt} handles
 * both paths, so any spec can call it regardless of order.
 */
import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';

export const OPERATOR = { username: 'operador', displayName: 'Operador' };

/**
 * Navigate to `route` and end up signed in as the shared operator, on that route.
 * Fresh server → the guard redirects to `/bem-vindo` and we complete the wizard; otherwise
 * the sign-in surface is showing and we pick the operator.
 */
export async function signInAt(page: Page, route = '/'): Promise<void> {
  await page.goto(route);
  if (await settledOnWizard(page)) {
    await completeOnboarding(page);
    if (route !== '/') {
      // Land on the originally requested route; a fresh load is signed out again.
      await page.goto(route);
      await pickOperator(page);
    }
  } else {
    await pickOperator(page);
  }
}

/**
 * Wait for the auth guard to settle into EITHER the wizard (fresh server → redirected to
 * `/bem-vindo`) or the sign-in surface, then report which. Racing the two locators avoids a
 * flake where the client-side redirect has not yet fired right after `page.goto`.
 */
async function settledOnWizard(page: Page): Promise<boolean> {
  const welcome = page.getByRole('button', { name: 'Começar' });
  const signIn = page.getByRole('heading', { name: 'Iniciar sessão' });
  await expect(welcome.or(signIn)).toBeVisible();
  return welcome.isVisible();
}

/** Complete the first-run wizard: organization → passwordless operator → skip password. */
async function completeOnboarding(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Começar' }).click();
  await page.getByLabel('Nome da organização').fill('Cartório de Testes');
  await page.getByRole('button', { name: 'Seguinte' }).click();
  await page.getByLabel('Nome de utilizador').fill(OPERATOR.username);
  await page.getByLabel('Nome a apresentar (opcional)').fill(OPERATOR.displayName);
  await page.getByRole('button', { name: 'Seguinte' }).click();
  // Skip the optional password (a passwordless operator signs in with one click later).
  await page.getByRole('button', { name: 'Ignorar' }).click();
  // Landed in the app.
  await expect(page.getByTestId('tab-bar')).toBeVisible();
}

/** On the sign-in surface, pick the passwordless operator (one click signs in). */
async function pickOperator(page: Page): Promise<void> {
  await page.getByText(OPERATOR.displayName, { exact: true }).click();
  await expect(page.getByTestId('tab-bar')).toBeVisible();
}
