/**
 * Browser coverage for the first-launch auth boundary. This spec intentionally owns the
 * fresh-server path: it starts at `/`, verifies the guard redirects into onboarding, then
 * walks the mandatory password and recovery-phrase steps before entering the app.
 */
import { test, expect, type Page } from './fixtures';
import { OPERATOR, OPERATOR_PASSWORD } from './auth';

test('fresh install requires strong password onboarding, recovery phrase, then opens the app', async ({
  page,
}) => {
  await test.step('fresh install redirects to onboarding', async () => {
    await ensureFreshInstall(page);
    await expect(page.getByRole('button', { name: 'Começar' })).toBeVisible();
    await expect(page).toHaveURL(/\/bem-vindo$/);
    await expect(page.getByTestId('tab-bar')).toHaveCount(0);
  });

  await test.step('reach the mandatory password step', async () => {
    await page.getByRole('button', { name: 'Começar' }).click();
    await page.getByLabel('Nome da organização').fill('Cartório de Testes');
    await page.getByRole('button', { name: 'Seguinte' }).click();
    await page.getByLabel('Nome de utilizador').fill(OPERATOR.username);
    await page.getByLabel('Nome a apresentar (opcional)').fill(OPERATOR.displayName);
    await page.getByRole('button', { name: 'Seguinte' }).click();
    await expect(page.getByRole('heading', { name: 'Palavra-passe obrigatória' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Ignorar' })).toHaveCount(0);
  });

  await test.step('weak, common, and username-containing passwords are blocked', async () => {
    await expectPasswordBlocked(page, 'abc', 'Pelo menos 10 caracteres');
    await expectPasswordBlocked(page, 'Password123!', 'Não é uma palavra-passe comum');
    await expectPasswordBlocked(page, 'Operador-9!Aa', 'Não contém o nome de utilizador');
  });

  await test.step('a strong password is accepted', async () => {
    await page.getByLabel('Palavra-passe', { exact: true }).fill(OPERATOR_PASSWORD);
    await page.getByLabel('Confirmar palavra-passe').fill(OPERATOR_PASSWORD);
    await expect(page.getByText('As palavras-passe coincidem.')).toBeVisible();
    const next = page.getByRole('button', { name: 'Seguinte' });
    await expect(next).toBeEnabled();
    await next.click();
    await expect(
      page.getByRole('heading', { name: 'Frase de recuperação obrigatória' }),
    ).toBeVisible();
  });

  await test.step('recovery phrase is required and shown once', async () => {
    const enter = page.getByRole('button', { name: 'Entrar no Chancela' });
    await expect(enter).toBeDisabled();

    await page.getByRole('button', { name: 'Gerar frase de recuperação' }).click();
    await expect(page.getByText('Guarde esta frase agora')).toBeVisible();
    await expect(page.locator('.access-manager__recovery-phrase code')).toHaveText(/.{32,}/);
    await expect(enter).toBeEnabled();
  });

  await test.step('finishing opens the authenticated app', async () => {
    await page.getByRole('button', { name: 'Entrar no Chancela' }).click();
    await expect(page.getByTestId('tab-bar')).toBeVisible();
    await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);
    await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();
  });
});

async function expectPasswordBlocked(
  page: Page,
  password: string,
  failedRule: string,
): Promise<void> {
  await page.getByLabel('Palavra-passe', { exact: true }).fill(password);
  await page.getByLabel('Confirmar palavra-passe').fill(password);
  await expect(page.getByText('As palavras-passe coincidem.')).toBeVisible();
  await expect(
    page.locator('.password-policy__item--unmet', { hasText: failedRule }),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Seguinte' })).toBeDisabled();
}

async function ensureFreshInstall(page: Page): Promise<void> {
  await page.goto('/');
  const welcome = page.getByRole('button', { name: 'Começar' });
  const signIn = page.getByRole('heading', { name: 'Iniciar sessão' });
  await expect(welcome.or(signIn)).toBeVisible();
  if (await welcome.isVisible()) return;

  const origin = new URL(page.url()).origin;
  const rosterResponse = await page.request.get(`${origin}/v1/session/roster`);
  if (!rosterResponse.ok()) {
    throw new Error(`session roster failed: ${await rosterResponse.text()}`);
  }
  const roster = (await rosterResponse.json()) as {
    users: Array<{ id: string; username: string }>;
  };
  const operator = roster.users.find((user) => user.username === OPERATOR.username);
  expect(
    operator,
    `Cannot reset to first launch: ${OPERATOR.username} is not in the roster`,
  ).toBeTruthy();

  const sessionResponse = await page.request.post(`${origin}/v1/session`, {
    data: { user_id: operator!.id, password: OPERATOR_PASSWORD },
  });
  if (!sessionResponse.ok()) {
    throw new Error(`session create failed: ${await sessionResponse.text()}`);
  }
  const session = (await sessionResponse.json()) as { token: string };

  const resetResponse = await page.request.post(`${origin}/v1/data/reset`, {
    headers: { 'X-Chancela-Session': session.token },
    data: {
      scope: 'backend_factory',
      confirm_phrase: 'REPOR FÁBRICA',
      export_first: false,
      skip_export_confirm: true,
      reauth: { password: OPERATOR_PASSWORD },
      actor: 'e2e:first-launch',
    },
  });
  if (!resetResponse.ok()) {
    throw new Error(`factory reset failed: ${await resetResponse.text()}`);
  }

  await page.goto('/');
  await expect(welcome).toBeVisible();
}
