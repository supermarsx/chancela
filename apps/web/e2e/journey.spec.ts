/**
 * The end-to-end journey (plan t15 §2.5, t44): one narrative through the composed system,
 * driven as a user in a real headless browser against the real server binary.
 *
 *   onboard the first user + sign in (the app is auth-gated since t41/t44) → create an
 *   entity → open a book → draft an ata → fill it, advance it to «Em assinatura», watch the
 *   compliance panel go clean, seal it → then confirm the Arquivo shows the hash chain
 *   intact with the signed-in username attributed as the actor on the sealed event.
 *
 * After sign-in every navigation is an in-app (client-side) route change, never a full
 * `page.goto` — the session token lives in the SPA's memory and a reload would drop it,
 * sending the ledger actor back to the sign-in surface. Keeping to SPA navigation is what
 * proves the `X-Chancela-Session` → actor attribution end to end.
 */
import { test, expect } from './fixtures';
import { OPERATOR, signInAt } from './auth';

test('onboard → session → entity → book → ata → seal → Arquivo chain with actor', async ({
  page,
}) => {
  // --- Onboard the first user + sign in (the app requires a session) ----------
  // On a fresh server this runs the /bem-vindo wizard (creates the passwordless operator);
  // it lands signed in at the app home.
  await signInAt(page, '/');
  const username = OPERATOR.username;
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  // From here on: in-app navigation only, so the in-memory session token survives.
  const tab = (name: string) =>
    page.getByTestId('tab-bar').getByRole('link', { name, exact: true });

  // --- Create an entity ------------------------------------------------------
  await tab('Entidades').click();
  await page.getByRole('link', { name: 'Nova entidade' }).click();
  await expect(page).toHaveURL(/\/entidades\/nova$/);
  await page.getByLabel('Denominação').fill('Encosto Estratégico, S.A.');
  // Exact match: the "NIPC sem validação" override switch also contains "NIPC".
  await page.getByLabel('NIPC', { exact: true }).fill('503004642'); // fake-but-valid check digit
  await page.getByLabel('Sede').fill('Lisboa');
  await page.getByLabel('Forma jurídica').selectOption('SociedadeAnonima');
  await page.getByRole('button', { name: 'Criar entidade' }).click();
  // Navigates to the new entity's detail page.
  await expect(page).toHaveURL(/\/entidades\/[0-9a-f-]{36}$/);

  // --- Open a book -----------------------------------------------------------
  await tab('Livros').click();
  await page.getByRole('link', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/livros\/novo$/);
  await page.getByLabel('Finalidade').fill('Atas da Assembleia Geral');
  await page.getByLabel('Data de abertura').fill('2026-01-15');
  await page.getByLabel('Signatários do termo de abertura').fill('Presidente da Mesa\nSecretário');
  await page.getByRole('button', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}$/);

  // --- Draft an ata ----------------------------------------------------------
  await page.getByRole('link', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}\/nova-ata$/);
  await page.getByLabel('Título da ata').fill('Ata da Assembleia Geral Anual');
  await page.getByRole('button', { name: 'Nova ata' }).click();
  // Lands in the ata editor.
  await expect(page).toHaveURL(/\/atas\/[0-9a-f-]{36}$/);

  // --- Fill the ata and save -------------------------------------------------
  await page.getByLabel('Data da reunião').fill('2026-03-30');
  await page.getByLabel('Hora da reunião').fill('15:00');
  await page.getByLabel('Local').fill('Sede social');
  await page.getByLabel('Referência de presenças').fill('Lista de presenças anexa');
  await page.getByLabel('Presentes').fill('3');
  await page.getByLabel('Representados').fill('0');
  // The mesa presidente is the seal-unblocker for a commercial company (csc-art63/v2):
  // without it the compliance panel keeps a blocking «CSC-63/mesa-presidente» error.
  await page.getByLabel('Presidente da mesa').fill('Amélia Marques');
  // A secretary clears the advisory «CSC-63/mesa-secretarios» so the panel reads «Conforme».
  await page.getByRole('button', { name: 'Adicionar secretário' }).click();
  await page.getByLabel('Nome do secretário').fill('Rui Secretário');
  await page.getByLabel('Texto').fill('Aprovadas por unanimidade as contas do exercício de 2025.');

  // Minimal structured content: one agenda point and one per-item deliberation with a
  // unanimous vote, exercising the new mesa/agenda/deliberação editors.
  await page.getByRole('button', { name: 'Adicionar ponto' }).click();
  await page.getByLabel('Ponto da ordem de trabalhos').fill('Aprovação de contas');
  await page.getByRole('button', { name: 'Adicionar deliberação' }).click();
  await page.getByLabel('Texto da deliberação').fill('Aprovadas as contas do exercício de 2025.');
  await page.getByLabel('Resultado da votação').selectOption('Unanimous');

  await page.getByRole('button', { name: 'Guardar' }).click();
  await expect(page.getByRole('button', { name: 'A guardar…' })).toHaveCount(0);

  // --- Advance Draft → … → «Em assinatura» (five steps) ----------------------
  for (let i = 0; i < 5; i++) {
    const advance = page.getByRole('button', { name: /^Avançar para/ });
    await expect(advance).toBeEnabled();
    await advance.click();
    await expect(page.getByRole('button', { name: 'A avançar…' })).toHaveCount(0);
  }
  // At «Em assinatura» there is no further advance step.
  await expect(page.getByRole('button', { name: /^Avançar para/ })).toHaveCount(0);

  // --- Compliance goes clean and the seal unlocks ----------------------------
  await expect(page.getByText('Conforme', { exact: true })).toBeVisible();
  const sealButton = page.getByRole('button', { name: 'Selar ata' });
  await expect(sealButton).toBeEnabled();

  // --- Seal ------------------------------------------------------------------
  await sealButton.click();
  const ataNumber = page.getByTestId('ata-number');
  await expect(ataNumber).toBeVisible();
  await expect(ataNumber).toContainText(/\d/); // an ata number was assigned
  await expect(page.getByText('Ata selada', { exact: true })).toBeVisible();

  // --- Arquivo: the chain is intact and the actor is the signed-in user ------
  await tab('Arquivo').click();
  await expect(page).toHaveURL(/\/arquivo$/);
  await expect(page.getByText(/^Cadeia verificada/)).toBeVisible();
  // The sealed event is present and attributed to the signed-in username.
  await expect(page.getByText('act.sealed', { exact: true }).first()).toBeVisible();
  await expect(page.locator('td', { hasText: username }).first()).toBeVisible();
});
