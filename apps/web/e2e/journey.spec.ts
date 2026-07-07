/**
 * The end-to-end journey (plan t15 §2.5): one narrative through the composed system,
 * driven as a user in a real headless browser against the real server binary.
 *
 *   create a user → sign in via the topbar picker → create an entity → open a book →
 *   draft an ata → fill it, advance it to «Em assinatura», watch the compliance panel go
 *   clean, seal it → then confirm the Arquivo shows the hash chain intact with the
 *   signed-in username attributed as the actor on the sealed event.
 *
 * After sign-in every navigation is an in-app (client-side) route change, never a full
 * `page.goto` — the session token lives in the SPA's memory and a reload would drop it,
 * sending the ledger actor back to the system "api". Keeping to SPA navigation is what
 * proves the `X-Chancela-Session` → actor attribution end to end.
 */
import { test, expect } from '@playwright/test';

test('user → session → entity → book → ata → seal → Arquivo chain with actor', async ({ page }) => {
  const stamp = Date.now();
  const username = `amelia.marques${stamp}`;
  const displayName = `Amélia Marques ${stamp}`;

  // --- Create a user (no session needed yet) ---------------------------------
  await page.goto('/utilizadores');
  await page.getByLabel('Nome de utilizador').fill(username);
  await page.getByLabel('Nome a apresentar (opcional)').fill(displayName);
  await page.getByRole('button', { name: 'Criar utilizador' }).click();
  // The new account shows in the list.
  await expect(page.getByText(username, { exact: true })).toBeVisible();

  // --- Sign in via the topbar picker -----------------------------------------
  await page.getByTestId('session-trigger').click();
  await page.getByRole('menuitemradio', { name: new RegExp(displayName) }).click();
  await expect(page.getByTestId('session-trigger')).toContainText(displayName);

  // From here on: in-app navigation only, so the in-memory session token survives.
  const tab = (name: string) =>
    page.getByTestId('tab-bar').getByRole('link', { name, exact: true });

  // --- Create an entity ------------------------------------------------------
  await tab('Entidades').click();
  await page.getByRole('link', { name: 'Nova entidade' }).click();
  await expect(page).toHaveURL(/\/entidades\/nova$/);
  await page.getByLabel('Denominação').fill('Encosto Estratégico, S.A.');
  await page.getByLabel('NIPC').fill('503004642'); // fake-but-valid check digit
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
  await page.getByLabel('Local').fill('Sede social');
  await page.getByLabel('Referência de presenças').fill('Lista de presenças anexa');
  await page.getByLabel('Texto').fill('Aprovadas por unanimidade as contas do exercício de 2025.');
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
