import { expect, test } from './fixtures';
import { signInAt } from './auth';

test('operator can reach every operations area and manage a real tenant group', async ({
  page,
}) => {
  await signInAt(page, '/');

  await page.getByRole('link', { name: 'Entidades' }).click();
  await page.getByRole('link', { name: 'Nova entidade' }).click();
  await page.getByLabel('Denominação').fill('Operações E2E, S.A.');
  await page.getByLabel('NIPC', { exact: true }).fill('503004642');
  await page.getByLabel('Sede').fill('Lisboa');
  await page.getByLabel('Forma jurídica').selectOption('SociedadeAnonima');
  await page.getByRole('button', { name: 'Criar entidade' }).click();
  await expect(page).toHaveURL(/\/entities\/[0-9a-f-]{36}$/u);

  await page.getByRole('link', { name: 'Administração' }).click();
  await expect(page).toHaveURL(/\/admin/u);
  await expect(page.getByRole('heading', { name: 'Administração', exact: true })).toBeVisible();
  await page
    .getByRole('group', { name: 'Áreas de administração' })
    .getByRole('button', { name: 'Grupos e bibliotecas', exact: true })
    .click();
  await expect(page).toHaveURL(/\/admin\/groups/u);
  await expect(page.getByLabel('Organização')).toContainText('Operações E2E, S.A.');

  await page.getByLabel('Nome', { exact: true }).fill('Grupo operacional E2E');
  await page.getByLabel('Descrição', { exact: true }).fill('Prova browser de grupos e bibliotecas');
  const created = page.waitForResponse(
    (response) =>
      response.request().method() === 'POST' &&
      /\/v1\/tenants\/[^/]+\/groups$/u.test(new URL(response.url()).pathname),
  );
  await page.getByRole('button', { name: 'Criar grupo' }).click();
  expect((await created).status()).toBe(201);

  const groupRow = page.getByRole('row').filter({ hasText: 'Grupo operacional E2E' });
  await expect(groupRow).toBeVisible();
  await groupRow.getByRole('button', { name: 'Abrir' }).click();
  await expect(page.getByRole('heading', { name: 'Detalhe do grupo' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Membros do grupo' })).toBeVisible();
  await expect(
    page.getByRole('heading', { name: 'Bibliotecas de minutas partilhadas' }),
  ).toBeVisible();

  await page.getByRole('button', { name: 'Conectores e trabalhos' }).click();
  await expect(page).toHaveURL(/\/admin\/connectors/u);
  await expect(page.getByText('Apenas referências de credenciais')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Trabalhos duráveis' })).toBeVisible();

  await page.getByRole('button', { name: 'Repositórios ZK' }).click();
  await expect(page).toHaveURL(/\/admin\/repositories/u);
  await expect(page.getByText('Zero knowledge é uma opção explícita')).toBeVisible();
  await page.getByLabel('Modo de cifragem').first().selectOption('zero_knowledge');
  await expect(page.getByText(/Não cria, recebe nem reconstrói partes secretas/u)).toBeVisible();
});
