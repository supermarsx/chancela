/**
 * Focused browser coverage for WFL-23/SIG-03 manual-signature original-reference sealing.
 *
 * This drives the real browser UI against the composed server: the seal action must require a
 * local reference to the signed original, send that metadata in the seal request, and display it
 * again from the sealed act after a fresh sign-in. The reference is custody metadata only; it is
 * not a qualified/eIDAS/legal signature validity claim.
 */
import { expect, test, type Locator, type Page } from './fixtures';
import { OPERATOR, signInAt } from './auth';
import { fillOpenBookTermSignatories, sealActForSigning } from './book-helpers';

test('manual sealing requires, captures, and preserves the signed-original reference', async ({
  page,
}) => {
  test.setTimeout(180_000);

  const suffix = Date.now().toString(36);
  const entityName = `Manual Original E2E ${suffix}, S.A.`;
  const actTitle = `Ata original manual ${suffix}`;
  const storageReference = `Arquivo manual E2E / ${suffix} / Original assinado`;
  const custodian = 'Secretariado de atas';
  const note = 'Original em papel localizado; metadados sem validação jurídica.';

  await signInAt(page, '/');
  await page.reload();
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  await createSigningReadyAct(page, {
    actTitle,
    entityName,
    nipc: validNipc(Date.now()),
    suffix,
  });
  await advanceToSigning(page);

  const seal = await sealActForSigning(page, {
    storageReference,
    custodian,
    note,
  });
  expect(seal.requestBody).toMatchObject({
    manual_signature_original_reference: {
      storage_reference: storageReference,
      custodian,
      note,
    },
  });

  const sealedPath = new URL(page.url()).pathname;
  await signInAt(page, sealedPath);
  await expect(page).toHaveURL(new RegExp(`${escapeRegExp(sealedPath)}$`));
  // «Ata selada» is also the title of the follow-ups panel note, so target the act-level
  // sealed banner by its body copy.
  await expect(
    page.getByRole('note').filter({ hasText: 'O conteúdo está congelado e encadeado no registo' }),
  ).toBeVisible();
  await expect(page.getByText('Original assinado', { exact: true })).toBeVisible();
  await expect(page.getByText(storageReference, { exact: true })).toBeVisible();
  await expect(page.getByText(custodian, { exact: true })).toBeVisible();
  await expect(page.getByText(note, { exact: true })).toBeVisible();
});

async function createSigningReadyAct(
  page: Page,
  {
    actTitle,
    entityName,
    nipc,
    suffix,
  }: { actTitle: string; entityName: string; nipc: string; suffix: string },
): Promise<void> {
  await tab(page, 'Entidades').click();
  await page.getByRole('link', { name: 'Nova entidade' }).click();
  await expect(page).toHaveURL(/\/entities\/new$/);
  await page.getByLabel('Denominação').fill(entityName);
  await page.getByLabel('NIPC', { exact: true }).fill(nipc);
  await page.getByLabel('Sede').fill('Lisboa');
  await page.getByLabel('Forma jurídica').selectOption('SociedadeAnonima');
  await page.getByRole('button', { name: 'Criar entidade' }).click();
  await expect(page).toHaveURL(/\/entities\/[0-9a-f-]{36}$/);

  await page.getByRole('link', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/books\/new\?entidade=[0-9a-f-]{36}$/);
  await page.getByLabel('Finalidade').fill(`Atas com original manual ${suffix}`);
  await page.getByLabel('Data de abertura').fill('2026-04-02');
  await fillOpenBookTermSignatories(page);
  await page.getByRole('button', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/books\/[0-9a-f-]{36}$/);

  await page.getByRole('link', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/books\/[0-9a-f-]{36}\/new-act$/);
  await page.getByLabel('Título da ata').fill(actTitle);
  await page.getByRole('button', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/acts\/[0-9a-f-]{36}$/);

  await fillSigningReadyAta(page);
  await page.getByRole('button', { name: 'Guardar' }).click();
  await expect(page.getByRole('button', { name: 'A guardar…' })).toHaveCount(0);
}

async function fillSigningReadyAta(page: Page): Promise<void> {
  await page.getByLabel('Data da reunião').fill('2026-04-30');
  await page.getByLabel('Hora da reunião').fill('10:00');
  // `getByLabel('Local')` is a substring match and also hits the convening-evidence group
  // («Evidência local de expedição…»); target the field by role + accessible name instead.
  await page.getByRole('textbox', { name: 'Local', exact: true }).fill('Sede social');
  await page.getByLabel('Referência de presenças').fill('Lista de presenças MANUAL-E2E');
  await page.getByLabel('Presentes').fill('3');
  await page.getByLabel('Representados').fill('0');
  await page.getByLabel('Presidente da mesa').fill('Amélia Marques');

  await page.getByRole('button', { name: 'Adicionar secretário' }).click();
  await page.getByLabel('Nome do secretário').fill('Rui Secretário');

  await page.getByRole('button', { name: 'Adicionar ponto' }).click();
  await page.getByLabel('Ponto da ordem de trabalhos').fill('Aprovação de contas');

  await page.getByRole('button', { name: 'Adicionar deliberação' }).click();
  await page.getByLabel('Texto da deliberação').fill('Aprovadas as contas de 2025.');
  await page.getByLabel('Ponto associado').selectOption('1');
  await page.getByLabel('Resultado da votação').selectOption('Unanimous');

  await page
    .getByLabel('Texto', { exact: true })
    .fill('Aprovadas por unanimidade as contas do exercício de 2025.');

  await page.getByRole('button', { name: 'Adicionar signatário' }).click();
  await page.getByLabel('Nome do signatário').fill('Amélia Marques');
  await page.getByLabel('Qualidade').selectOption('Chair');
}

async function advanceToSigning(page: Page): Promise<void> {
  for (let i = 0; i < 5; i += 1) {
    const advance = page.getByRole('button', { name: /^Avançar para/ });
    await expect(advance).toBeEnabled();
    await advance.click();
    await expect(page.getByRole('button', { name: 'A avançar…' })).toHaveCount(0);
  }
  await expect(page.getByRole('button', { name: /^Avançar para/ })).toHaveCount(0);
  await expect(page.getByText('Conforme', { exact: true })).toBeVisible();
}

function tab(page: Page, name: string): Locator {
  return page.getByTestId('tab-bar').getByRole('link', { name, exact: true });
}

function validNipc(seed: number): string {
  const body = `5${String(Math.abs(seed) % 10_000_000).padStart(7, '0')}`;
  const sum = [...body].reduce((acc, digit, index) => acc + Number(digit) * (9 - index), 0);
  const remainder = sum % 11;
  const check = remainder < 2 ? 0 : 11 - remainder;
  return `${body}${check}`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
