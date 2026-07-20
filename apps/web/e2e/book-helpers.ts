import { expect, type Page } from './fixtures';

type ManualSignatureSealOptions = {
  storageReference?: string;
  custodian?: string;
  note?: string;
};

type ManualSignatureSealResult = {
  requestBody: unknown;
  storageReference: string;
  custodian?: string;
  note?: string;
};

export async function fillOpenBookTermSignatories(page: Page): Promise<void> {
  await page.getByLabel('Nome do signatário').first().fill('Amélia Marques');
  await page.getByLabel('Qualidade').first().selectOption('Chair');

  await page.getByRole('button', { name: 'Adicionar signatário' }).click();
  await page.getByLabel('Nome do signatário').nth(1).fill('Rui Secretário');
  await page.getByLabel('Qualidade').nth(1).selectOption('Secretary');
}

export async function sealActForSigning(
  page: Page,
  options: ManualSignatureSealOptions = {},
): Promise<ManualSignatureSealResult> {
  const storageReference =
    options.storageReference ?? 'Arquivo E2E / Pasta 2026 / Original assinado';
  const custodian = options.custodian;
  const note = options.note;
  const seal = page.getByRole('button', { name: 'Selar ata' });
  await expect(seal).toBeEnabled();
  await seal.click();

  const dialog = page.getByRole('dialog', { name: 'Confirmar selagem manual' });
  await expect(dialog).toBeVisible();
  await expect(
    dialog.getByText('não validam a assinatura nem certificam o arquivo'),
  ).toBeVisible();

  const confirm = dialog.getByRole('button', { name: 'Confirmar e selar ata' });
  await expect(confirm).toBeDisabled();
  await dialog
    .getByLabel(/referência do original assinado manualmente foi registada/i)
    .check();
  await expect(confirm).toBeDisabled();

  await dialog
    .getByRole('textbox', { name: /^Referência do original/u })
    .fill(storageReference);
  if (custodian) {
    await dialog.getByLabel('Custodiante').fill(custodian);
  }
  if (note) {
    await dialog.getByLabel('Nota').fill(note);
  }

  await expect(confirm).toBeEnabled();
  const sealRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return request.method() === 'POST' && /^\/v1\/acts\/[^/]+\/seal$/u.test(url.pathname);
  });
  await confirm.click();
  const requestBody = (await sealRequest).postDataJSON();

  expect(requestBody).toMatchObject({
    manual_signature_original_reference: {
      storage_reference: storageReference,
      ...(custodian ? { custodian } : {}),
      ...(note ? { note } : {}),
    },
  });
  await expect(page.getByText('Ata selada', { exact: true }).first()).toBeVisible();
  await expect(page.getByText(storageReference, { exact: true })).toBeVisible();
  if (custodian) {
    await expect(page.getByText(custodian, { exact: true })).toBeVisible();
  }
  if (note) {
    await expect(page.getByText(note, { exact: true })).toBeVisible();
  }
  await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toBeVisible();

  return { requestBody, storageReference, custodian, note };
}
