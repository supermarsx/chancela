import { expect, type Page } from './fixtures';

export async function fillOpenBookTermSignatories(page: Page): Promise<void> {
  await page.getByLabel('Nome do signatário').first().fill('Amélia Marques');
  await page.getByLabel('Qualidade').first().selectOption('Chair');

  await page.getByRole('button', { name: 'Adicionar signatário' }).click();
  await page.getByLabel('Nome do signatário').nth(1).fill('Rui Secretário');
  await page.getByLabel('Qualidade').nth(1).selectOption('Secretary');
}

export async function sealActForSigning(page: Page): Promise<void> {
  const seal = page.getByRole('button', { name: 'Selar ata' });
  await expect(seal).toBeEnabled();
  await seal.click();
  await expect(page.getByText('Ata selada', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toBeVisible();
}
