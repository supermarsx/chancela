import { expect, type Page } from './fixtures';

type OpenBookFixtureOptions = {
  entityId: string;
  purpose: string;
  openingDate: string;
};

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

/**
 * Create an already-open book for downstream browser journeys.
 *
 * The operator UI correctly uses the formal two-phase opening-term flow. These focused
 * document/signing tests are not opening-term tests, and the local E2E server has no
 * cryptographic term signer, so use the server's documented legacy one-shot compatibility
 * path to seed their prerequisite without waiting on a UI action that no longer exists.
 */
export async function createOpenBookFixture(
  page: Page,
  { entityId, purpose, openingDate }: OpenBookFixtureOptions,
): Promise<string> {
  const result = await page.evaluate(
    async ({ entityId: entity_id, purpose: bookPurpose, openingDate: opening_date }) => {
      const token = window.sessionStorage.getItem('chancela.session-token');
      const response = await window.fetch('/v1/books', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'X-Chancela-Session': token } : {}),
        },
        body: JSON.stringify({
          entity_id,
          kind: 'AssembleiaGeral',
          purpose: bookPurpose,
          numbering_scheme: 'Sequential',
          opening_date,
          required_signatories: [
            { name: 'Amélia Marques', capacity: 'Chair' },
            { name: 'Rui Secretário', capacity: 'Secretary' },
          ],
          one_shot: true,
        }),
      });
      return {
        status: response.status,
        body: await response.text(),
      };
    },
    { entityId, purpose, openingDate },
  );

  expect(result.status, result.body).toBe(201);
  const book = JSON.parse(result.body) as { id?: unknown };
  expect(book.id).toEqual(expect.any(String));
  return book.id as string;
}

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
  await expect(dialog.getByText('não validam a assinatura nem certificam o arquivo')).toBeVisible();

  const confirm = dialog.getByRole('button', { name: 'Confirmar e selar ata' });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel(/referência do original assinado manualmente foi registada/i).check();
  await expect(confirm).toBeDisabled();

  await dialog.getByRole('textbox', { name: /^Referência do original/u }).fill(storageReference);
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
