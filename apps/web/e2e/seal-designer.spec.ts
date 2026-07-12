/**
 * Browser E2E for the visual seal designer (t67-e12).
 *
 * Creates and seals its own act, opens the signing panel, and drives the seal designer: opening
 * it from the "Posicionar selo visível" affordance, placing a seal with the precise numeric
 * position fields, and confirming the applied-seal summary. It then starts a Chave Móvel Digital
 * sign and captures the request body to prove the placed seal `{page,x,y,w,h}` actually reaches
 * the sign request (the designer -> SigningPanel -> API wiring). The suite is serial and runs
 * against the one shared server with the shared auth helper.
 */
import { expect, test, type Locator, type Page } from './fixtures';
import { OPERATOR, signInAt } from './auth';
import { fillOpenBookTermSignatories, sealActForSigning } from './book-helpers';

test('seal designer: place a visible seal and carry it into the sign request', async ({ page }) => {
  test.setTimeout(180_000);

  const suffix = Date.now().toString(36);
  const entityName = `Selo E2E ${suffix} & Filhos, S.A.`;
  const actTitle = `Ata selo ${suffix}`;
  const nipc = validNipc(Date.now());

  // Capture the CMD initiate body so we can assert the seal rides along; fail it closed so no
  // real signing is attempted (the point is the request shape, not a completed signature).
  let cmdInitiateBody: Record<string, unknown> | null = null;
  await page.route('**/v1/acts/*/signature/cmd/initiate', async (route) => {
    cmdInitiateBody = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      status: 422,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'PIN de teste rejeitado (E2E).' }),
    });
  });

  await signInAt(page, '/');
  await page.reload();
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  await createAct(page, { actTitle, entityName, nipc, suffix });
  await fillAtaForDocument(page);
  await page.getByRole('button', { name: 'Guardar' }).click();
  await expect(page.getByRole('button', { name: 'A guardar…' })).toHaveCount(0);
  await advanceToSigning(page);
  await sealActForSigning(page);

  await test.step('the seal affordance opens the designer', async () => {
    const open = page.getByRole('button', { name: 'Posicionar selo visível' });
    await expect(open).toBeVisible();
    await open.click();
    await expect(
      page.getByRole('application', { name: 'Área de posicionamento do selo' }),
    ).toBeVisible();
    await expect(page.getByText('Posição exata (pontos PDF)')).toBeVisible();
  });

  await test.step('precise placement applies and summarizes the seal', async () => {
    await page.getByLabel('X (pontos)').fill('72');
    await page.getByLabel('Y (pontos)').fill('144');
    await page.getByLabel('Largura (pontos)').fill('180');
    await page.getByLabel('Altura (pontos)').fill('60');
    await page.getByRole('textbox', { name: 'Nome', exact: true }).fill('Amélia Marques');
    await page.getByRole('button', { name: 'Aplicar selo' }).click();
    await expect(page.getByText('Selo visível posicionado na página 1.')).toBeVisible();
  });

  await test.step('the placed seal reaches the CMD sign request body', async () => {
    await page.getByRole('button', { name: 'Assinar com Chave Móvel Digital' }).click();
    await page.getByLabel('Número de telemóvel').fill('+351 912345678');
    await page.getByLabel('PIN de assinatura da CMD').fill('1234');
    await page.getByRole('button', { name: 'Enviar código por SMS' }).click();

    await expect.poll(() => cmdInitiateBody).not.toBeNull();
    const seal = (cmdInitiateBody as Record<string, unknown>).seal as Record<string, unknown>;
    expect(seal).toMatchObject({
      invisible: false,
      page: 0,
      x: 72,
      y: 144,
      w: 180,
      h: 60,
      template: { kind: 'name_date', name: 'Amélia Marques' },
    });
  });
});

async function createAct(
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
  await expect(page).toHaveURL(/\/entidades\/nova$/);
  await page.getByLabel('Denominação').fill(entityName);
  await page.getByLabel('NIPC', { exact: true }).fill(nipc);
  await page.getByLabel('Sede').fill('Lisboa');
  await page.getByLabel('Forma jurídica').selectOption('SociedadeAnonima');
  await page.getByRole('button', { name: 'Criar entidade' }).click();
  await expect(page).toHaveURL(/\/entidades\/[0-9a-f-]{36}$/);

  await page.getByRole('link', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/livros\/novo\?entidade=[0-9a-f-]{36}$/);
  await page.getByLabel('Finalidade').fill(`Atas selo ${suffix}`);
  await page.getByLabel('Data de abertura').fill('2026-02-02');
  await fillOpenBookTermSignatories(page);
  await page.getByRole('button', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}$/);

  await page.getByRole('link', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}\/nova-ata$/);
  await page.getByLabel('Título da ata').fill(actTitle);
  await page.getByRole('button', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/atas\/[0-9a-f-]{36}$/);
}

async function fillAtaForDocument(page: Page): Promise<void> {
  await page.getByLabel('Data da reunião').fill('2026-03-30');
  await page.getByLabel('Hora da reunião').fill('15:00');
  await page.getByLabel('Local').fill('Sede social');
  await page.getByLabel('Referência de presenças').fill('Lista de presenças SELO-E2E');
  await page.getByLabel('Presentes').fill('3');
  await page.getByLabel('Representados').fill('0');
  await page.getByLabel('Presidente da mesa').fill('Amélia Marques');

  await page.getByRole('button', { name: 'Adicionar secretário' }).click();
  await page.getByLabel('Nome do secretário').fill('Rui Secretário');

  await page.getByRole('button', { name: 'Adicionar ponto' }).click();
  await page.getByLabel('Ponto da ordem de trabalhos').fill('Aprovação do relatório e contas');

  await page.getByRole('button', { name: 'Adicionar deliberação' }).click();
  await page
    .getByLabel('Texto da deliberação')
    .fill('Aprovação do relatório e contas do exercício de 2025.');
  await page.getByLabel('Ponto associado').selectOption('1');
  await page.getByLabel('Resultado da votação').selectOption('Unanimous');

  await page
    .getByLabel('Texto', { exact: true })
    .fill('Foi analisado o relatório de gestão e aprovado o relatório e contas de 2025.');

  await page.getByRole('button', { name: 'Adicionar signatário' }).click();
  await page.getByLabel('Nome do signatário').fill('Amélia Marques');
  await page.getByLabel('Qualidade').selectOption('Chair');
}

async function advanceToSigning(page: Page): Promise<void> {
  for (let i = 0; i < 5; i++) {
    const advance = page.getByRole('button', { name: /^Avançar para/ });
    await expect(advance).toBeEnabled();
    await advance.click();
    await expect(page.getByRole('button', { name: 'A avançar…' })).toHaveCount(0);
  }
  await expect(page.getByRole('button', { name: /^Avançar para/ })).toHaveCount(0);
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
