/**
 * Browser E2E for the signing-format selector and the SCAP professional-attribute picker (t67-e13).
 *
 * Creates and seals its own act, opens the signing panel, and:
 *   1. switches the signing format to XAdES, choosing a packaging + level, then submits the local
 *      XAdES tool with a dummy PKCS#12 — the xades/sign request is intercepted (fulfilled 409, the
 *      off-host / not-co-located reality) so the placed choices are proven to reach the request body
 *      and the honest co-location note is shown;
 *   2. switches to the SCAP format and, with the providers/attributes endpoints routed to a mock
 *      (declared) attribute, proves the attribute renders as «declared, not SCAP-verified» and never
 *      as verified.
 *
 * The suite is serial and runs against the one shared server with the shared auth helper.
 */
import { expect, test, type Locator, type Page } from './fixtures';
import { OPERATOR, signInAt } from './auth';

test('signing format selector: XAdES choice reaches the request body; SCAP shows declared-not-verified', async ({
  page,
}) => {
  test.setTimeout(180_000);

  const suffix = Date.now().toString(36);
  const entityName = `Formato E2E ${suffix} & Filhos, S.A.`;
  const actTitle = `Ata formato ${suffix}`;
  const nipc = validNipc(Date.now());

  // Capture the XAdES sign body and fulfil it 409 (the hosted server is not co-located with a
  // private key) so no real signing is attempted — the point is the request shape + honest note.
  let xadesBody: Record<string, unknown> | null = null;
  await page.route('**/v1/signature/xades/sign', async (route) => {
    xadesBody = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      status: 409,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'requires the desktop app (E2E)' }),
    });
  });

  // Route the SCAP providers/attributes to a deterministic mock (declared) attribute.
  await page.route('**/v1/scap/providers', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        report_kind: 'scap_attribute_providers',
        environment: 'preprod',
        transport: 'mock',
        providers: [
          { id: 'ordem-advogados', name: 'Ordem dos Advogados', attribute_names: ['Advogado'] },
        ],
      }),
    });
  });
  await page.route('**/v1/scap/attributes', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        report_kind: 'scap_citizen_attributes',
        environment: 'preprod',
        transport: 'mock',
        citizen_id: '12345678',
        attributes: [
          {
            provider_id: 'ordem-advogados',
            provider_name: 'Ordem dos Advogados',
            name: 'Advogado',
            valid_from: null,
            valid_until: null,
            sub_attributes: [{ name: 'cedula', value: '12345P' }],
          },
        ],
      }),
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

  await test.step('XAdES format/level/packaging choice reaches the xades/sign body', async () => {
    await page.getByLabel('Formato de assinatura').selectOption('xades');
    await expect(page.getByText('Assinatura XAdES local')).toBeVisible();
    await page.getByLabel('Empacotamento').selectOption('enveloping');
    await page.getByLabel('Nível', { exact: true }).selectOption('T');
    await page.getByLabel('Ficheiro PKCS#12/PFX').setInputFiles({
      name: 'signer.pfx',
      mimeType: 'application/x-pkcs12',
      buffer: Buffer.from('pfx-bytes'),
    });
    await page.getByLabel('Frase-passe').fill('pfx-passphrase');
    await page.getByRole('button', { name: 'Produzir XAdES' }).click();

    await expect.poll(() => xadesBody).not.toBeNull();
    expect(xadesBody as Record<string, unknown>).toMatchObject({
      content_name: 'ata.pdf',
      packaging: 'enveloping',
      level: 'T',
      signer: { kind: 'soft_pkcs12' },
    });
    // The 409 surfaces the honest co-location note rather than a faked success.
    await expect(page.getByText('Disponível apenas na aplicação de secretária')).toBeVisible();
  });

  await test.step('SCAP shows a declared (not SCAP-verified) attribute, never verified', async () => {
    await page.getByLabel('Formato de assinatura').selectOption('scap');
    await page.getByLabel('Identificação do cidadão').fill('12345678');
    await page.getByRole('button', { name: 'Procurar atributos' }).click();

    await expect(page.getByText('Advogado').first()).toBeVisible();
    await expect(page.getByText('Declarado — não verificado pela SCAP').first()).toBeVisible();
    await expect(page.getByText('Verificado pela SCAP')).toHaveCount(0);
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
  await page.getByLabel('Finalidade').fill(`Atas formato ${suffix}`);
  await page.getByLabel('Data de abertura').fill('2026-02-02');
  await page.getByLabel('Signatários do termo de abertura').fill('Presidente da Mesa\nSecretário');
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
  await page.getByLabel('Referência de presenças').fill('Lista de presenças FORMATO-E2E');
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
