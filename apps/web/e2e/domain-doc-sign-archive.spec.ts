/**
 * Browser E2E coverage for the document / archive / signing surfaces on top of the
 * domain journey. The suite is serial: this spec creates its own entity/book/act, but
 * still runs against the one shared server and uses the shared auth helper.
 */
import { expect, test, type Download, type Locator, type Page } from './fixtures';
import { readFile, stat } from 'node:fs/promises';
import { OPERATOR, signInAt } from './auth';
import { fillOpenBookTermSignatories, sealActForSigning } from './book-helpers';

test('document preview/PDF, sealed deep link, signing fallback, archive filters/export', async ({
  page,
}) => {
  test.setTimeout(180_000);

  const suffix = Date.now().toString(36);
  const entityName = `Documentos E2E ${suffix} & Filhos/Q+A #7, S.A.`;
  const actTitle = `Ata documental ${suffix} / Q&A #7`;
  const downloadStem = `${slugForDownload(entityName)}-ata-\\d+`;
  const nipc = validNipc(Date.now());

  await installBrowserDownloadFallback(page);
  await mockUnavailableSigningProviders(page);
  await signInAt(page, '/');
  // A fresh onboarding path lands signed in, but the permission-gated action cache is only
  // fully populated after the normal password sign-in path. Reload once so this focused spec
  // works both when it runs first and when another spec already onboarded the server.
  await page.reload();
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  const { actId, bookId } = await createAct(page, {
    actTitle,
    entityName,
    nipc,
    suffix,
  });

  await test.step('pre-seal document preview renders and signing/seal are unavailable', async () => {
    // Before the act reaches «Em assinatura» the Selagem card offers no seal affordance at all —
    // it renders only the explanatory note. (It used to render the button in a disabled state.)
    await expect(page.getByRole('button', { name: 'Selar ata' })).toHaveCount(0);
    await expect(page.getByText('A selagem só fica disponível')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Descarregar PDF' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Descarregar Markdown' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Descarregar DOCX' })).toHaveCount(0);

    await fillAtaForDocument(page);
    await page.getByRole('button', { name: 'Guardar' }).click();
    await expect(page.getByRole('button', { name: 'A guardar…' })).toHaveCount(0);

    await page.getByRole('button', { name: 'Pré-visualizar documento' }).click();
    const preview = page.locator('.doc-preview');
    await expect(preview).toContainText(actTitle);
    await expect(preview).toContainText(entityName);
    await expect(preview).toContainText('Aprovação do relatório e contas');
    await expect(page.getByRole('button', { name: 'Descarregar PDF' })).toHaveCount(0);
  });

  await test.step('signing panel shows configured/unconfigured providers and CC unavailable state', async () => {
    // Signing affordances only exist while the act is «Em assinatura» — sealing closes them
    // (asserted below), so this step runs before the seal rather than after it.
    await advanceToSigning(page);
    await expect(page.getByText('Conforme', { exact: true })).toBeVisible();

    await expect(page.getByText('Cópia canónica ainda não assinada')).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Assinar com Chave Móvel Digital' }),
    ).toBeVisible();

    const multicert = page.getByRole('button', { name: 'Assinar com Multicert' });
    await expect(multicert).toBeEnabled();

    const digitalSign = page.getByRole('button', { name: 'Assinar com DigitalSign' });
    await expect(digitalSign).toBeDisabled();
    const digitalSignRow = page.locator('.signing-provider').filter({ has: digitalSign });
    await expect(digitalSignRow.getByText('não configurado', { exact: true })).toBeVisible();

    await page.getByRole('button', { name: 'Assinar com Cartão de Cidadão' }).click();
    await expect(page.getByText('Assinatura com Cartão de Cidadão')).toBeVisible();
    await page.getByRole('button', { name: 'Assinar com o cartão' }).click();
    await expect(
      page.getByText('Disponível apenas na aplicação de secretária', { exact: true }),
    ).toBeVisible();
  });

  await test.step('seal and download canonical PDF/A plus non-evidentiary working copies', async () => {
    const seal = page.getByRole('button', { name: 'Selar ata' });
    await expect(seal).toBeEnabled();
    await sealActForSigning(page, {
      storageReference: `Arquivo E2E / Documentos / Original ${suffix}`,
      custodian: 'Secretariado documental',
    });
    await expect(page.getByTestId('ata-number')).toContainText(/\d/);

    await expect(
      page.getByText(
        'Markdown, TXT, HTML, RTF, ODT e DOCX são cópias de trabalho não probatórias para revisão; o PDF/A preservado é o documento oficial.',
      ),
    ).toBeVisible();

    const pdfDownload = await downloadFrom(page.getByRole('button', { name: 'Descarregar PDF' }));
    await expectPdfDownload(pdfDownload, new RegExp(`^${downloadStem}\\.pdf$`));

    const repeatedPdfDownload = await downloadFrom(
      page.getByRole('button', { name: 'Descarregar PDF' }),
    );
    await expectPdfDownload(repeatedPdfDownload, new RegExp(`^${downloadStem}\\.pdf$`));
    expect(repeatedPdfDownload.suggestedFilename()).toBe(pdfDownload.suggestedFilename());

    const markdownDownload = await downloadFrom(
      page.getByRole('button', { name: 'Descarregar Markdown' }),
    );
    await expectMarkdownDownload(
      markdownDownload,
      new RegExp(`^${downloadStem}-working-copy\\.md$`),
      [
        'WORKING COPY - NON-EVIDENTIARY',
        'not the preserved signed original',
        'Preserved PDF digest',
        `Ata documental ${suffix} / Q&A`,
      ],
    );

    const docxDownload = await downloadFrom(page.getByRole('button', { name: 'Descarregar DOCX' }));
    await expectDocxDownload(
      docxDownload,
      new RegExp(`^${downloadStem}-office-working-copy\\.docx$`),
      [
        'WORKING COPY - NON-EVIDENTIARY',
        'not the preserved signed original',
        'Office-editable non-evidentiary export',
      ],
    );
  });

  await test.step('sealed act direct URL reload keeps the read-only document state after sign-in', async () => {
    const sealedPath = new URL(page.url()).pathname;

    await page.goto(sealedPath);
    await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();

    await signInAt(page, sealedPath);
    await expect(page).toHaveURL(new RegExp(`${escapeRegExp(sealedPath)}$`));
    // «Ata selada» is also the title of the follow-ups panel note, so target the act-level
    // sealed banner by its body copy.
    await expect(
      page
        .getByRole('note')
        .filter({ hasText: 'O conteúdo está congelado e encadeado no registo' }),
    ).toBeVisible();
    await expect(page.getByRole('button', { name: 'Descarregar PDF' })).toBeVisible();
    await expect(page.getByLabel('Data da reunião')).toBeDisabled();
  });

  await test.step('download the book preservation package separately from document copies', async () => {
    await page.getByRole('link', { name: 'Livro', exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/livros/${escapeRegExp(bookId)}$`));
    await expect(
      page.getByRole('button', { name: 'Pacote de preservação Chancela' }),
    ).toBeEnabled();

    const packageDownload = await downloadFrom(
      page.getByRole('button', { name: 'Pacote de preservação Chancela' }),
    );
    await expectZipDownload(
      packageDownload,
      new RegExp(`^chancela-preservation-book-${escapeRegExp(bookId)}\\.zip$`),
    );

    await page.getByRole('link', { name: 'Abrir' }).click();
    await expect(page).toHaveURL(new RegExp(`/atas/${escapeRegExp(actId)}$`));
    // «Ata selada» is also the title of the follow-ups panel note, so target the act-level
    // sealed banner by its body copy.
    await expect(
      page
        .getByRole('note')
        .filter({ hasText: 'O conteúdo está congelado e encadeado no registo' }),
    ).toBeVisible();
  });

  await test.step('sealing closes the signing actions but keeps the evidence readable', async () => {
    await expect(page.getByRole('heading', { name: 'Assinatura qualificada' })).toBeVisible();
    await expect(page.getByText('Assinatura encerrada')).toBeVisible();
    await expect(page.getByRole('button', { name: /^Assinar com/ })).toHaveCount(0);
  });

  await test.step('archive the act, filter the ledger, and export the filtered PDF/A', async () => {
    await page.getByRole('button', { name: 'Arquivar ata' }).click();
    await expect(page.getByRole('main').getByText('Ata arquivada.', { exact: true })).toBeVisible();

    await tab(page, 'Arquivo').click();
    await expect(page).toHaveURL(/\/arquivo$/);
    await expect(page.getByText(/^Cadeia verificada/)).toBeVisible();

    await page.getByLabel('Filtrar por cadeia').selectOption(`book:${bookId}`);
    await expect(page.getByText('act.sealed', { exact: true })).toBeVisible();

    await page.getByLabel('Filtrar por âmbito').fill(`act:${actId}`);
    await expect(page.getByText('document.generated', { exact: true })).toBeVisible();
    await expect(page.getByText('act.archived', { exact: true })).toBeVisible();
    await expect(page.locator('td', { hasText: OPERATOR.username }).first()).toBeVisible();

    const archiveDownload = await downloadFrom(
      page.getByRole('button', { name: 'Exportar arquivo' }),
    );
    await expectPdfDownload(archiveDownload, /^arquivo-.*\.pdf$/);
  });
});

/**
 * The document/export surfaces prefer the File System Access save picker, which never resolves in
 * headless Chromium. Removing it makes them fall back to the ordinary browser download this spec
 * inspects — the same fixture `export-save-hardening.spec.ts` uses.
 */
async function installBrowserDownloadFallback(page: Page): Promise<void> {
  await page.addInitScript(() => {
    try {
      Object.defineProperty(window, 'showSaveFilePicker', {
        value: undefined,
        configurable: true,
      });
    } catch {
      (window as Window & { showSaveFilePicker?: unknown }).showSaveFilePicker = undefined;
    }
  });
}

async function mockUnavailableSigningProviders(page: Page): Promise<void> {
  await page.route('**/v1/signature/providers', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify([
        {
          id: 'cmd',
          family: 'ChaveMovelDigital',
          label: 'Chave Móvel Digital',
          evidentiary_level: 'Qualified',
          configured: false,
        },
        {
          id: 'multicert',
          family: 'QualifiedCertificate',
          label: 'Multicert',
          evidentiary_level: 'Qualified',
          configured: true,
        },
        {
          id: 'digitalsign',
          family: 'QualifiedCertificate',
          label: 'DigitalSign',
          evidentiary_level: 'Qualified',
          configured: false,
        },
      ]),
    });
  });

  await page.route('**/v1/acts/*/signature/cc/sign', async (route) => {
    await route.fulfill({
      status: 409,
      contentType: 'application/json',
      body: JSON.stringify({
        error: 'Assinatura com Cartão de Cidadão disponível apenas na aplicação de secretária.',
      }),
    });
  });
}

async function createAct(
  page: Page,
  {
    actTitle,
    entityName,
    nipc,
    suffix,
  }: {
    actTitle: string;
    entityName: string;
    nipc: string;
    suffix: string;
  },
): Promise<{ bookId: string; actId: string }> {
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
  await page.getByLabel('Finalidade').fill(`Atas documentais ${suffix}`);
  await page.getByLabel('Data de abertura').fill('2026-02-02');
  await fillOpenBookTermSignatories(page);
  await page.getByRole('button', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}$/);
  const bookId = idFromUrl(page);

  await page.getByRole('link', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}\/nova-ata$/);
  await page.getByLabel('Título da ata').fill(actTitle);
  await page.getByRole('button', { name: 'Nova ata' }).click();
  await expect(page).toHaveURL(/\/atas\/[0-9a-f-]{36}$/);
  const actId = idFromUrl(page);

  return { bookId, actId };
}

async function fillAtaForDocument(page: Page): Promise<void> {
  await page.getByLabel('Data da reunião').fill('2026-03-30');
  await page.getByLabel('Hora da reunião').fill('15:00');
  // `getByLabel('Local')` is a substring match and also hits the convening-evidence group
  // («Evidência local de expedição…»); target the field by role + accessible name instead.
  await page.getByRole('textbox', { name: 'Local', exact: true }).fill('Sede social');
  await page.getByLabel('Referência de presenças').fill('Lista de presenças DOC-E2E');
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

  await page.getByRole('button', { name: 'Adicionar documento' }).click();
  await page.getByLabel('Designação do documento').fill('Relatório de gestão');
  await page.getByLabel('Referência do documento').fill('DOC-REL-2025');

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

async function downloadFrom(button: Locator): Promise<Download> {
  const [download] = await Promise.all([button.page().waitForEvent('download'), button.click()]);
  return download;
}

async function expectPdfDownload(download: Download, filename: RegExp): Promise<void> {
  expect(download.suggestedFilename()).toMatch(filename);
  expect(download.suggestedFilename()).not.toContain('working-copy');
  const bytes = await downloadBytes(download);
  expect(bytes.subarray(0, 4).toString('utf8')).toBe('%PDF');
}

async function expectMarkdownDownload(
  download: Download,
  filename: RegExp,
  requiredText: string[],
): Promise<void> {
  expect(download.suggestedFilename()).toMatch(filename);
  expect(download.suggestedFilename()).toContain('working-copy');
  expect(download.suggestedFilename()).not.toMatch(/\.pdf$/);
  const bytes = await downloadBytes(download);
  expect(bytes.subarray(0, 4).toString('utf8')).not.toBe('%PDF');
  const text = bytes.toString('utf8');
  for (const value of requiredText) {
    expect(text).toContain(value);
  }
}

async function expectDocxDownload(
  download: Download,
  filename: RegExp,
  requiredText: string[],
): Promise<void> {
  expect(download.suggestedFilename()).toMatch(filename);
  expect(download.suggestedFilename()).toContain('office-working-copy');
  expect(download.suggestedFilename()).not.toMatch(/\.pdf$/);
  const bytes = await downloadBytes(download);
  expect(bytes.subarray(0, 2).toString('utf8')).toBe('PK');
  expect(bytes.subarray(0, 4).toString('utf8')).not.toBe('%PDF');
  const text = bytes.toString('utf8');
  for (const value of requiredText) {
    expect(text).toContain(value);
  }
}

async function expectZipDownload(download: Download, filename: RegExp): Promise<void> {
  expect(download.suggestedFilename()).toMatch(filename);
  expect(download.suggestedFilename()).not.toContain('working-copy');
  expect(download.suggestedFilename()).not.toMatch(/\.pdf$/);
  const bytes = await downloadBytes(download);
  expect(bytes.subarray(0, 2).toString('utf8')).toBe('PK');
  expect(bytes.subarray(0, 4).toString('utf8')).not.toBe('%PDF');
}

async function downloadBytes(download: Download): Promise<Buffer> {
  await expect(download.failure()).resolves.toBeNull();
  const file = await download.path();
  expect(file).toBeTruthy();
  const info = await stat(file!);
  expect(info.size).toBeGreaterThan(4);
  return readFile(file!);
}

function tab(page: Page, name: string): Locator {
  return page.getByTestId('tab-bar').getByRole('link', { name, exact: true });
}

function idFromUrl(page: Page): string {
  return new URL(page.url()).pathname.split('/').at(-1) ?? '';
}

function validNipc(seed: number): string {
  const body = `5${String(Math.abs(seed) % 10_000_000).padStart(7, '0')}`;
  const sum = [...body].reduce((acc, digit, index) => acc + Number(digit) * (9 - index), 0);
  const remainder = sum % 11;
  const check = remainder < 2 ? 0 : 11 - remainder;
  return `${body}${check}`;
}

function slugForDownload(value: string): string {
  return (
    value
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'documento'
  );
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
