import { Buffer } from 'node:buffer';
import { expect, test, type Download, type Locator, type Page } from './fixtures';
import { readFile, stat } from 'node:fs/promises';
import { OPERATOR, signInAt } from './auth';

test('paper-book import preserves non-canonical package and OCR review stays auxiliary', async ({
  page,
}) => {
  test.setTimeout(180_000);
  await installBrowserDownloadFallback(page);

  const suffix = Date.now().toString(36);
  const entityName = `Livro Papel OCR E2E ${suffix}, S.A.`;
  const nipc = validNipc(Date.now());

  await signInAt(page, '/');
  await page.reload();
  await signInAt(page, '/');
  await expect(page.getByTestId('session-trigger')).toContainText(OPERATOR.displayName);

  const bookId = await createEntityAndBook(page, { entityName, nipc, suffix });

  const reviewedImport = await preservePaperBookPackage(page, {
    filename: `ag-1968-1971-${suffix}.pdf`,
    dateFrom: '1968-01-01',
    dateTo: '1971-12-31',
    pageCount: '4',
    notes: 'Digitalizado do livro encadernado guardado no arquivo físico.',
  });

  await test.step('preserved package is labelled as non-canonical evidence', async () => {
    await expect(page.getByText(reviewedImport.filename)).toBeVisible();
    await expect(page.getByText('Relatório não canónico')).toBeVisible();
    await expect(page.getByText(/não declaram validade legal, PDF\/A/i)).toBeVisible();
    await expect(page.getByText(/não cria nem altera cadeias de atas/i)).toBeVisible();
    await expect(page.locator('.badge').filter({ hasText: 'Não canónico' }).first()).toBeVisible();
    await expect(page.getByText('OCR não executado').first()).toBeVisible();
    await expect(page.getByText(/texto autoritativo: não/i).first()).toBeVisible();
    await expect(page.locator('body')).not.toContainText('PDF/A canónico gerado');
    await expect(page.locator('body')).not.toContainText('Download signed PDF');
    await expect(page.locator('body')).not.toContainText('Descarregar PDF assinado');
  });

  await test.step('auxiliary OCR draft requires acknowledgement before review save', async () => {
    const section = ocrSection(page, reviewedImport.importId);

    await section
      .getByLabel('Texto OCR auxiliar')
      .fill('Livro de atas digitalizado para consulta.');
    await section.getByLabel('Página final').fill('2');
    await section.getByLabel('Confiança').fill('0.91');

    const createButton = section.getByRole('button', { name: 'Guardar rascunho OCR' });
    await expect(createButton).toBeDisabled();
    await section.getByLabel(/Confirmo que este rascunho OCR é auxiliar/i).check();
    await expect(createButton).toBeEnabled();
    await createButton.click();

    await expect(
      page.getByText('Rascunho OCR guardado como metadado auxiliar não canónico.'),
    ).toBeVisible();
    await expect(section.getByText('Livro de atas digitalizado para consulta.')).toBeVisible();
    await expect(section.getByText(/Texto autoritativo: não/i)).toBeVisible();
    await expect(section.getByText(/ata canónica: não/i)).toBeVisible();
    await expect(section.getByText(/documento canónico: não/i)).toBeVisible();
    await expect(section.getByText(/validade legal: não/i)).toBeVisible();

    await section.getByLabel('Estado da revisão OCR').selectOption('accepted');
    await section.getByLabel('Nota da revisão OCR').fill('Conferido contra o pacote preservado.');

    const reviewButton = section.getByRole('button', { name: 'Guardar revisão OCR' });
    await expect(reviewButton).toBeDisabled();
    await section.getByLabel(/Confirmo que esta revisão é apenas metadado auxiliar/i).check();
    await expect(reviewButton).toBeEnabled();
    await reviewButton.click();

    await expect(
      page.getByText('Revisão OCR guardada como metadado auxiliar não canónico.'),
    ).toBeVisible();
    await expect(section.getByText('Aceite para referência auxiliar').first()).toBeVisible();
    await expect(
      section.getByRole('definition').filter({ hasText: 'Conferido contra o pacote preservado.' }),
    ).toBeVisible();
  });

  const noOcrImport = await preservePaperBookPackage(page, {
    filename: `ag-no-local-ocr-${suffix}.pdf`,
    dateFrom: '1972-01-01',
    dateTo: '1972-12-31',
    pageCount: '1',
    notes: 'Importação separada para confirmar falha conservadora do OCR local.',
  });

  await test.step('local OCR without configured command creates no draft', async () => {
    const section = ocrSection(page, noOcrImport.importId);
    await expect(section.getByText('Sem rascunhos OCR registados')).toBeVisible();

    const runResponse = waitForApiResponse(
      page,
      `/v1/books/paper-import/${noOcrImport.importId}/ocr/run`,
      'POST',
    );
    await rowForImport(page, noOcrImport.filename)
      .getByRole('button', { name: 'Executar OCR local' })
      .click();
    await page.getByRole('button', { name: 'Confirmar execução de OCR local' }).click();

    expect((await runResponse).status()).toBe(422);
    await expect(
      page
        .getByRole('dialog', { name: 'Executar OCR local' })
        .getByRole('alert')
        .filter({ hasText: /operator-configured local OCR command/i }),
    ).toBeVisible();
    await expect(section.getByText('Sem rascunhos OCR registados')).toBeVisible();
    await expect(section.getByText('Livro de atas digitalizado para consulta.')).toHaveCount(0);
  });

  await test.step('reload keeps reviewed OCR auxiliary and package download separate', async () => {
    await page.goto(`/livros/${bookId}`);
    await signInAt(page, `/livros/${bookId}`);

    const section = ocrSection(page, reviewedImport.importId);
    await expect(page.getByText(reviewedImport.filename)).toBeVisible();
    await expect(section.getByText('Aceite para referência auxiliar').first()).toBeVisible();
    await expect(
      section.getByRole('definition').filter({ hasText: 'Conferido contra o pacote preservado.' }),
    ).toBeVisible();
    await expect(section.getByText(/Texto autoritativo: não/i)).toBeVisible();
    await expect(section.getByText(/documento canónico: não/i)).toBeVisible();
    await expect(
      page.getByRole('button', { name: 'Pacote de preservação Chancela' }),
    ).toBeVisible();

    const retainedPackage = await downloadFrom(
      rowForImport(page, reviewedImport.filename).getByRole('button', {
        name: 'Descarregar pacote',
      }),
    );
    await expectPackageDownload(retainedPackage, reviewedImport.filename, reviewedImport.bytes);
  });
});

async function createEntityAndBook(
  page: Page,
  {
    entityName,
    nipc,
    suffix,
  }: {
    entityName: string;
    nipc: string;
    suffix: string;
  },
): Promise<string> {
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
  await page.getByLabel('Finalidade').fill(`Atas em papel importadas ${suffix}`);
  await page.getByLabel('Data de abertura').fill('2026-01-15');
  await page.getByLabel('Signatários do termo de abertura').fill('Presidente da Mesa\nSecretário');
  await page.getByRole('button', { name: 'Abrir livro' }).click();
  await expect(page).toHaveURL(/\/livros\/[0-9a-f-]{36}$/);
  return idFromUrl(page);
}

async function preservePaperBookPackage(
  page: Page,
  {
    filename,
    dateFrom,
    dateTo,
    pageCount,
    notes,
  }: {
    filename: string;
    dateFrom: string;
    dateTo: string;
    pageCount: string;
    notes: string;
  },
): Promise<{ filename: string; importId: string; bytes: Buffer }> {
  const bytes = Buffer.from(
    `%PDF-1.7\n% paper-book preserved import ${filename}\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n`,
    'utf8',
  );

  await page.getByLabel('Pacote digitalizado').setInputFiles({
    name: filename,
    mimeType: 'application/pdf',
    buffer: bytes,
  });
  await page.getByLabel('Data inicial').fill(dateFrom);
  await page.getByLabel('Data final').fill(dateTo);
  await page.getByLabel('Páginas').fill(pageCount);
  await page.getByLabel('Notas').fill(notes);

  const preserveResponse = waitForApiResponse(page, '/v1/books/paper-import', 'POST');
  await page.getByRole('button', { name: 'Preservar pacote' }).click();
  const response = await preserveResponse;
  expect(response.status()).toBe(201);
  const body = (await response.json()) as { import_id: string };
  expect(body.import_id).toMatch(/[0-9a-f-]{36}/);

  await expect(page.getByText(filename)).toBeVisible();
  await expect(ocrSection(page, body.import_id)).toBeVisible();
  return { filename, importId: body.import_id, bytes };
}

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

function ocrSection(page: Page, importId: string): Locator {
  return page.locator(`section[aria-label="Rascunhos OCR da importação ${importId}"]`);
}

function rowForImport(page: Page, filename: string): Locator {
  return page.getByRole('row').filter({ hasText: filename });
}

async function waitForApiResponse(page: Page, pathname: string, method: string) {
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.pathname === pathname && response.request().method() === method;
  });
}

async function downloadFrom(button: Locator): Promise<Download> {
  const [download] = await Promise.all([button.page().waitForEvent('download'), button.click()]);
  return download;
}

async function expectPackageDownload(
  download: Download,
  filename: string,
  expectedBytes: Buffer,
): Promise<void> {
  expect(download.suggestedFilename()).toBe(filename);
  await expect(download.failure()).resolves.toBeNull();
  const file = await download.path();
  expect(file).toBeTruthy();
  const info = await stat(file!);
  expect(info.size).toBe(expectedBytes.length);
  const bytes = await readFile(file!);
  expect(bytes.equals(expectedBytes)).toBe(true);
  expect(bytes.subarray(0, 4).toString('utf8')).toBe('%PDF');
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
