/**
 * Real-browser coverage for the template PDF/A preview's pdf.js compatibility boundary.
 *
 * The component tests mock pdf.js; this test deliberately does not. It opens a built-in catalog
 * template against the real server, waits for its stateless PDF/A response to render through the
 * production lazy engine + worker, and then proves that switching representations unmounts PDF
 * rather than leaving two competing previews in the document.
 */
import { expect, test } from './fixtures';
import { signInAt } from './auth';

const TEMPLATE_ID = 'csc-ata-ag/v1';
const PREVIEW_PATH = `/templates/${encodeURIComponent(TEMPLATE_ID)}/preview`;
const UPSERT_ERROR = /getOrInsertComputed/i;

test('template PDF/A preview renders through real pdf.js and remains exclusive with Markdown', async ({
  page,
}) => {
  const compatibilityErrors: string[] = [];
  // Keep the compatibility target (PDF generation + pdf.js) fully real; the Markdown response is
  // route-stubbed so this test stays focused on representation exclusivity rather than recompiling
  // or re-verifying the sibling server renderer.
  await page.route('**/v1/templates/document/preview/markdown', async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'text/markdown; charset=utf-8',
      body: '# Ata de Assembleia Geral\n\nConteúdo integral da ata.',
    });
  });
  page.on('pageerror', (error) => {
    if (UPSERT_ERROR.test(error.message)) compatibilityErrors.push(error.message);
  });
  page.on('console', (message) => {
    if (message.type() === 'error' && UPSERT_ERROR.test(message.text())) {
      compatibilityErrors.push(message.text());
    }
  });

  await signInAt(page, PREVIEW_PATH);

  const pdfTab = page.getByRole('tab', { name: 'PDF', exact: true });
  const markdownTab = page.getByRole('tab', { name: 'Markdown', exact: true });
  const pdfPreview = page.locator('.template-pdf-preview');
  const canvas = pdfPreview.locator('canvas');

  await expect(pdfTab).toHaveAttribute('aria-selected', 'true');
  await expect(markdownTab).toHaveAttribute('aria-selected', 'false');
  await expect(pdfPreview.getByRole('link', { name: 'Abrir PDF' })).toBeVisible();
  await expect(canvas).toBeVisible();
  await expect
    .poll(() =>
      canvas.evaluate(
        (element) =>
          element instanceof HTMLCanvasElement && element.width > 0 && element.height > 0,
      ),
    )
    .toBe(true);
  await expect(page.getByLabel('Conteúdo da pré-visualização Markdown')).toHaveCount(0);
  expect(compatibilityErrors).toEqual([]);

  await markdownTab.click();

  await expect(markdownTab).toHaveAttribute('aria-selected', 'true');
  await expect(pdfTab).toHaveAttribute('aria-selected', 'false');
  await expect(page.getByLabel('Conteúdo da pré-visualização Markdown')).toBeVisible();
  await expect(page.locator('.template-pdf-preview')).toHaveCount(0);
  await expect(page.locator('canvas.template-pdf-preview__canvas')).toHaveCount(0);
  expect(compatibilityErrors).toEqual([]);
});
