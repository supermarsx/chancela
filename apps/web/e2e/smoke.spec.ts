/**
 * Independent, read-only smoke checks against the composed system (plan t15 §2.5):
 * the SPA boots and paints its chrome, the theme flip stamps `[data-theme]`, and the
 * CAE catalog search returns results from the embedded dataset. None of these depend on
 * the journey's mutations, so they run in isolation against a freshly-booted server.
 */
import { test, expect } from './fixtures';
import { signInAt } from './auth';

test('boots the SPA with the leather background and the six-tab bar', async ({ page }) => {
  // The app is auth-gated (t44): onboard/sign in before the chrome renders.
  await signInAt(page, '/');

  // The fixed leather layer is rendered (settings default the texture on).
  await expect(page.getByTestId('leather-bg')).toBeAttached();

  // The centered secondary tab bar carries exactly the six pinned PT-PT tabs (the
  // Ferramentas tools surface joined the set in t22-web).
  const tabs = page.getByTestId('tab-bar').getByRole('link');
  await expect(tabs).toHaveCount(6);
  await expect(tabs).toHaveText([
    'Painel',
    'Entidades',
    'Livros',
    'Arquivo',
    'Ferramentas',
    'Configurações',
  ]);

  // The dashboard actually rendered (a real /v1/dashboard response parsed in-browser).
  await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();
});

test('settings theme flip applies [data-theme] live', async ({ page }) => {
  await signInAt(page, '/configuracoes');
  const html = page.locator('html');
  const theme = page.getByLabel('Tema');

  await theme.selectOption('dark');
  await expect(html).toHaveAttribute('data-theme', 'dark');

  await theme.selectOption('light');
  await expect(html).toHaveAttribute('data-theme', 'light');

  // `system` removes the attribute so the OS preference wins again.
  await theme.selectOption('system');
  await expect(html).not.toHaveAttribute('data-theme', /.*/);
});

test('Configurações sub-tabs switch sections and deep-link via ?sec=', async ({ page }) => {
  await signInAt(page, '/configuracoes');

  // Aparência is the default section (its theme control shows). The sub-tab pills use the
  // shared SubNav (gliding indicator, same guarded effect as Ferramentas) — repeated
  // switching must not trigger the "Maximum update depth" loop in a real browser.
  await expect(page.getByLabel('Tema')).toBeVisible();

  // Documentos: its CAE-URL field appears, the section deep-links, and Aparência's control
  // is gone (one section at a time).
  await page.getByRole('button', { name: 'Documentos' }).click();
  await expect(page.getByLabel('URL de atualização do catálogo CAE')).toBeVisible();
  await expect(page).toHaveURL(/[?&]sec=documentos/);
  await expect(page.getByLabel('Tema')).toHaveCount(0);

  // Switch to Sobre and back to Aparência — no crash across repeated indicator re-measures.
  await page.getByRole('button', { name: 'Sobre' }).click();
  await expect(page.getByText('Versão da interface')).toBeVisible();
  await page.getByRole('button', { name: 'Aparência' }).click();
  await expect(page.getByLabel('Tema')).toBeVisible();
});

test('safe mode (?safe=1) shows the banner and bypasses the appearance layer', async ({ page }) => {
  await signInAt(page, '/?safe=1');

  // The persistent safe-mode banner is visible with its exit action.
  await expect(page.getByText('Modo de segurança', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sair do modo de segurança' })).toBeVisible();

  // Appearance is bypassed: the safe-mode flag is stamped and the leather layer is gone.
  await expect(page.locator('html')).toHaveAttribute('data-safe-mode', 'on');
  await expect(page.getByTestId('leather-bg')).toHaveCount(0);
});

test('Legislação shelf filters live via search in Ferramentas', async ({ page }) => {
  await signInAt(page, '/ferramentas?tool=legislacao&leg=prateleira');

  // The curated law shelf renders (a known theme heading, incl. the new t34 group).
  await expect(page.getByRole('heading', { name: 'Registo e identificação' })).toBeVisible();

  // Search folds accents/case and filters the cards live (query without accents matches
  // the accented "condomínio" content).
  await page.getByLabel('Procurar na legislação').fill('condominio');
  await expect(
    page.getByRole('heading', { name: 'Atas das assembleias de condóminos' }),
  ).toBeVisible();
  // A non-matching diploma drops out of the shelf.
  await expect(page.getByRole('heading', { name: 'Lei-Quadro das Fundações' })).toHaveCount(0);

  // The committed query is deep-linked in the tool's search params.
  await expect(page).toHaveURL(/[?&]q=condominio/);
});

test('CAE search returns results from the catalog in Ferramentas', async ({ page }) => {
  // The former /cae page now redirects into the Ferramentas explorer (deep links kept).
  await signInAt(page, '/cae');
  await expect(page).toHaveURL(/\/ferramentas/);

  await page.getByLabel('Procurar no catálogo CAE').fill('68110');

  // The catalog resolves 68110 (Compra e venda de bens imobiliários, Rev.4) into the
  // explorer's pick list; selecting it opens the detail pane at that código.
  const results = page.locator('.cae-picklist .cae-pick');
  await expect(results.first()).toBeVisible();
  const code = page.locator('.cae-pick__code', { hasText: '68110' }).first();
  await expect(code).toBeVisible();
  await code.click();
  await expect(page.locator('.cae-detail__code')).toHaveText('68110');
});
