/**
 * Server-backed data-management storage coverage. The assertions here deliberately use
 * the real E2E backend for status, RBAC, and cleanup, while seeding only disposable files
 * inside Playwright's throwaway CHANCELA_E2E_DATA_DIR.
 */
import type { APIResponse } from '@playwright/test';
import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { expect, test, type APIRequestContext } from './fixtures';
import { OPERATOR, OPERATOR_PASSWORD, signInAt } from './auth';
import type {
  DataCleanupResult,
  DataStatusResponse,
  DataUsageConcern,
  SessionResult,
  SessionRoster,
  UserView,
} from '../src/api/types';

const GESTOR_PASSWORD = 'Gestor-Forte7!Z';

test('storage cleanup is settings.manage-gated and only deletes retained exports', async ({
  page,
}) => {
  test.setTimeout(120_000);

  const suffix = Date.now().toString(36);

  await signInAt(page, '/');
  const origin = new URL(page.url()).origin;
  const ownerSession = await createSessionForUsername(
    page.request,
    origin,
    OPERATOR.username,
    OPERATOR_PASSWORD,
  );

  const initialStatus = await getDataStatus(page.request, origin, ownerSession.token);
  expect(initialStatus.persistence.mode).toBe('durable');
  expect(initialStatus.persistence.durable_store_open).toBe(true);
  expect(initialStatus.permissions.delete_probe_file.ok).toBe(true);

  const dataDir = resolveReportedDataDir(initialStatus.data_dir.path);
  const seeded = await seedStorageFixtures(dataDir, suffix);

  const gestor = await createGestorUser(page.request, origin, ownerSession.token, suffix);
  const gestorSession = await createSessionForUserId(
    page.request,
    origin,
    gestor.id,
    GESTOR_PASSWORD,
  );
  const gestorStatus = await getDataStatus(page.request, origin, gestorSession.token);
  expect(concernById(gestorStatus, 'exports')?.file_count).toBeGreaterThanOrEqual(2);
  expect(concernById(gestorStatus, 'crash')?.file_count).toBeGreaterThanOrEqual(1);

  const forbiddenCleanup = await page.request.post(`${origin}/v1/data/cleanup`, {
    headers: sessionHeaders(gestorSession.token),
    data: { target: 'exports' },
  });
  expect(forbiddenCleanup.status(), await forbiddenCleanup.text()).toBe(403);
  expect(await pathExists(seeded.exportManifest)).toBe(true);
  expect(await pathExists(seeded.exportBundle)).toBe(true);
  expect(await pathExists(seeded.crashFile)).toBe(true);

  await signInAt(page, '/configuracoes?sec=dados');
  await expect(page).toHaveURL(/[?&]sec=dados/);
  await expect(page.getByRole('heading', { name: 'Estado do armazenamento' })).toBeVisible();
  await expect(page.getByText('Durável aberto')).toBeVisible();
  await expect(page.getByText('Apagar ficheiro de teste')).toBeVisible();

  const exportsCleanup = page.locator('.data-status-cleanup', {
    hasText: 'Exportações retidas',
  });
  await expect(exportsCleanup).toContainText('Exportações retidas');
  await expect(exportsCleanup.getByRole('button', { name: 'Limpar exportações' })).toBeEnabled();

  await exportsCleanup.getByRole('button', { name: 'Limpar exportações' }).click();
  const dialog = page.getByRole('dialog', { name: 'Exportações retidas' });
  await expect(dialog).toContainText('Apagar exportações retidas nesta pasta de dados?');

  const cleanupResponsePromise = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === '/v1/data/cleanup' &&
      response.request().method() === 'POST',
  );
  await dialog.getByRole('button', { name: 'Limpar exportações' }).click();
  const cleanupResponse = await cleanupResponsePromise;
  await expectOk(cleanupResponse, 'Owner export cleanup');
  const cleanup = (await cleanupResponse.json()) as DataCleanupResult;
  expect(cleanup.target).toBe('exports');
  expect(cleanup.deleted_files).toBeGreaterThanOrEqual(2);
  expect(cleanup.deleted_directories).toBeGreaterThanOrEqual(1);
  expect(cleanup.skipped).toEqual([]);

  await expect(page.getByText('Manutenção concluída')).toBeVisible();
  await expect
    .poll(
      async () =>
        (await pathExists(seeded.exportManifest)) || (await pathExists(seeded.exportBundle)),
    )
    .toBe(false);
  await expect.poll(async () => (await readdir(seeded.exportRoot)).length).toBe(0);
  expect(await pathExists(seeded.crashFile)).toBe(true);
  expect(await readFile(seeded.crashFile, 'utf8')).toContain('kept during exports cleanup');

  const finalStatus = await getDataStatus(page.request, origin, ownerSession.token);
  expect(concernById(finalStatus, 'exports')?.file_count ?? 0).toBe(0);
  expect(concernById(finalStatus, 'crash')?.file_count).toBeGreaterThanOrEqual(1);
});

async function createSessionForUsername(
  request: APIRequestContext,
  origin: string,
  username: string,
  password: string,
): Promise<SessionResult> {
  const rosterResponse = await request.get(`${origin}/v1/session/roster`);
  await expectOk(rosterResponse, 'session roster');
  const roster = (await rosterResponse.json()) as SessionRoster;
  const user = roster.users.find((item) => item.username === username);
  if (!user) {
    throw new Error(`User ${username} not present in session roster.`);
  }
  return createSessionForUserId(request, origin, user.id, password);
}

async function createSessionForUserId(
  request: APIRequestContext,
  origin: string,
  userId: string,
  password: string,
): Promise<SessionResult> {
  const response = await request.post(`${origin}/v1/session`, {
    data: {
      user_id: userId,
      password,
    },
  });
  await expectOk(response, `session for user ${userId}`);
  return (await response.json()) as SessionResult;
}

async function createGestorUser(
  request: APIRequestContext,
  origin: string,
  ownerToken: string,
  suffix: string,
): Promise<UserView> {
  const response = await request.post(`${origin}/v1/users`, {
    headers: sessionHeaders(ownerToken),
    data: {
      username: `e2e.storage.${suffix}`,
      display_name: `E2E Storage ${suffix}`,
      password: GESTOR_PASSWORD,
    },
  });
  await expectOk(response, 'create Gestor storage user');
  return (await response.json()) as UserView;
}

async function getDataStatus(
  request: APIRequestContext,
  origin: string,
  token: string,
): Promise<DataStatusResponse> {
  const response = await request.get(`${origin}/v1/data/status`, {
    headers: sessionHeaders(token),
  });
  await expectOk(response, 'data status');
  return (await response.json()) as DataStatusResponse;
}

function resolveReportedDataDir(reported: string | null): string {
  if (!reported) {
    throw new Error('Backend did not report a data directory.');
  }
  const e2eRoot = process.env.CHANCELA_E2E_DATA_DIR;
  if (!e2eRoot) {
    throw new Error('CHANCELA_E2E_DATA_DIR is not set; refusing to seed storage fixtures.');
  }

  const resolved = path.resolve(reported);
  const allowedRoot = path.resolve(e2eRoot);
  const relative = path.relative(allowedRoot, resolved);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error(`Reported data directory is outside CHANCELA_E2E_DATA_DIR: ${reported}`);
  }
  return resolved;
}

async function seedStorageFixtures(dataDir: string, suffix: string) {
  const exportRoot = path.join(dataDir, 'exports');
  const nestedExportDir = path.join(exportRoot, `retained-${suffix}`);
  const exportManifest = path.join(exportRoot, `manifest-${suffix}.json`);
  const exportBundle = path.join(nestedExportDir, `bundle-${suffix}.zip`);
  const crashFile = path.join(dataDir, `crash-${suffix}.log`);

  await mkdir(nestedExportDir, { recursive: true });
  await writeFile(exportManifest, `{"kind":"retained-export","suffix":"${suffix}"}\n`, 'utf8');
  await writeFile(exportBundle, `PK e2e retained export ${suffix}\n`, 'utf8');
  await writeFile(crashFile, `crash evidence kept during exports cleanup ${suffix}\n`, 'utf8');

  return { exportRoot, exportManifest, exportBundle, crashFile };
}

function concernById(status: DataStatusResponse, id: string): DataUsageConcern | undefined {
  return status.usage.filesystem.find((concern) => concern.id === id);
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await stat(target);
    return true;
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return false;
    }
    throw error;
  }
}

async function expectOk(response: APIResponse, context: string): Promise<void> {
  if (!response.ok()) {
    throw new Error(`${context} failed: HTTP ${response.status()} ${await response.text()}`);
  }
}

function sessionHeaders(token: string): Record<string, string> {
  return { 'X-Chancela-Session': token };
}
