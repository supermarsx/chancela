/**
 * Remove the throwaway `CHANCELA_DATA_DIR` the run used, so no per-run state leaks onto
 * disk. The path is published by `playwright.config.ts` on `CHANCELA_E2E_DATA_DIR`.
 */
import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { setTimeout } from 'node:timers/promises';

const STRICT_CLEANUP_ENV = 'CHANCELA_E2E_STRICT_CLEANUP';
const CLEANUP_STATUS_FILE_ENV = 'CHANCELA_E2E_CLEANUP_STATUS_FILE';
const CLEANUP_RETRY_DELAYS_MS = [100, 250, 500, 1_000, 2_000];
const POST_TEARDOWN_RETRY_DELAYS_MS = [500, 1_000, 2_000, 4_000, 8_000, 16_000, 32_000];

const POST_TEARDOWN_CLEANUP_SCRIPT = `
const { rm } = require('node:fs/promises');
const { mkdir, writeFile } = require('node:fs/promises');
const path = require('node:path');
const { setTimeout } = require('node:timers/promises');

const dir = process.argv[1];
const statusFile = process.argv[2];
const delays = [${POST_TEARDOWN_RETRY_DELAYS_MS.join(', ')}];

async function writeStatus(status) {
  if (!statusFile) {
    return;
  }

  try {
    await mkdir(path.dirname(statusFile), { recursive: true });
    await writeFile(statusFile, JSON.stringify({
      ...status,
      dir,
      finishedAt: new Date().toISOString(),
    }) + '\\n');
  } catch {
    // The wrapper also checks the directory itself, so status write failures are not fatal here.
  }
}

(async () => {
  let lastError;

  for (let attempt = 0; attempt <= delays.length; attempt += 1) {
    try {
      await rm(dir, { recursive: true, force: true });
      await writeStatus({ status: 'removed', attempts: attempt + 1 });
      return;
    } catch (error) {
      lastError = error;

      const delayMs = delays[attempt];
      if (delayMs === undefined) {
        await writeStatus({
          status: 'failed',
          attempts: attempt + 1,
          error: error instanceof Error ? error.message : String(error),
          code: error && typeof error === 'object' ? error.code : undefined,
        });
        return;
      }

      await setTimeout(delayMs);
    }
  }

  await writeStatus({
    status: 'failed',
    attempts: delays.length + 1,
    error: lastError instanceof Error ? lastError.message : String(lastError),
    code: lastError && typeof lastError === 'object' ? lastError.code : undefined,
  });
})();
`;

function isStrictCleanupEnabled(): boolean {
  const value = process.env[STRICT_CLEANUP_ENV]?.toLowerCase();
  return value === '1' || value === 'true';
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function removeDataDir(dir: string): Promise<void> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= CLEANUP_RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      await rm(dir, { recursive: true, force: true });
      return;
    } catch (error) {
      lastError = error;

      const delayMs = CLEANUP_RETRY_DELAYS_MS[attempt];
      if (delayMs === undefined) {
        break;
      }

      await setTimeout(delayMs);
    }
  }

  throw lastError;
}

function schedulePostTeardownCleanup(dir: string): boolean {
  try {
    // Playwright runs globalTeardown before stopping webServer. Continue cleanup after
    // this hook returns so Windows can release SQLite handles held by the server process.
    const cleanupStatusFile = process.env[CLEANUP_STATUS_FILE_ENV];
    const child = spawn(
      process.execPath,
      ['-e', POST_TEARDOWN_CLEANUP_SCRIPT, dir, cleanupStatusFile ?? ''],
      {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
      },
    );

    child.unref();
    return true;
  } catch {
    return false;
  }
}

function deferInitialCleanupUntilWebServerStops(): boolean {
  return process.platform === 'win32';
}

export default async function globalTeardown(): Promise<void> {
  const dir = process.env.CHANCELA_E2E_DATA_DIR;
  if (!dir) {
    return;
  }

  if (deferInitialCleanupUntilWebServerStops()) {
    const scheduled = schedulePostTeardownCleanup(dir);
    if (scheduled) {
      return;
    }

    const message =
      `Playwright global teardown could not schedule delayed cleanup for ` +
      `CHANCELA_E2E_DATA_DIR at ${dir}.`;
    if (isStrictCleanupEnabled()) {
      throw new Error(message);
    }

    console.warn(`${message}\nSet ${STRICT_CLEANUP_ENV}=1 to make cleanup failures fatal.`);
    return;
  }

  try {
    await removeDataDir(dir);
  } catch (error) {
    const message =
      `Playwright global teardown could not remove CHANCELA_E2E_DATA_DIR at ${dir} ` +
      `after ${CLEANUP_RETRY_DELAYS_MS.length + 1} attempts: ${formatError(error)}`;

    if (isStrictCleanupEnabled()) {
      throw new Error(message);
    }

    const scheduled = schedulePostTeardownCleanup(dir);
    const fallback = scheduled
      ? 'Scheduled a best-effort background cleanup for after Playwright stops the web server.'
      : 'Could not schedule a background cleanup.';

    console.warn(
      `${message}\n${fallback}\nSet ${STRICT_CLEANUP_ENV}=1 to make cleanup failures fatal.`,
    );
  }
}
