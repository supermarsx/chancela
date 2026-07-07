/**
 * Playwright browser E2E config (plan t15 §2.5, t15-e2).
 *
 * The suite drives the **built** SPA (`apps/web/dist`) served by the **real**
 * `chancela-server` release binary over real HTTP — the only layer that reproduces the
 * original bug as the user saw it (a real browser parsing a real response) and catches
 * UI-render/route regressions. It is deliberately small and headless (no display
 * needed), runnable both locally and on ubuntu CI.
 *
 * `webServer` spawns the pre-built release binary (built by the `test:browser` npm
 * script) pointed at the built dist and a fresh, throwaway `CHANCELA_DATA_DIR`, so every
 * run starts from clean, hermetic state; `globalTeardown` removes that temp dir. The
 * binary and dist are built by `npm run test:browser` before Playwright starts — if the
 * binary is missing (someone ran `playwright test` directly), we fail fast with a hint.
 */
import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

const here = path.dirname(fileURLToPath(import.meta.url)); // apps/web
const repoRoot = path.resolve(here, '..', '..');

const serverBin = path.join(
  repoRoot,
  'target',
  'release',
  process.platform === 'win32' ? 'chancela-server.exe' : 'chancela-server',
);
const webDist = path.join(here, 'dist');

// A fixed loopback port (overridable) — the browser and the webServer must agree on a
// known URL. A fresh, unique data dir per run keeps each run hermetic; its path is
// published on the environment so globalTeardown can remove it afterwards.
const port = Number(process.env.CHANCELA_E2E_PORT ?? 8097);
const baseURL = `http://127.0.0.1:${port}`;
const dataDir =
  process.env.CHANCELA_E2E_DATA_DIR ??
  path.join(os.tmpdir(), `chancela-e2e-${Date.now()}-${process.pid}`);
process.env.CHANCELA_E2E_DATA_DIR = dataDir;

if (!fs.existsSync(serverBin)) {
  // Direct `playwright test` without the build step. `npm run test:browser` builds both.
  throw new Error(
    `chancela-server release binary not found at ${serverBin}.\n` +
      `Run \`npm run test:browser\` (builds server + dist first), or build it with\n` +
      `\`cargo build --release -p chancela-server\` and \`npm run build\` before \`playwright test\`.`,
  );
}

export default defineConfig({
  testDir: './e2e',
  // One server, one browser: the journey mutates shared server state, so run serially.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list']],
  globalTeardown: './e2e/global-teardown.ts',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `"${serverBin}"`,
    url: `${baseURL}/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      CHANCELA_ADDR: `127.0.0.1:${port}`,
      CHANCELA_WEB_DIST: webDist,
      CHANCELA_DATA_DIR: dataDir,
    },
  },
});
