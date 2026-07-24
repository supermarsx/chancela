/**
 * Playwright browser E2E config (plan t15 §2.5, t15-e2).
 *
 * The suite drives the **built** SPA (`apps/web/dist`) served by the **real**
 * `chancela-server` release binary over real HTTP — the only layer that reproduces the
 * original bug as the user saw it (a real browser parsing a real response) and catches
 * UI-render/route regressions. It is deliberately small and headless (no display
 * needed), runnable both locally and on ubuntu CI.
 *
 * `webServer` spawns the pre-built release binary (built by the browser npm scripts)
 * pointed at the built dist and a fresh, throwaway `CHANCELA_DATA_DIR`, so every run
 * starts from clean, hermetic state; `globalTeardown` removes that temp dir. The binary
 * and dist are built by `npm run test:browser` / `npm run test:browser:matrix` before
 * Playwright starts — if the binary is missing (someone ran `playwright test` directly),
 * we fail fast with a hint.
 */
import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';

const here = path.dirname(fileURLToPath(import.meta.url)); // apps/web
const repoRoot = path.resolve(here, '..', '..');
const loopbackHost = '127.0.0.1';
const defaultPort = 8097;
const defaultPortSearchWidth = 100;
const strictCleanupEnv = 'CHANCELA_E2E_STRICT_CLEANUP';

const serverBin = path.join(
  repoRoot,
  'target',
  'release',
  process.platform === 'win32' ? 'chancela-server.exe' : 'chancela-server',
);
const webDist = path.join(here, 'dist');

const portProbeScript = `
const net = require('node:net');
const port = Number(process.argv[1]);
const server = net.createServer();

server.once('error', () => process.exit(1));
server.listen({ host: '${loopbackHost}', port, exclusive: true }, () => {
  server.close(() => process.exit(0));
});
`;

let selectedDefaultPortLockDir: string | undefined;

function errorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return undefined;
  }

  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : undefined;
}

function formatError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isStrictCleanupEnabled(): boolean {
  const value = process.env[strictCleanupEnv]?.toLowerCase();
  return value === '1' || value === 'true';
}

function isChancelaEnvKey(key: string): boolean {
  return key.toUpperCase().startsWith('CHANCELA_');
}

function isPreservedE2EEnvKey(key: string): boolean {
  return key.toUpperCase().startsWith('CHANCELA_E2E_');
}

function scrubInheritedChancelaEnv(): void {
  for (const key of Object.keys(process.env)) {
    if (isChancelaEnvKey(key) && !isPreservedE2EEnvKey(key)) {
      delete process.env[key];
    }
  }
}

function parseTcpPort(value: string, source: string): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error(`${source} must be an integer TCP port from 1 to 65535; got ${value}.`);
  }

  return port;
}

function canSignalProcess(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) === 'EPERM';
  }
}

function readLockOwnerPid(lockDir: string): number | undefined {
  try {
    const raw = fs.readFileSync(path.join(lockDir, 'owner.json'), 'utf8');
    const owner = JSON.parse(raw) as { pid?: unknown };
    return Number.isInteger(owner.pid) ? owner.pid : undefined;
  } catch {
    return undefined;
  }
}

function removeStalePortLock(lockDir: string): boolean {
  const ownerPid = readLockOwnerPid(lockDir);
  if (ownerPid !== undefined && canSignalProcess(ownerPid)) {
    return false;
  }

  try {
    fs.rmSync(lockDir, { recursive: true, force: true });
    return true;
  } catch {
    return false;
  }
}

function releasePortLock(lockDir: string | undefined): void {
  if (!lockDir) {
    return;
  }

  try {
    fs.rmSync(lockDir, { recursive: true, force: true });
  } catch {
    // Best effort only; stale locks are detected and cleaned on the next default run.
  }
}

function tryReserveDefaultPort(port: number): string | undefined {
  const lockDir = path.join(os.tmpdir(), `chancela-e2e-port-${port}.lock`);

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      fs.mkdirSync(lockDir);
      fs.writeFileSync(
        path.join(lockDir, 'owner.json'),
        `${JSON.stringify({ pid: process.pid, port, createdAt: new Date().toISOString() })}\n`,
      );
      return lockDir;
    } catch (error) {
      if (errorCode(error) !== 'EEXIST' || !removeStalePortLock(lockDir)) {
        return undefined;
      }
    }
  }

  return undefined;
}

function canBindLoopbackPort(port: number): boolean {
  const result = spawnSync(process.execPath, ['-e', portProbeScript, String(port)], {
    stdio: 'ignore',
    timeout: 5_000,
    windowsHide: true,
  });

  return result.status === 0;
}

function defaultPortCandidates(): number[] {
  return Array.from({ length: defaultPortSearchWidth }, (_, offset) => defaultPort + offset);
}

function selectDefaultPort(): number {
  for (const candidate of defaultPortCandidates()) {
    const lockDir = tryReserveDefaultPort(candidate);
    if (!lockDir) {
      continue;
    }

    if (canBindLoopbackPort(candidate)) {
      selectedDefaultPortLockDir = lockDir;
      return candidate;
    }

    releasePortLock(lockDir);
  }

  throw new Error(
    `No available Playwright E2E port found on ${loopbackHost}:${defaultPort}-${
      defaultPort + defaultPortSearchWidth - 1
    }. Set CHANCELA_E2E_PORT to an explicit free port.`,
  );
}

function selectPort(): number {
  const override = process.env.CHANCELA_E2E_PORT;
  if (override !== undefined && override !== '') {
    return parseTcpPort(override, 'CHANCELA_E2E_PORT');
  }

  return selectDefaultPort();
}

// The browser baseURL, Playwright webServer health URL, and server CHANCELA_ADDR all
// derive from this single port. Explicit CHANCELA_E2E_PORT is honored as-is; otherwise
// the default path scans 8097-8196 in order, with a temp lock to coordinate concurrent
// Playwright configs and a loopback bind probe to avoid ports already held by non-E2E
// processes.
const port = selectPort();
// Playwright may evaluate this config in more than one process; publish the selected
// default so later evaluations use the same baseURL as the webServer process.
process.env.CHANCELA_E2E_PORT = String(port);

// A fresh, unique data dir per run keeps each run hermetic; its path is published on the
// environment so globalTeardown can remove it afterwards.
const baseURL = `http://${loopbackHost}:${port}`;
const dataDir =
  process.env.CHANCELA_E2E_DATA_DIR ??
  path.join(os.tmpdir(), `chancela-e2e-${Date.now()}-${process.pid}`);
process.env.CHANCELA_E2E_DATA_DIR = dataDir;
const credentialKey = randomBytes(48).toString('base64');

// Playwright merges webServer.env over process.env, so scrub the runner environment before
// the real server is spawned. Keep CHANCELA_E2E_* controls intact for Playwright and pass
// the server's required CHANCELA_* values explicitly in webServer.env below.
scrubInheritedChancelaEnv();

function cleanupDataDirAtProcessExit(dir: string): void {
  if (process.platform === 'win32') {
    // globalTeardown schedules a delayed cleanup worker on Windows; this exit hook can
    // still run while the webServer process is releasing SQLite handles.
    return;
  }

  try {
    fs.rmSync(dir, {
      recursive: true,
      force: true,
      maxRetries: 3,
      retryDelay: 100,
    });
  } catch (error) {
    const message = `Playwright process-exit cleanup could not remove CHANCELA_E2E_DATA_DIR at ${dir}: ${formatError(error)}`;
    if (isStrictCleanupEnabled()) {
      console.error(message);
      process.exitCode = 1;
    } else {
      console.warn(`${message}\nSet ${strictCleanupEnv}=1 to make cleanup failures fatal.`);
    }
  }
}

process.once('exit', () => {
  releasePortLock(selectedDefaultPortLockDir);
  cleanupDataDirAtProcessExit(dataDir);
});

if (!fs.existsSync(serverBin)) {
  // Direct `playwright test` without the build step. The browser npm scripts build both.
  throw new Error(
    `chancela-server release binary not found at ${serverBin}.\n` +
      `Run \`npm run test:browser\` or \`npm run test:browser:matrix\` (builds server + dist first), or build it with\n` +
      `\`cargo build --release -p chancela-server\` and \`npm run build\` before \`playwright test\`.`,
  );
}

export default defineConfig({
  testDir: './e2e',
  // One server, one browser keeps CI resource use predictable; the e2e fixture resets
  // backend state before each test so retries do not inherit half-mutated data.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ['list'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
    ['junit', { outputFile: 'test-results/e2e-junit.xml' }],
  ],
  globalTeardown: './e2e/global-teardown.ts',
  outputDir: 'test-results',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: {
    baseURL,
    // The core specs assert the source-locale accessible names. Pin the browser locale so
    // environment language differences do not turn those assertions into runner-specific flakes.
    locale: 'pt-PT',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 5'] } },
  ],
  webServer: {
    command: `"${serverBin}"`,
    url: `${baseURL}/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
    env: {
      CHANCELA_ADDR: `${loopbackHost}:${port}`,
      CHANCELA_WEB_DIST: webDist,
      CHANCELA_DATA_DIR: dataDir,
      // The Linux CI host has no OS credential-sealing provider, while Windows can fall back to
      // DPAPI. Give this throwaway, hermetic server fresh test-only key material so TOTP and the
      // other encrypted-credential flows exercise the same fail-closed store on every platform.
      // The key exists only in this child environment; its data directory is unique to this run
      // and removed by globalTeardown.
      CHANCELA_CREDENTIAL_KEY: credentialKey,
    },
  },
});
