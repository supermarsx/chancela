import { spawn } from 'node:child_process';
import console from 'node:console';
import { createRequire } from 'node:module';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { setTimeout } from 'node:timers/promises';

const require = createRequire(import.meta.url);

const cleanupStatusFileEnv = 'CHANCELA_E2E_CLEANUP_STATUS_FILE';
const dataDirEnv = 'CHANCELA_E2E_DATA_DIR';
const cleanupProofTimeoutMs = 90_000;
const cleanupProofPollMs = 250;

async function pathExists(target) {
  try {
    await stat(target);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return false;
    }

    throw error;
  }
}

async function readCleanupStatus(statusFile) {
  try {
    return JSON.parse(await readFile(statusFile, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return undefined;
    }

    throw error;
  }
}

async function waitForCleanupProof(dataDir, statusFile) {
  const deadline = Date.now() + cleanupProofTimeoutMs;
  let lastStatus;

  while (Date.now() <= deadline) {
    lastStatus = await readCleanupStatus(statusFile);

    if (lastStatus?.status === 'removed') {
      return;
    }

    if (lastStatus?.status === 'failed') {
      throw new Error(
        `Playwright cleanup worker failed to remove CHANCELA_E2E_DATA_DIR at ${dataDir}: ${
          lastStatus.error ?? 'unknown cleanup error'
        }`,
      );
    }

    if (!(await pathExists(dataDir))) {
      return;
    }

    await setTimeout(cleanupProofPollMs);
  }

  throw new Error(
    `Timed out after ${cleanupProofTimeoutMs}ms waiting for Playwright cleanup proof for ` +
      `CHANCELA_E2E_DATA_DIR at ${dataDir}. Last cleanup status: ${
        lastStatus === undefined ? 'none' : JSON.stringify(lastStatus)
      }`,
  );
}

function runPlaywright(args, env) {
  const cli = require.resolve('@playwright/test/cli');
  const child = spawn(process.execPath, [cli, 'test', ...args], {
    env,
    stdio: 'inherit',
    windowsHide: true,
  });

  return new Promise((resolve) => {
    child.on('exit', (code, signal) => {
      resolve({ code: code ?? 1, signal });
    });
    child.on('error', (error) => {
      console.error(`Could not start Playwright: ${error.message}`);
      resolve({ code: 1, signal: null });
    });
  });
}

const proofRoot = await mkdtemp(path.join(os.tmpdir(), 'chancela-e2e-cleanup-proof-'));
const dataDir = process.env[dataDirEnv] || path.join(proofRoot, 'data');
const cleanupStatusFile = process.env[cleanupStatusFileEnv] || path.join(proofRoot, 'cleanup.json');
const env = {
  ...process.env,
  [dataDirEnv]: dataDir,
  [cleanupStatusFileEnv]: cleanupStatusFile,
};

const result = await runPlaywright(process.argv.slice(2), env);
let cleanupFailed = false;

try {
  await waitForCleanupProof(dataDir, cleanupStatusFile);
} catch (error) {
  cleanupFailed = true;
  console.error(error instanceof Error ? error.message : String(error));
}

if (!cleanupFailed) {
  await rm(proofRoot, { recursive: true, force: true });
}

if (result.signal) {
  console.error(`Playwright exited after signal ${result.signal}.`);
}

process.exitCode = cleanupFailed ? 1 : result.code;
