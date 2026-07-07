/**
 * Remove the throwaway `CHANCELA_DATA_DIR` the run used, so no per-run state leaks onto
 * disk. The path is published by `playwright.config.ts` on `CHANCELA_E2E_DATA_DIR`.
 */
import fs from 'node:fs';

export default function globalTeardown(): void {
  const dir = process.env.CHANCELA_E2E_DATA_DIR;
  if (dir && fs.existsSync(dir)) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
