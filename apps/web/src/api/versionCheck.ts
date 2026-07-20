/**
 * Best-effort server/UI version reconciliation, run once at boot.
 *
 * A version skew between this UI build (`__APP_VERSION__`, inlined from package.json) and the
 * running server (`GET /health` → `version`) usually means a stale server binary — the same
 * condition that lets a `/v1` route the server predates fall through to the SPA shell and hand
 * the client `index.html` where it expects JSON. This only logs a console warning: it never
 * throws and never blocks rendering.
 */
import { api } from './client';

/** The UI build version, for callers that want to display it (e.g. the Sobre section). */
export const UI_VERSION: string = __APP_VERSION__;

/**
 * Render a CalVer manifest version (`YY.N.0`, e.g. `26.1.0`) as its user-facing
 * `YY.N` surface by dropping a trailing `.0` — manifests keep the 3-part semver
 * that Cargo/npm/Tauri require, while displays show the shorter release label.
 * A version without a trailing `.0` (e.g. a server reporting `9.9.9`) is returned
 * unchanged, so this is safe to apply to any version string, including the
 * server's `/health` value.
 */
export function displayVersion(version: string): string {
  return version.replace(/\.0$/, '');
}

/** Fire-and-forget: warn in the console when the server version differs from this UI build. */
export async function checkServerVersion(): Promise<void> {
  try {
    const health = await api.health();
    const server = health.version;
    if (server && server !== UI_VERSION) {
      console.warn(
        `[Chancela] Versão do servidor (${server}) diferente da interface (${UI_VERSION}). ` +
          'O servidor pode estar desatualizado — reinicie a aplicação/servidor se surgirem erros.',
      );
    }
  } catch {
    // A health probe failure is surfaced by the normal query paths; nothing to do here.
  }
}
