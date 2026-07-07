/**
 * Restart the application (t26 crash-recovery action).
 *
 * In the Tauri desktop shell a true relaunch — tear down the process and start it
 * again — is the only way to recover a wedged embedded server or a corrupt in-memory
 * state, so we hand off to the official `tauri-plugin-process` `relaunch()`. The plugin
 * module is pulled in through a dynamic `import()` so it lands in the lazily-split
 * `@tauri-apps/*` chunk: an ordinary browser build and vitest never resolve it.
 *
 * In a plain browser there is no process to relaunch — a full-document `location.reload()`
 * is the equivalent fresh start, and it is also the fallback if the desktop hand-off ever
 * fails (plugin missing, ACL) so the button is never dead.
 */
import { isTauri } from './tauri';

/** Restart the app (desktop) or reload the document (browser). Never throws. */
export async function relaunchApp(): Promise<void> {
  if (isTauri()) {
    try {
      const { relaunch } = await import('@tauri-apps/plugin-process');
      await relaunch();
      return;
    } catch (err) {
      // Fall through to a reload rather than leaving the restart button dead.
      console.error('relaunchApp: process plugin relaunch failed, reloading instead', err);
    }
  }
  window.location.reload();
}
