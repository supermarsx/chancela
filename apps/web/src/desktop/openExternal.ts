/**
 * Open an external URL in the user's environment, not inside the app.
 *
 * In the Tauri desktop shell the WebView is navigated to the in-process embedded
 * server, so a bare `<a target="_blank">` (or `window.open`) would try to open the
 * link *inside* WebView2 — a jarring, chrome-less navigation with no back button.
 * Instead we hand the URL to the OS via the official `tauri-plugin-opener`, which
 * launches the user's default browser. The plugin module is pulled in through a
 * dynamic `import()` so it lands in the same lazily-split chunk as the other
 * `@tauri-apps/*` code: an ordinary browser build and vitest never resolve it.
 *
 * In a plain browser there is nothing to hand off to — `window.open` with
 * `_blank`/`noopener` is exactly the right behaviour, and it is what a normal
 * anchor would have done anyway.
 */
import { isTauri } from './tauri';

const SAFE_EXTERNAL_PROTOCOLS = new Set(['http:', 'https:', 'mailto:', 'tel:']);

function isSafeExternalUrl(url: string): boolean {
  try {
    return SAFE_EXTERNAL_PROTOCOLS.has(new URL(url).protocol.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * Route `url` to the user's default browser (desktop) or a new tab (browser).
 * Never throws to the caller: a failed hand-off is logged and swallowed so a
 * mis-typed or unreachable URL can't break the click handler.
 */
export async function openExternal(url: string): Promise<void> {
  // Defence-in-depth: never hand a non-http(s)/mailto/tel scheme to Tauri, the
  // OS opener, or window.open.
  if (!isSafeExternalUrl(url)) return;

  if (isTauri()) {
    try {
      const { openUrl } = await import('@tauri-apps/plugin-opener');
      await openUrl(url);
      return;
    } catch (err) {
      // If the hand-off fails (plugin missing, ACL, malformed URL) fall through
      // to window.open rather than leaving the click dead.
      console.error('openExternal: opener plugin failed, falling back', err);
    }
  }
  window.open(url, '_blank', 'noopener,noreferrer');
}
