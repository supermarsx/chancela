/**
 * Runtime detection for the Tauri desktop shell.
 *
 * Everything Tauri-specific is gated on {@link isTauri}. In a plain browser the
 * global is absent, so the title bar renders nothing and `@tauri-apps/api` is
 * never imported — the browser bundle and vitest stay Tauri-free (the API is
 * only ever pulled in via the dynamic `import()` inside the desktop controls,
 * which only run when we're actually inside the WebView).
 */

/** True when running inside the Tauri WebView (vs. an ordinary browser tab). */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
