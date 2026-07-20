/**
 * Safe mode + crash-loop detection (t26).
 *
 * Safe mode is a minimal, self-healing boot: the default theme is forced, the
 * leather/animations/button-texture chrome is bypassed and the persisted settings
 * are NOT applied, so a configuration that crashes the shell on every launch can
 * still be reached and repaired. It is entered three ways:
 *   1. Automatically, when the app crashes {@link CRASH_THRESHOLD} times inside
 *      {@link CRASH_WINDOW_MS} (a crash loop) — the error boundary trips it.
 *   2. Manually, via the `?safe=1` query parameter (a support/user escape hatch).
 *   3. From the desktop shell, when `CHANCELA_SAFE_MODE` is set — lib.rs appends the
 *      same `?safe=1` to the URL it navigates the WebView to, so there is ONE
 *      mechanism to reason about.
 *
 * ## Why localStorage (a deliberate exception)
 *
 * The rest of the app avoids `localStorage` (state lives server-side), but safe-mode
 * state and the crash-loop counter MUST survive a reload/relaunch: the whole point is
 * that a boot which crashes before the shell mounts still remembers it crashed, so the
 * next boot can force safe mode. There is no server round-trip available on a shell
 * that cannot render, and a reload wipes in-memory state — so a persisted, synchronous,
 * pre-React store is exactly what this needs. Access is fully guarded so a browser with
 * storage disabled (private mode, quota) degrades to "no persistence" rather than
 * throwing during a crash — the last place we can afford a second failure.
 */

/** Number of crashes within {@link CRASH_WINDOW_MS} that trips auto safe mode. */
export const CRASH_THRESHOLD = 3;
/** Sliding window (5 minutes) over which crashes are counted. */
export const CRASH_WINDOW_MS = 5 * 60 * 1000;

const SAFE_MODE_FLAG_KEY = 'chancela.safeMode';
const CRASH_LOG_KEY = 'chancela.crashLog';
/** Query parameter that forces safe mode for a single boot (manual + desktop env). */
export const SAFE_MODE_QUERY_PARAM = 'safe';

/** Read a key from localStorage, swallowing any access error (disabled/quota). */
function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // Storage unavailable — safe mode simply won't persist across this reload.
  }
}

function removeStorage(key: string): void {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Nothing to do; a missing key is already the desired state.
  }
}

/** True when `?safe=1` (or any truthy `?safe=`) is present on the current URL. */
export function hasSafeModeQueryParam(): boolean {
  try {
    const value = new URLSearchParams(window.location.search).get(SAFE_MODE_QUERY_PARAM);
    return value === '1' || value === 'true' || value === '';
  } catch {
    return false;
  }
}

/**
 * Whether this boot is running in safe mode: either the URL flag is set (manual /
 * desktop env) or a previous boot persisted the safe-mode flag (auto crash-loop).
 */
export function isSafeMode(): boolean {
  return hasSafeModeQueryParam() || readStorage(SAFE_MODE_FLAG_KEY) === '1';
}

/** Persist the safe-mode flag so the NEXT boot comes up minimal. */
export function enterSafeMode(): void {
  writeStorage(SAFE_MODE_FLAG_KEY, '1');
}

/** Clear the crash-loop counter (called on a clean exit from safe mode). */
export function clearCrashLog(): void {
  removeStorage(CRASH_LOG_KEY);
}

/**
 * Leave safe mode: drop the persisted flag AND the crash counter, so the next boot
 * starts clean with settings applied again. Stripping the URL `?safe=1` is the
 * caller's job (a navigation), since it lives outside storage.
 */
export function exitSafeMode(): void {
  removeStorage(SAFE_MODE_FLAG_KEY);
  clearCrashLog();
}

function readCrashTimestamps(): number[] {
  const raw = readStorage(CRASH_LOG_KEY);
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((n): n is number => typeof n === 'number' && Number.isFinite(n));
  } catch {
    return [];
  }
}

/**
 * Record a crash at `now` and report whether the crash-loop threshold has tripped.
 * Only timestamps inside the sliding window are kept, so a slow trickle of unrelated
 * errors over a long session never accumulates into a false positive.
 */
export function recordCrash(now: number = Date.now()): boolean {
  const recent = readCrashTimestamps().filter((t) => now - t < CRASH_WINDOW_MS);
  recent.push(now);
  writeStorage(CRASH_LOG_KEY, JSON.stringify(recent));
  return recent.length >= CRASH_THRESHOLD;
}
