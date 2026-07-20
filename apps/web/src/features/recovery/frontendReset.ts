/**
 * "Repor interface" — the CLIENT-ONLY frontend reset (§2.11-1, taxonomy row 1).
 *
 * This is the deliberately non-destructive, low-risk sibling of the server wipes: it clears
 * the browser-local state (localStorage — the session token is in memory, plus the theme /
 * locale / appearance prefs, the safe-mode flag and crash-loop counter; sessionStorage; the
 * in-memory session token) and the React Query cache, then reloads into a clean boot. It
 * makes **NO server call and mutates NO server data** — the only recovery here is of a
 * wedged client, so it must never be confused with (or route through) the backend wipe.
 *
 * The reload is injectable so the flow is testable in jsdom (where `location.reload` is not
 * implemented); production passes the default.
 */
import type { QueryClient } from '@tanstack/react-query';
import { clearSessionToken } from '../../api/session';

/** Clear every browser-local store, swallowing access errors (private mode / quota). */
function clearStorage(store: Storage | undefined): void {
  try {
    store?.clear();
  } catch {
    // Storage unavailable — nothing to clear.
  }
}

/**
 * Perform the client-only reset: drop local + session storage, the in-memory session
 * token and the whole query cache, then reload. NO network request is made.
 */
export function resetFrontend(
  qc: QueryClient,
  reload: () => void = () => window.location.reload(),
): void {
  clearStorage(typeof window !== 'undefined' ? window.localStorage : undefined);
  clearStorage(typeof window !== 'undefined' ? window.sessionStorage : undefined);
  clearSessionToken();
  qc.clear();
  reload();
}
