/**
 * In-memory session-token store (plan t14 §2.8).
 *
 * The current-user session token lives ONLY in module state — deliberately NOT in
 * `localStorage`/`sessionStorage` or the query cache. The server keeps sessions in
 * memory too (they reset on restart), so persisting a token client-side would only
 * ever resurrect a token the server has already forgotten. A page reload therefore
 * drops the token and the app falls back to the system ("api") actor until the
 * operator picks a user again — which is the intended v1 behaviour (attribution, not
 * access control).
 *
 * The typed `api` client reads the token here on every request and, when present,
 * sends it as `X-Chancela-Session` so the server attributes the ledger `actor` to the
 * active user. React reactivity does NOT flow through this module: the picker observes
 * the session via the `['session']` query, which re-reads the header after the token
 * changes.
 */
let sessionToken: string | null = null;

/**
 * Listeners notified whenever the session token is cleared — most importantly by a 401
 * from the server (the server forgot the token, e.g. after a restart). The query layer
 * registers a listener that invalidates the `['session']` query so the UI re-reads the
 * session immediately instead of showing a stale signed-in user. Kept as a registry
 * here (rather than a direct QueryClient import) so this module stays React-free.
 */
const clearedListeners = new Set<() => void>();

/** The current session token, or `null` when signed out (the system/"api" actor). */
export function getSessionToken(): string | null {
  return sessionToken;
}

/** Store the token issued by `POST /v1/session` (kept in memory only). */
export function setSessionToken(token: string): void {
  sessionToken = token;
}

/** Forget the token (sign-out); subsequent requests carry no session header. */
export function clearSessionToken(): void {
  sessionToken = null;
  for (const cb of clearedListeners) {
    try {
      cb();
    } catch {
      /* a listener throwing must not break the clear */
    }
  }
}

/**
 * Register a callback fired whenever the token is cleared (sign-out OR a 401). Returns
 * an unsubscribe function. The query layer uses this to invalidate the session query.
 */
export function onSessionCleared(cb: () => void): () => void {
  clearedListeners.add(cb);
  return () => {
    clearedListeners.delete(cb);
  };
}
