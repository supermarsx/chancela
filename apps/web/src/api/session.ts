/**
 * Session-token store (plan t14 §2.8; persistence added by t51).
 *
 * The current-user session token lives in module state, mirrored into **`sessionStorage`** so a
 * page reload does not silently sign the operator out.
 *
 * ## Why this is now safe (the old comment here was out of date)
 *
 * This module used to hold the token in memory ONLY, on the reasoning that "the server keeps
 * sessions in memory too, so persisting a token client-side would only ever resurrect a token the
 * server has already forgotten". That is no longer true, and had already stopped being true before
 * this change:
 *
 *  - a data-dir deployment writes a **digest-only** durable registry (`sessions.json`) and
 *    re-authenticates a presented token after a restart — `crates/chancela-api/src/session.rs`
 *    (`DurableSessionRegistry`);
 *  - an HA deployment treats the shared cluster store as authoritative and a restarted/follower node
 *    reconstructs identity from it — `crates/chancela-api/src/actor.rs` (`resolve_session_actor`).
 *
 * So the server does remember, and dropping the token on reload was a pure UX loss: a refresh fell
 * back to the system ("api") actor with no permissions and forced a re-login.
 *
 * ## Why `sessionStorage` and not `localStorage` or a cookie
 *
 *  - **Never `localStorage`.** It is origin-scoped and outlives the browser session, so a bearer
 *    token there survives a walk-away on a shared or kiosk machine. `sessionStorage` is scoped to
 *    the **tab**: it survives F5 and in-app navigation, and is gone the moment the tab closes.
 *  - **Not an httpOnly cookie**, despite being the stronger answer to XSS in a plain web app. This
 *    client deliberately supports an **absolute, cross-origin** API base URL (`baseUrl.ts`, used by
 *    the mobile/companion shell), where a `SameSite=Strict` cookie is never sent, and the Tauri
 *    desktop WebView serves the app from a non-`https` custom-protocol origin, where a `Secure`
 *    cookie is refused. Cookie auth would also make every mutating route CSRF-reachable for the
 *    first time — today the custom `X-Chancela-Session` header makes the API structurally immune.
 *
 * ## What persistence does NOT do
 *
 * It does not extend a session by one second. The server owns the lifetime — a 24 h sliding idle
 * window plus an absolute cap (`CHANCELA_SESSION_MAX_LIFETIME`, default 7 days) anchored to the true
 * issue time in the durable/shared record. A restored token is simply *presented*; the server
 * decides. It also cannot satisfy a **step-up** re-authentication: `require_step_up`
 * (`crates/chancela-api/src/data.rs`) demands the acting user's current password or recovery phrase
 * in the request body, and a session token — restored or freshly minted — is not a proof there.
 *
 * The typed `api` client reads the token here on every request and, when present, sends it as
 * `X-Chancela-Session`. React reactivity does NOT flow through this module: the picker observes the
 * session via the `['session']` query, which re-reads the header after the token changes.
 */

/** The `sessionStorage` key holding the active token. Tab-scoped; never `localStorage`. */
const STORAGE_KEY = 'chancela.session-token';

/**
 * `sessionStorage`, or `null` where it is unavailable — server-side rendering, a jsdom test that
 * did not install it, a sandboxed iframe, or a browser configured to deny storage. Every access
 * below tolerates `null` and simply degrades to the previous in-memory-only behaviour rather than
 * throwing on boot.
 */
function storage(): Storage | null {
  try {
    return typeof globalThis.sessionStorage === 'undefined' ? null : globalThis.sessionStorage;
  } catch {
    return null;
  }
}

/** Read the persisted token at module load, so the very first request after a reload carries it. */
function restore(): string | null {
  try {
    const stored = storage()?.getItem(STORAGE_KEY);
    return stored && stored.trim() !== '' ? stored : null;
  } catch {
    return null;
  }
}

let sessionToken: string | null = restore();

/**
 * Listeners notified whenever the session token is cleared — most importantly by a 401
 * from the server (the server forgot the token, e.g. it was revoked or aged out). The query layer
 * registers a listener that invalidates the `['session']` query so the UI re-reads the
 * session immediately instead of showing a stale signed-in user. Kept as a registry
 * here (rather than a direct QueryClient import) so this module stays React-free.
 */
const clearedListeners = new Set<() => void>();

/** The current session token, or `null` when signed out (the system/"api" actor). */
export function getSessionToken(): string | null {
  return sessionToken;
}

/** Store the token issued by `POST /v1/session` (in memory and in tab-scoped `sessionStorage`). */
export function setSessionToken(token: string): void {
  sessionToken = token;
  try {
    storage()?.setItem(STORAGE_KEY, token);
  } catch {
    /* storage full or denied — the in-memory token still works for this page load */
  }
}

/**
 * Forget the token (sign-out, a 401, or a session the server no longer honours); subsequent
 * requests carry no session header. Clears the persisted copy too, so signing out on a shared
 * machine really ends it on this side — the server side is ended by `DELETE /v1/session`, which
 * revokes the token in the live map, the durable digest registry and the shared cluster store.
 */
export function clearSessionToken(): void {
  sessionToken = null;
  try {
    storage()?.removeItem(STORAGE_KEY);
  } catch {
    /* nothing to do; the in-memory token is already gone */
  }
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
