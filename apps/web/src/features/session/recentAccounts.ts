/**
 * Recently-used sign-in identifiers — a DEVICE-LOCAL convenience list (t33).
 *
 * ## Why this exists
 * The sign-in screen used to render the server's roster: every account on the instance,
 * to anybody who could reach the page. That is user enumeration — a signed-out visitor
 * learns exactly which usernames to spray or phish. The identifier is now TYPED, and the
 * only names ever shown back are the ones that have successfully signed in *on this
 * device*. That list is derived entirely from what happened in this browser, so it tells
 * an attacker who already has the browser nothing they could not read from it anyway.
 *
 * ## What is stored, and what is deliberately NOT
 * Stored: the identifier the operator typed, the display name the server returned AFTER a
 * successful sign-in, and a timestamp used only for ordering. That is the whole record.
 *
 * NEVER stored: passwords, session tokens, user ids, permissions, or anything else that
 * could authenticate a request. The session token stays in memory (see `api/session`) and
 * this module must not become the place that regresses it. Two further rules keep the
 * list from becoming an oracle in its own right:
 *
 *  1. Only a **successful** sign-in is remembered. If failures were recorded the list
 *     would answer "is this a real username?" for anyone with a minute at the keyboard.
 *  2. Entries are removable one at a time from the UI, and "Repor interface"
 *     (`features/recovery/frontendReset`) clears localStorage wholesale — the shared /
 *     kiosk escape hatch.
 *
 * All storage access is guarded: a browser with storage disabled (private mode, quota)
 * degrades to "no recents", never to a thrown error on the sign-in path.
 */

/** localStorage key holding the JSON-encoded {@link RecentAccount} array. */
const RECENT_ACCOUNTS_KEY = 'chancela.signin.recentAccounts';

/** How many identifiers we keep; older entries fall off the end. */
export const MAX_RECENT_ACCOUNTS = 5;

/**
 * One remembered sign-in identifier. Non-secret by construction — if a field cannot be
 * read off the sign-in form or off a *successful* session response, it does not belong here.
 */
export interface RecentAccount {
  /** The identifier typed into the username field. */
  username: string;
  /** The display name the server returned after the successful sign-in, when it had one. */
  displayName?: string;
  /** Epoch millis of the last successful sign-in — ordering only. */
  lastUsedAt: number;
}

function readStorage(): string | null {
  try {
    return window.localStorage.getItem(RECENT_ACCOUNTS_KEY);
  } catch {
    return null;
  }
}

function writeStorage(value: RecentAccount[]): void {
  try {
    window.localStorage.setItem(RECENT_ACCOUNTS_KEY, JSON.stringify(value));
  } catch {
    // Storage unavailable — the convenience list simply does not persist.
  }
}

/**
 * Coerce one parsed entry, dropping anything malformed or unrecognised. Unknown keys are
 * discarded rather than carried through, so a future/tampered payload can never smuggle
 * an extra field (a token, say) back into the app.
 */
function parseEntry(value: unknown): RecentAccount | null {
  if (typeof value !== 'object' || value === null) return null;
  const record = value as Record<string, unknown>;
  const username = typeof record.username === 'string' ? record.username.trim() : '';
  if (username.length === 0) return null;
  const displayName = typeof record.displayName === 'string' ? record.displayName : undefined;
  const lastUsedAt = typeof record.lastUsedAt === 'number' && Number.isFinite(record.lastUsedAt)
    ? record.lastUsedAt
    : 0;
  return displayName ? { username, displayName, lastUsedAt } : { username, lastUsedAt };
}

/** The remembered identifiers, most recently used first. Never throws. */
export function readRecentAccounts(): RecentAccount[] {
  const raw = readStorage();
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const entries = parsed
    .map(parseEntry)
    .filter((entry): entry is RecentAccount => entry !== null)
    .sort((a, b) => b.lastUsedAt - a.lastUsedAt);
  return entries.slice(0, MAX_RECENT_ACCOUNTS);
}

/**
 * Record a **successful** sign-in and return the new list. Call this from the mutation's
 * `onSuccess` only — never on an error path, never optimistically before the server has
 * accepted the credentials.
 */
export function rememberAccount(
  account: { username: string; displayName?: string },
  now: number = Date.now(),
): RecentAccount[] {
  const username = account.username.trim();
  if (username.length === 0) return readRecentAccounts();
  const entry: RecentAccount = account.displayName
    ? { username, displayName: account.displayName, lastUsedAt: now }
    : { username, lastUsedAt: now };
  const rest = readRecentAccounts().filter(
    (r) => r.username.toLowerCase() !== username.toLowerCase(),
  );
  const next = [entry, ...rest].slice(0, MAX_RECENT_ACCOUNTS);
  writeStorage(next);
  return next;
}

/**
 * Drop one identifier (the ✕ on its row) and return the new list. The removal is written
 * through immediately, so it survives a reload — "removed" must mean removed, not
 * "hidden until the next boot".
 */
export function forgetAccount(username: string): RecentAccount[] {
  const next = readRecentAccounts().filter(
    (r) => r.username.toLowerCase() !== username.trim().toLowerCase(),
  );
  writeStorage(next);
  return next;
}
