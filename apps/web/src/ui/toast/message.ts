/**
 * Extract a human-readable message from whatever a caller hands to `toast.error(...)`.
 *
 * An `ApiError` (api/client) is an `Error` subclass whose `.message` is already the
 * server's Portuguese `{ error }` text (with the HTTP status folded in at construction),
 * so the `Error` branch yields exactly that. A plain string passes through untouched;
 * anything else (a thrown object, `undefined`, …) falls back to a translated generic
 * string rather than surfacing `[object Object]`.
 */
export function toastMessage(input: string | unknown, fallback: string): string {
  if (typeof input === 'string') return input.trim() ? input : fallback;
  if (input instanceof Error) return input.message.trim() ? input.message : fallback;
  return fallback;
}
