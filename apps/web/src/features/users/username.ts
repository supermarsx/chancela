/**
 * Client-side mirror of the server's username rule (plan t14 §2.8): a non-empty
 * lowercase slug of `[a-z0-9._-]`, at most 64 characters. Uppercase is REJECTED, not
 * silently lowercased — the check exists to give the operator an immediate, matching
 * error before the round-trip, not to normalise the input (the server would 422 an
 * uppercase username too).
 */
import { t } from '../../i18n';

const USERNAME_RE = /^[a-z0-9._-]+$/;
export const USERNAME_MAX = 64;

/** Whether `value` is a valid username (same predicate the server enforces). */
export function isValidUsername(value: string): boolean {
  return value.length > 0 && value.length <= USERNAME_MAX && USERNAME_RE.test(value);
}

/**
 * A PT-PT validation message for an invalid username, or `null` when it is valid or
 * still empty (an empty field is "incomplete", not "invalid" — the submit button is
 * disabled rather than shouting at an untouched field).
 */
export function usernameError(value: string): string | null {
  if (value.length === 0) return null;
  if (value.length > USERNAME_MAX) return t('users.username.error.tooLong', { max: USERNAME_MAX });
  if (!USERNAME_RE.test(value)) {
    return t('users.username.error.invalidChars');
  }
  return null;
}
