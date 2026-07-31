/**
 * The addresses of the self-service account area, in one place.
 *
 * Same discipline as `features/users/paths.ts`, and for the same reason: an address spelled in two
 * places is how a second entry point to one action appears. The top-bar user picker, the pointer
 * on the administrative security tab and the tests all resolve these constants rather than each
 * writing `/account/...` by hand.
 *
 * Slugs are ENGLISH, like every other path segment in this app: an address is an identifier, not
 * copy, and the user-facing language lives in the catalog.
 *
 * Kept in a module of its own so importing an address never drags the account screen — and the
 * credential managers it mounts — into another screen's lazy chunk.
 */

/** The account area. `profile` is the default section and carries no segment of its own. */
export const ACCOUNT_PATH = '/account';

/** One section of the account area — `/account/security`. */
export const accountSectionPath = (section: string) => `${ACCOUNT_PATH}/${section}`;

/** Security, named once because two surfaces link to it. */
export const ACCOUNT_SECURITY_PATH = accountSectionPath('security');
