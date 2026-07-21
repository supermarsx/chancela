/**
 * The addresses of the user-management surfaces, in one place (t89).
 *
 * There is exactly ONE address per action — a roster, a create screen and an edit screen — and
 * these constants are how that stays true: the roster row, the breadcrumbs, the redirects out of
 * the retired inline settings states and the tests all resolve the same string rather than each
 * spelling it. A second, hand-written copy of one of these paths is how the duplicate entry
 * points that t71 and t89 removed appeared in the first place.
 *
 * Kept in a module of their own, not beside a component, so importing an address never drags a
 * screen (and its credential managers) into another screen's lazy chunk.
 */

/** The roster — a Configurações sub-tab. Lists and filters; grants nothing. */
export const USERS_LIST_PATH = '/settings/users';

/** The create screen (t71). */
export const NEW_USER_PATH = '/users/new';

/**
 * The edit screen (t89). `hash` carries a fragment; since t103 the screen's sections are path
 * segments rather than anchors, so prefer {@link editUserSectionPath} over a `#…` here.
 */
export const editUserPath = (id: string, hash = '') => `/users/${encodeURIComponent(id)}${hash}`;

/**
 * One section of the edit screen (t103) — `/users/:id/access`.
 *
 * Here rather than assembled at each call site for the reason this whole module exists: the tab
 * segment is now part of an address, and an address spelled in two places is how the duplicate
 * entry points t71 and t89 removed appeared. The default section (`general`) deliberately has no
 * spelling of its own — it *is* {@link editUserPath}.
 */
export const editUserSectionPath = (id: string, section: string) =>
  `${editUserPath(id)}/${section}`;
