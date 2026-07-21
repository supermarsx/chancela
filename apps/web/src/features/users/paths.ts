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
export const USERS_LIST_PATH = '/configuracoes?sec=utilizadores';

/** The create screen (t71). */
export const NEW_USER_PATH = '/utilizadores/novo';

/** The edit screen (t89). `hash` carries a section anchor such as `#acesso`. */
export const editUserPath = (id: string, hash = '') =>
  `/utilizadores/${encodeURIComponent(id)}${hash}`;
