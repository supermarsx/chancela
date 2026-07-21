/**
 * Path-based section navigation (t97).
 *
 * Navigation identity — which section, which sub-tab, which record — lives in the URL PATH:
 * `/settings/operations/email`, not `/settings?sec=operacoes&sub=email`. The query
 * string is left to what it is actually good at: describing how you are LOOKING at a surface —
 * search terms, filters, sort, pagination, transient selections. The law reader's `?q=`, the
 * trust catalogue's filter set and the roster filters are all genuine parameters and stay.
 *
 * Two properties this module exists to guarantee:
 *
 *  - **A deep link is right on the first frame.** The section is DERIVED from the pathname on
 *    every render and never mirrored into state, so `/books/x/opening` paints the Termo tab
 *    immediately instead of flipping to it after a switch (the t62/t34 rule, preserved).
 *  - **An id containing a slash survives.** Template ids are `csc-ata-ag/v1`, and travel as
 *    `csc-ata-ag%2Fv1`. Everything here slices RAW, still-encoded segments off the pathname
 *    rather than re-encoding a decoded `useParams()` value, so the id is never re-encoded,
 *    double-encoded, or split into two segments.
 *
 * Push-versus-replace is the caller's decision and is preserved surface by surface: a sub-tab
 * switch the operator performed pushes where it pushed before, and replaces where it replaced.
 */
import { matchRoutes, useLocation, useNavigate, type RouteObject } from 'react-router-dom';

/** The raw (still percent-encoded) path segments of `pathname`. */
export function pathSegments(pathname: string): string[] {
  return pathname.split('/').filter((segment) => segment !== '');
}

/** Decode one segment, tolerating a malformed escape rather than throwing mid-render. */
function decodeSegment(segment: string | undefined): string | undefined {
  if (segment === undefined) return undefined;
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/**
 * The page's own address, with its section segments cut off — `/settings/operations/email`
 * is still the `/settings` page. The shell keys the routed content on this so that a
 * sub-tab switch does NOT remount the page (which would discard the settings working copy);
 * only a real page change does.
 */
export function pageKey(pathname: string, navDepth: number | undefined): string {
  if (navDepth === undefined) return pathname;
  const segments = pathSegments(pathname).slice(0, navDepth);
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

/**
 * {@link pageKey} for an arbitrary location, resolved against the route table rather than the
 * rendered match — so two locations can be compared without navigating to either.
 *
 * This is what lets the unsaved-changes guard ask "is this a different PAGE?" instead of "is this
 * a different pathname?". Since t97 those are no longer the same question: a sub-tab switch
 * changes the pathname, and a guard that blocked on that would prompt an operator to confirm
 * discarding their work for moving between two tabs of the surface they are still editing.
 */
export function pageKeyForLocation(routes: RouteObject[], pathname: string): string {
  const matches = matchRoutes(routes, pathname);
  const handle = matches?.[matches.length - 1]?.route.handle as { navDepth?: number } | undefined;
  return pageKey(pathname, handle?.navDepth);
}

export interface SectionNavConfig<T extends string> {
  /**
   * The page's own address, for a surface whose address is FIXED (`/archive`, `/settings`).
   * Stating it beats inferring it: the section index follows from it, and a link that arrives
   * from somewhere unexpected still resolves to this surface rather than to whatever the current
   * pathname happens to look like. Exactly one of `base` / `depth` is given.
   */
  base?: string;
  /**
   * 0-based index of the segment naming the section — for a surface whose base contains a
   * RECORD ID (`/books/:id`) and so cannot be written down. The base is sliced off the raw
   * pathname, which is what keeps an id containing `%2F` intact.
   */
  depth?: number;
  /** Narrow a raw segment to a section id; an unknown one must fall back, never
   *  blanking the panel. */
  parse: (raw: string | undefined) => T;
  /** The section that owns the bare base path and therefore carries no segment of its own. */
  fallback: T;
  /** Address of the default section when it is not the base itself (the dashboard lives at `/`). */
  defaultPath?: string;
  /** Replace instead of push. Per surface — see the note at the top of this file. */
  replace?: boolean;
  /**
   * Query params that belong to the section being left and must not travel with the switch.
   * Filters that describe the whole surface are NOT listed here — they survive, as they should.
   */
  dropParams?: readonly string[];
}

export interface SectionNav<T extends string> {
  section: T;
  /** The decoded segment as written, before `parse` narrowed it — for alias tables. */
  raw: string | undefined;
  /** The full address of `next`, query and fragment preserved — for `<Link>`s and assertions. */
  hrefFor: (next: T) => string;
  select: (next: T) => void;
}

/**
 * Read the active section out of the path and navigate between sections.
 *
 * Selecting a section rebuilds the address from the base, which drops anything below it: a
 * `sub` belongs to the section that declared it, so leaving the section opens the new one on
 * its own default rather than on a stale child id.
 */
export function useSectionNav<T extends string>(config: SectionNavConfig<T>): SectionNav<T> {
  const location = useLocation();
  const navigate = useNavigate();
  const segments = pathSegments(location.pathname);
  const depth = config.base === undefined ? (config.depth ?? 0) : pathSegments(config.base).length;
  const base = config.base ?? `/${segments.slice(0, depth).join('/')}`;
  const raw = decodeSegment(segments[depth]);
  const section = config.parse(raw);

  let search = location.search;
  if (config.dropParams && config.dropParams.length > 0) {
    const kept = new URLSearchParams(search);
    for (const name of config.dropParams) kept.delete(name);
    const rest = kept.toString();
    search = rest ? `?${rest}` : '';
  }
  const suffix = `${search}${location.hash}`;

  const hrefFor = (next: T) => {
    if (next === config.fallback) return `${config.defaultPath ?? base}${suffix}`;
    return `${base === '/' ? '' : base}/${encodeURIComponent(next)}${suffix}`;
  };

  return {
    section,
    raw,
    hrefFor,
    select: (next: T) => navigate(hrefFor(next), { replace: config.replace ?? false }),
  };
}
