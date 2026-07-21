/**
 * Keeps every pre-t97 `?sec=`/`?sub=`/`?tool=`/`?leg=`/`?view=`/`?painel=` address working.
 *
 * Those URLs are addressable today — several were made addressable only hours ago — and are
 * bookmarked, pasted into tickets and, in the case of `/configuracoes?sec=dados`, built
 * server-side by the dashboard alert routes. A 404 (or a silent landing on the default tab)
 * on one of them is a regression, so each legacy query param is translated into its path
 * equivalent and REPLACED into history: the old address never becomes a Back-button stop.
 *
 * The translation is purely mechanical — it moves values from query to path and nothing else.
 * Aliases (Configurações' retired `?sec=email` and friends) are resolved one level down, by the
 * page that owns them, so this component stays free of any surface's vocabulary.
 */
import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { pathSegments } from './navPath';

export interface LegacyNavRedirectProps {
  /**
   * The legacy param names per path level, outermost first. A level lists alternatives because
   * one surface can spell the same level two ways: Ferramentas' second level is `?sec=` under
   * the PDF validator and `?leg=` under Legislação.
   */
  levels: string[][];
  /** How many leading segments belong to the page itself (the section segments come after). */
  depth: number;
  /** Base override, for a surface whose default section has its own address (`/` → `/painel`). */
  base?: string;
  children: ReactNode;
}

export function LegacyNavRedirect({ levels, depth, base, children }: LegacyNavRedirectProps) {
  const location = useLocation();
  const search = new URLSearchParams(location.search);

  const values: string[] = [];
  for (const names of levels) {
    const value = names
      .map((name) => search.get(name))
      .find((v): v is string => v !== null && v !== '');
    // Stop at the first gap: a `?sub=` with no `?sec=` addressed nothing before this change
    // either, so it must not be promoted into a top-level section segment.
    if (value === undefined) break;
    values.push(value);
  }

  if (values.length === 0) return <>{children}</>;

  for (const names of levels) for (const name of names) search.delete(name);
  const rest = search.toString();
  const root = base ?? `/${pathSegments(location.pathname).slice(0, depth).join('/')}`;
  const path = `${root === '/' ? '' : root}/${values.map(encodeURIComponent).join('/')}`;
  return <Navigate to={`${path}${rest ? `?${rest}` : ''}${location.hash}`} replace />;
}
