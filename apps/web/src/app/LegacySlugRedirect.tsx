/**
 * The one place a Portuguese address is turned into its English equivalent (t97b).
 *
 * Mounted on the catch-all route, so it costs nothing on a normal navigation: a legacy address
 * matches no English route, falls through to `*`, is translated here and `replace`d — never
 * pushed, so an old link is not left as a Back-button stop. Anything it cannot translate renders
 * the real Not Found page, exactly as before.
 *
 * The two routes that live OUTSIDE the app shell (`/bem-vindo`, `/assinatura-externa`) get their
 * own explicit entries in the route table rather than relying on this fall-through: both are
 * reachable while signed OUT, and the catch-all sits inside the shell behind the auth gate, which
 * would swallow the redirect for exactly the visitors those two addresses exist for.
 *
 * See {@link ./legacySlugs} for the table and for why these redirects are permanent.
 */
import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { translateLegacyAddress } from './legacySlugs';

export function LegacySlugRedirect({ children }: { children?: ReactNode }) {
  const location = useLocation();
  const translated = translateLegacyAddress(location.pathname, location.search);

  if (translated === null || translated.pathname === location.pathname) {
    return <>{children}</>;
  }

  return <Navigate to={`${translated.pathname}${translated.search}${location.hash}`} replace />;
}
