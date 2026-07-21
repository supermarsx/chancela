/**
 * The former standalone CAE facility (`/cae`) is now folded into Ferramentas (t22-web
 * item 3): the catalog metadata, refresh and consultation all live on that surface. This
 * route redirects there so existing deep links to `/cae` keep working, preserving any
 * query string (`?code=`/`?rev=`) so a linked code opens straight in the explorer.
 */
import { Navigate, useLocation } from 'react-router-dom';

export function CaePage() {
  const { search } = useLocation();
  return <Navigate to={{ pathname: '/tools', search }} replace />;
}
