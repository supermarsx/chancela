/**
 * The Suspense fallback for a lazily-loaded route.
 *
 * This is the one surface where nothing about the incoming page is known yet — not its
 * shape, not its length — so it gets the indeterminate {@link Loading} bar rather than a
 * skeleton. It is also the wait an operator sees most often, so it is given a little
 * vertical room instead of sitting flush under the tab bar.
 *
 * `Loading` already carries `role="status"` and `aria-busy`, so this wrapper deliberately
 * adds no second live region: nesting two would announce the same wait twice.
 */
import { Loading } from '../ui';

export function RouteLoading() {
  return (
    <div className="route-loading">
      <Loading />
    </div>
  );
}
