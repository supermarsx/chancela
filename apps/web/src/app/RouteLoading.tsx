/**
 * The Suspense fallback for a lazily-loaded route.
 *
 * The destination page is unknown here — but its *frame* is not. Every routed page in this
 * app is the same shape: a `PageHeader` (crumbs, title, lede) over one or more cards. So
 * this is a skeleton of that frame rather than an indeterminate bar; the header block lands
 * where the real header will sit, and the page does not jump when the chunk resolves.
 *
 * `SkeletonRegion` owns the `role="status"` + `aria-busy` and carries the announcement as
 * visually-hidden text: there is deliberately no visible "a carregar" caption, and equally
 * deliberately no silence for a screen reader. The blocks themselves are `aria-hidden`.
 */
import { Skeleton, SkeletonRegion, SkeletonText } from '../ui';

export function RouteLoading() {
  return (
    <SkeletonRegion className="stack">
      <div className="stack--tight">
        <Skeleton height="0.75rem" width="9rem" />
        <Skeleton height="2rem" width="55%" />
        <SkeletonText lines={2} />
      </div>
      <section className="panel">
        <div className="panel__body">
          <SkeletonText lines={4} />
        </div>
      </section>
    </SkeletonRegion>
  );
}
