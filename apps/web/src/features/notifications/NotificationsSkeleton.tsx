/**
 * The loading placeholder for a notification list.
 *
 * It is built from `NotificationList`'s own classes — `.notifications-list`, its `__item`,
 * `__icon`, `__body`, `__head` and `__meta` — rather than a generic block, because a
 * skeleton that does not resemble what replaces it is worse than the text it replaced: the
 * content jumps on swap. The bell popup and the notifications page both wait on the same
 * shape, so they share this one.
 *
 * Decorative throughout (`aria-hidden`); wrap it in a `SkeletonRegion` so the wait is
 * announced.
 */
import { Skeleton } from '../../ui';

export function NotificationsSkeleton({
  items = 4,
  compact = false,
}: {
  items?: number;
  compact?: boolean;
}) {
  return (
    <ol
      className={`notifications-list${compact ? ' notifications-list--compact' : ''}`}
      aria-hidden="true"
    >
      {Array.from({ length: items }, (_, i) => (
        <li className="notifications-list__item" key={i}>
          <span className="notifications-list__icon" aria-hidden="true">
            <Skeleton height="1.1rem" width="1.1rem" />
          </span>
          <div className="notifications-list__body">
            <div className="notifications-list__head">
              <Skeleton height="1.05rem" width={i % 2 === 0 ? '58%' : '44%'} />
            </div>
            <Skeleton height="0.8rem" width="82%" />
            <div className="notifications-list__meta">
              <Skeleton height="0.72rem" width="6rem" />
              <Skeleton height="0.72rem" width="4.5rem" />
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}
