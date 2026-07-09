import { Link } from 'react-router-dom';
import { useLocale, useT } from '../../i18n';
import { Badge, EmptyState, Icon } from '../../ui';
import type { NotificationItem } from './notifications';

function formatTimestamp(value: string | undefined, locale: string): string | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

export function NotificationList({
  items,
  compact = false,
  emptyTitle,
  onAction,
}: {
  items: NotificationItem[];
  compact?: boolean;
  emptyTitle?: string;
  onAction?: () => void;
}) {
  const t = useT();
  const locale = useLocale();

  if (items.length === 0) {
    if (compact) return <p className="notifications-list__empty muted">{emptyTitle}</p>;
    return <EmptyState title={emptyTitle ?? t('notifications.empty')} />;
  }

  return (
    <ol
      className={`notifications-list${compact ? ' notifications-list--compact' : ''}`}
      aria-label={t('notifications.title')}
    >
      {items.map((item) => {
        const timestamp = formatTimestamp(item.timestamp, locale);
        return (
          <li
            className={`notifications-list__item notifications-list__item--${item.tone}`}
            data-kind={item.kind}
            key={item.id}
          >
            <div className="notifications-list__head">
              <Badge tone={item.tone}>{item.badge}</Badge>
              <span className="notifications-list__title">{item.title}</span>
            </div>
            <p className="notifications-list__detail muted">{item.detail}</p>
            {item.meta.length > 0 || timestamp ? (
              <div className="notifications-list__meta">
                {timestamp ? <span className="muted">{timestamp}</span> : null}
                {item.meta.map((meta) => (
                  <span className="muted" key={meta}>
                    {meta}
                  </span>
                ))}
              </div>
            ) : null}
            {item.action ? (
              <Link
                className="btn btn--ghost btn--icon notifications-list__action"
                to={item.action.href}
                onClick={onAction}
              >
                <span className="btn__icon">
                  <Icon.ArrowRight />
                </span>
                {item.action.label}
              </Link>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}
