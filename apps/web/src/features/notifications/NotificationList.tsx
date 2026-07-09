import { Link } from 'react-router-dom';
import { useLocale, useT } from '../../i18n';
import { Badge, EmptyState, Icon } from '../../ui';
import type { NotificationTriageStatus } from '../../api/types';
import type { TriagedNotificationItem } from './triage';

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
  onTriage,
  triageDisabled = false,
}: {
  items: TriagedNotificationItem[];
  compact?: boolean;
  emptyTitle?: string;
  onAction?: () => void;
  onTriage?: (id: string, status: NotificationTriageStatus) => void;
  triageDisabled?: boolean;
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
        const statusLabel =
          item.triageStatus === 'read'
            ? t('notifications.status.read')
            : item.triageStatus === 'dismissed'
              ? t('notifications.status.dismissed')
              : item.triageStatus === 'acknowledged'
                ? t('notifications.status.acknowledged')
                : null;
        const resolved = item.triageStatus === 'dismissed' || item.triageStatus === 'acknowledged';
        return (
          <li
            className={`notifications-list__item notifications-list__item--${item.tone}${
              item.triageStatus === 'read' ? ' is-read' : ''
            }${resolved ? ' is-resolved' : ''}`}
            data-kind={item.kind}
            data-triage-status={item.triageStatus}
            key={item.id}
          >
            <div className="notifications-list__head">
              <Badge tone={item.tone}>{item.badge}</Badge>
              {statusLabel ? <Badge>{statusLabel}</Badge> : null}
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
            {item.action || onTriage ? (
              <div className="notifications-list__actions">
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
                {onTriage && resolved ? (
                  <button
                    type="button"
                    className="btn btn--ghost btn--icon notifications-list__triage"
                    disabled={triageDisabled}
                    onClick={() => onTriage(item.id, 'unread')}
                  >
                    <span className="btn__icon">
                      <Icon.Refresh />
                    </span>
                    {t('notifications.triage.restore')}
                  </button>
                ) : null}
                {onTriage && !resolved && item.triageStatus === 'unread' ? (
                  <button
                    type="button"
                    className="btn btn--ghost btn--icon notifications-list__triage"
                    disabled={triageDisabled}
                    onClick={() => onTriage(item.id, 'read')}
                  >
                    <span className="btn__icon">
                      <Icon.Check />
                    </span>
                    {t('notifications.triage.read')}
                  </button>
                ) : null}
                {onTriage && !resolved && item.kind !== 'operation' ? (
                  <button
                    type="button"
                    className="btn btn--ghost btn--icon notifications-list__triage"
                    disabled={triageDisabled}
                    onClick={() => onTriage(item.id, 'acknowledged')}
                  >
                    <span className="btn__icon">
                      <Icon.Check />
                    </span>
                    {t('notifications.triage.acknowledge')}
                  </button>
                ) : null}
                {onTriage && !resolved ? (
                  <button
                    type="button"
                    className="btn btn--ghost btn--icon notifications-list__triage"
                    disabled={triageDisabled}
                    onClick={() => onTriage(item.id, 'dismissed')}
                  >
                    <span className="btn__icon">
                      <Icon.Close />
                    </span>
                    {t('notifications.triage.dismiss')}
                  </button>
                ) : null}
              </div>
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}
