import { Link } from 'react-router-dom';
import type { ReactNode } from 'react';
import { useT, type TFunction } from '../../i18n';
import { Badge, EmptyState, Icon, RelativeDateTime, Tooltip, TooltipText } from '../../ui';
import type { NotificationSnapshot, NotificationTriageStatus } from '../../api/types';
import type { TriagedNotificationItem } from './triage';
import { notificationSnapshotFromItem } from './notifications';
import { MailOpenGlyph, ShieldCheckGlyph, notificationTypeGlyph } from './icons';

function compactKindLabel(item: TriagedNotificationItem, t: TFunction): string {
  if (item.kind === 'reminder') return t('notifications.filter.reminders');
  return item.badge;
}

function NotificationActionLink({
  href,
  label,
  icon,
  onClick,
}: {
  href: string;
  label: string;
  icon: ReactNode;
  onClick?: () => void;
}) {
  return (
    <Tooltip label={label}>
      <Link
        className="btn btn--ghost btn--icon btn--iconOnly notifications-list__action"
        to={href}
        aria-label={label}
        onClick={onClick}
      >
        <span className="btn__icon" aria-hidden="true">
          {icon}
        </span>
      </Link>
    </Tooltip>
  );
}

/**
 * These controls are icon-only, so the glyph is the only thing separating them on screen — hence
 * `iconName`, a stable scan/test hook (mirroring the row chip's `data-notification-icon`) that
 * lets a test assert the four remain pairwise distinct. The accessible name never depends on it:
 * every button keeps its `aria-label` and its themed tooltip.
 */
function NotificationTriageButton({
  label,
  icon,
  iconName,
  disabled,
  onClick,
}: {
  label: string;
  icon: ReactNode;
  iconName: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <Tooltip label={label}>
      <button
        type="button"
        className="btn btn--ghost btn--icon btn--iconOnly notifications-list__triage"
        aria-label={label}
        data-triage-icon={iconName}
        disabled={disabled}
        onClick={onClick}
      >
        <span className="btn__icon" aria-hidden="true">
          {icon}
        </span>
      </button>
    </Tooltip>
  );
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
  onTriage?: (
    id: string,
    status: NotificationTriageStatus,
    snapshot?: NotificationSnapshot,
  ) => void;
  triageDisabled?: boolean;
}) {
  const t = useT();

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
        const restoreLabel = t('notifications.triage.restore');
        const readLabel = t('notifications.triage.read');
        const acknowledgeLabel = t('notifications.triage.acknowledge');
        const dismissLabel = t('notifications.triage.dismiss');
        // An alert is read for RECENCY ("há 3 minutos"), so this is the one surface where the
        // relative form leads; `RelativeDateTime` keeps the exact instant on hover and focus.
        const timestamp = item.timestamp;
        const statusLabel =
          item.triageStatus === 'read'
            ? t('notifications.status.read')
            : item.triageStatus === 'dismissed'
              ? t('notifications.status.dismissed')
              : item.triageStatus === 'acknowledged'
                ? t('notifications.status.acknowledged')
                : null;
        const resolved = item.triageStatus === 'dismissed' || item.triageStatus === 'acknowledged';
        const typeGlyph = notificationTypeGlyph(item);
        const compactTitleTags: string[] = [];
        if (compact) {
          const kindLabel = compactKindLabel(item, t);
          compactTitleTags.push(kindLabel);
          if (item.kind === 'reminder' && item.badge !== kindLabel)
            compactTitleTags.push(item.badge);
          if (statusLabel) compactTitleTags.push(statusLabel);
        }
        return (
          <li
            className={`notifications-list__item notifications-list__item--${item.tone}${
              item.triageStatus === 'read' ? ' is-read' : ''
            }${resolved ? ' is-resolved' : ''}`}
            data-kind={item.kind}
            data-triage-status={item.triageStatus}
            key={item.id}
          >
            <span
              className={`notifications-list__icon notifications-list__icon--${item.tone}`}
              data-notification-icon={typeGlyph.name}
              aria-hidden="true"
            >
              {typeGlyph.icon}
            </span>
            <div className="notifications-list__body">
              <div className="notifications-list__head">
                {compact ? null : <Badge tone={item.tone}>{item.badge}</Badge>}
                {!compact && statusLabel ? <Badge>{statusLabel}</Badge> : null}
                {/* The title is rendered in full below; the reveal engages only if the row
                    is narrow enough to ellipsise it. */}
                <TooltipText
                  className="notifications-list__title"
                  label={item.title}
                  onlyWhenClipped
                >
                  {compactTitleTags.map((tag) => (
                    <span className="notifications-list__title-tag" key={tag}>
                      {tag}
                    </span>
                  ))}
                  <span className="notifications-list__title-text">{item.title}</span>
                </TooltipText>
              </div>
              <p className="notifications-list__detail muted">{item.detail}</p>
              {item.meta.length > 0 || timestamp ? (
                <div className="notifications-list__meta">
                  {timestamp ? <RelativeDateTime value={timestamp} className="muted" /> : null}
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
                    <NotificationActionLink
                      href={item.action.href}
                      label={item.action.label}
                      icon={<Icon.ArrowRight />}
                      onClick={onAction}
                    />
                  ) : null}
                  {onTriage && resolved ? (
                    <NotificationTriageButton
                      label={restoreLabel}
                      iconName="restore"
                      icon={<Icon.Refresh />}
                      disabled={triageDisabled}
                      onClick={() => onTriage(item.id, 'unread')}
                    />
                  ) : null}
                  {onTriage && !resolved && item.triageStatus === 'unread' ? (
                    <NotificationTriageButton
                      label={readLabel}
                      iconName="read"
                      icon={<MailOpenGlyph />}
                      disabled={triageDisabled}
                      onClick={() => onTriage(item.id, 'read')}
                    />
                  ) : null}
                  {onTriage && !resolved && item.kind !== 'operation' ? (
                    <NotificationTriageButton
                      label={acknowledgeLabel}
                      iconName="acknowledge"
                      icon={<ShieldCheckGlyph />}
                      disabled={triageDisabled}
                      onClick={() => onTriage(item.id, 'acknowledged')}
                    />
                  ) : null}
                  {onTriage && !resolved ? (
                    <NotificationTriageButton
                      label={dismissLabel}
                      iconName="dismiss"
                      icon={<Icon.Close />}
                      disabled={triageDisabled}
                      // Freeze the display copy at dismiss time so Descartadas can show this row for
                      // the full retention window even after the dashboard stops generating it.
                      onClick={() =>
                        onTriage(item.id, 'dismissed', notificationSnapshotFromItem(item))
                      }
                    />
                  ) : null}
                </div>
              ) : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
}
