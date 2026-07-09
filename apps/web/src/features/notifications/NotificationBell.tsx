import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useDashboard } from '../../api/hooks';
import { useT } from '../../i18n';
import { Badge, Card, ErrorNote, Loading, Tooltip, Icon } from '../../ui';
import { NotificationList } from './NotificationList';
import {
  buildDashboardNotifications,
  isActionableNotification,
  popupNotifications,
} from './notifications';

const POPUP_LIMIT = 5;

function compactCount(count: number): string {
  return count > 99 ? '99+' : String(count);
}

export function NotificationBell() {
  const t = useT();
  const [open, setOpen] = useState(false);
  const { data, isLoading, error } = useDashboard();
  const notifications = useMemo(
    () => (data ? buildDashboardNotifications(data, t) : []),
    [data, t],
  );
  const actionableCount = notifications.filter(isActionableNotification).length;
  const topItems = popupNotifications(notifications, POPUP_LIMIT);
  const label =
    actionableCount > 0
      ? t('notifications.bell.labelWithCount', { count: actionableCount })
      : t('notifications.bell.label');

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open]);

  return (
    <div className="notification-center">
      <Tooltip label={label} placement="bottom">
        <button
          type="button"
          className={`notification-bell btn btn--ghost btn--icon btn--iconOnly${
            open ? ' is-active' : ''
          }`}
          aria-label={label}
          aria-haspopup="dialog"
          aria-expanded={open}
          onClick={() => setOpen((value) => !value)}
        >
          <span className="btn__icon notification-bell__icon">
            <Icon.Bell />
            {actionableCount > 0 ? (
              <span className="notification-bell__count" aria-hidden="true">
                {compactCount(actionableCount)}
              </span>
            ) : null}
          </span>
        </button>
      </Tooltip>

      {open ? (
        <>
          <div
            className="notification-center__backdrop"
            aria-hidden="true"
            onClick={() => setOpen(false)}
          />
          <div
            className="notification-center__popup"
            role="dialog"
            aria-label={t('notifications.title')}
          >
            <Card
              title={t('notifications.title')}
              actions={
                actionableCount > 0 ? (
                  <Badge tone="accent">{compactCount(actionableCount)}</Badge>
                ) : null
              }
            >
              {isLoading ? (
                <Loading />
              ) : error ? (
                <ErrorNote error={error} />
              ) : (
                <NotificationList
                  compact
                  items={topItems}
                  emptyTitle={t('notifications.popup.empty')}
                  onAction={() => setOpen(false)}
                />
              )}
              <div className="notification-center__footer">
                <Link to="/notificacoes" onClick={() => setOpen(false)}>
                  {t('notifications.viewAll')}
                </Link>
              </div>
            </Card>
          </div>
        </>
      ) : null}
    </div>
  );
}
