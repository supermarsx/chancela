import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from 'react';
import { createPortal } from 'react-dom';
import { Link } from 'react-router-dom';
import { useDashboard } from '../../api/hooks';
import { useT } from '../../i18n';
import { Badge, Card, ErrorNote, SkeletonRegion, Tooltip, Icon } from '../../ui';
import { NotificationsSkeleton } from './NotificationsSkeleton';
import { NotificationList } from './NotificationList';
import {
  buildDashboardNotifications,
  isActionableNotification,
  popupNotifications,
} from './notifications';
import { unreadNotifications, useNotificationTriage, withNotificationTriage } from './triage';

const POPUP_LIMIT = 5;
const POPUP_GAP = 8;
const POPUP_MARGIN = 12;

function compactCount(count: number): string {
  return count > 99 ? '99+' : String(count);
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

export function NotificationBell() {
  const t = useT();
  const [open, setOpen] = useState(false);
  const anchorRef = useRef<HTMLDivElement>(null);
  const popupRef = useRef<HTMLDivElement>(null);
  const [popupPosition, setPopupPosition] = useState({ left: 0, top: 0, maxHeight: 0 });
  const { data, isLoading, error } = useDashboard();
  const triage = useNotificationTriage();
  const notifications = useMemo(
    () =>
      data ? withNotificationTriage(buildDashboardNotifications(data, t), triage.entries) : [],
    [data, t, triage.entries],
  );
  const unread = unreadNotifications(notifications);
  const actionableCount = unread.filter(isActionableNotification).length;
  const topItems = popupNotifications(unread, POPUP_LIMIT);
  const label =
    actionableCount > 0
      ? t('notifications.bell.labelWithCount', { count: actionableCount })
      : t('notifications.bell.label');
  const viewAllLabel = t('notifications.viewAll');
  const closePopup = useCallback(() => setOpen(false), []);

  const repositionPopup = useCallback(() => {
    const anchor = anchorRef.current;
    if (!anchor) return;

    const anchorRect = anchor.getBoundingClientRect();
    const viewportWidth = window.innerWidth || document.documentElement.clientWidth;
    const viewportHeight = window.innerHeight || document.documentElement.clientHeight;
    const popupRect = popupRef.current?.getBoundingClientRect();
    const fallbackWidth = Math.min(384, Math.max(0, viewportWidth - POPUP_MARGIN * 2));
    const popupWidth = popupRect && popupRect.width > 0 ? popupRect.width : fallbackWidth;
    const maxLeft = Math.max(POPUP_MARGIN, viewportWidth - popupWidth - POPUP_MARGIN);
    const left = clamp(anchorRect.right - popupWidth, POPUP_MARGIN, maxLeft);
    const top = anchorRect.bottom + POPUP_GAP;
    const maxHeight = Math.max(0, viewportHeight - top - POPUP_MARGIN);

    setPopupPosition((prev) =>
      prev.left === left && prev.top === top && prev.maxHeight === maxHeight
        ? prev
        : { left, top, maxHeight },
    );
  }, []);

  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closePopup();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, closePopup]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (anchorRef.current?.contains(target) || popupRef.current?.contains(target)) return;
      closePopup();
    };
    document.addEventListener('pointerdown', onPointerDown, true);
    return () => document.removeEventListener('pointerdown', onPointerDown, true);
  }, [open, closePopup]);

  useLayoutEffect(() => {
    if (!open) return;
    repositionPopup();
    window.addEventListener('scroll', repositionPopup, true);
    window.addEventListener('resize', repositionPopup);
    return () => {
      window.removeEventListener('scroll', repositionPopup, true);
      window.removeEventListener('resize', repositionPopup);
    };
  }, [open, repositionPopup, isLoading, error, triage.isLoading, triage.error, topItems.length]);

  const popupStyle: CSSProperties = {
    left: popupPosition.left,
    top: popupPosition.top,
  };
  if (popupPosition.maxHeight > 0) popupStyle.maxHeight = popupPosition.maxHeight;

  const popup = open ? (
    <>
      <div className="notification-center__backdrop" aria-hidden="true" onClick={closePopup} />
      <div
        ref={popupRef}
        className="notification-center__popup"
        role="dialog"
        aria-label={t('notifications.title')}
        style={popupStyle}
      >
        <Card
          title={t('notifications.title')}
          actions={
            actionableCount > 0 ? (
              <span className="notification-center__title-badge">
                <Badge tone="accent">{compactCount(actionableCount)}</Badge>
              </span>
            ) : null
          }
        >
          {isLoading || triage.isLoading ? (
            <SkeletonRegion>
              <NotificationsSkeleton items={3} compact />
            </SkeletonRegion>
          ) : error || triage.error ? (
            <ErrorNote error={error ?? triage.error} />
          ) : (
            <NotificationList
              compact
              items={topItems}
              emptyTitle={t('notifications.popup.empty')}
              onAction={closePopup}
              onTriage={triage.setStatus}
              triageDisabled={triage.isUpdating}
            />
          )}
          <div className="notification-center__footer">
            <Tooltip label={viewAllLabel}>
              <Link
                to="/notificacoes"
                className="notification-center__view-all btn btn--ghost btn--icon btn--iconOnly"
                aria-label={viewAllLabel}
                onClick={closePopup}
              >
                <span className="btn__icon" aria-hidden="true">
                  <Icon.ArrowRight />
                </span>
              </Link>
            </Tooltip>
          </div>
        </Card>
      </div>
    </>
  ) : null;

  return (
    <div className="notification-center" ref={anchorRef}>
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

      {popup && typeof document !== 'undefined' ? createPortal(popup, document.body) : popup}
    </div>
  );
}
