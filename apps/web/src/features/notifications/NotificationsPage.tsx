import { useMemo, useState } from 'react';
import { useDashboard } from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import { Card, ErrorNote, Icon, Loading, PageHeader, SubNav, type SubNavItem } from '../../ui';
import { NotificationList } from './NotificationList';
import { buildDashboardNotifications } from './notifications';
import {
  activeNotifications,
  resolvedNotifications,
  useNotificationTriage,
  withNotificationTriage,
  type TriagedNotificationItem,
} from './triage';

type NotificationFilter = 'all' | 'alerts' | 'reminders' | 'operations' | 'resolved';

function filterItems(
  items: TriagedNotificationItem[],
  filter: NotificationFilter,
): TriagedNotificationItem[] {
  if (filter === 'resolved') return resolvedNotifications(items);
  const active = activeNotifications(items);
  if (filter === 'alerts') return active.filter((item) => item.kind === 'alert');
  if (filter === 'reminders') return active.filter((item) => item.kind === 'reminder');
  if (filter === 'operations') return active.filter((item) => item.kind === 'operation');
  return active;
}

function emptyTitle(filter: NotificationFilter, t: TFunction): string {
  if (filter === 'resolved') return t('notifications.empty.resolved');
  return t('notifications.empty');
}

export function NotificationsPage() {
  const t = useT();
  const [filter, setFilter] = useState<NotificationFilter>('all');
  const { data, isLoading, error } = useDashboard();
  const triage = useNotificationTriage();
  const notifications = useMemo(
    () =>
      data ? withNotificationTriage(buildDashboardNotifications(data, t), triage.entries) : [],
    [data, t, triage.entries],
  );
  const visible = filterItems(notifications, filter);
  const navItems: SubNavItem<NotificationFilter>[] = [
    {
      id: 'all',
      label: t('notifications.filter.all'),
      tooltipLabel: t('notifications.filter.all'),
      iconOnly: true,
      icon: <Icon.Bell />,
    },
    {
      id: 'alerts',
      label: t('notifications.filter.alerts'),
      tooltipLabel: t('notifications.filter.alerts'),
      iconOnly: true,
      icon: <Icon.Info />,
    },
    {
      id: 'reminders',
      label: t('notifications.filter.reminders'),
      tooltipLabel: t('notifications.filter.reminders'),
      iconOnly: true,
      icon: <Icon.Calendar />,
    },
    {
      id: 'operations',
      label: t('notifications.filter.operations'),
      tooltipLabel: t('notifications.filter.operations'),
      iconOnly: true,
      icon: <Icon.Archive />,
    },
    {
      id: 'resolved',
      label: t('notifications.filter.resolved'),
      tooltipLabel: t('notifications.filter.resolved'),
      iconOnly: true,
      icon: <Icon.Check />,
    },
  ];

  return (
    <div className="stack">
      <PageHeader title={t('notifications.title')}>
        <SubNav
          items={navItems}
          active={filter}
          onSelect={setFilter}
          ariaLabel={t('notifications.title')}
        />
      </PageHeader>

      <Card>
        {isLoading || triage.isLoading ? (
          <Loading />
        ) : error || triage.error ? (
          <ErrorNote error={error ?? triage.error} />
        ) : (
          <NotificationList
            compact
            items={visible}
            emptyTitle={emptyTitle(filter, t)}
            onTriage={triage.setStatus}
            triageDisabled={triage.isUpdating}
          />
        )}
      </Card>
    </div>
  );
}
