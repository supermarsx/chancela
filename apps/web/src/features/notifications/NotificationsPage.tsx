import { useMemo, useState, type ReactNode } from 'react';
import { useDashboard } from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import { Card, ErrorNote, Icon, Loading, PageHeader, SubNav } from '../../ui';
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
  const navItems: { id: NotificationFilter; label: ReactNode; icon: ReactNode }[] = [
    { id: 'all', label: t('notifications.filter.all'), icon: <Icon.Bell /> },
    { id: 'alerts', label: t('notifications.filter.alerts'), icon: <Icon.Info /> },
    { id: 'reminders', label: t('notifications.filter.reminders'), icon: <Icon.Calendar /> },
    { id: 'operations', label: t('notifications.filter.operations'), icon: <Icon.Archive /> },
    { id: 'resolved', label: t('notifications.filter.resolved'), icon: <Icon.Check /> },
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
