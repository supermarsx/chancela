import { useMemo, useState, type ReactNode } from 'react';
import { useDashboard } from '../../api/hooks';
import { useT } from '../../i18n';
import { Card, ErrorNote, Icon, Loading, PageHeader, SubNav } from '../../ui';
import { NotificationList } from './NotificationList';
import { buildDashboardNotifications, type NotificationItem } from './notifications';

type NotificationFilter = 'all' | 'alerts' | 'reminders' | 'operations';

function filterItems(items: NotificationItem[], filter: NotificationFilter): NotificationItem[] {
  if (filter === 'alerts') return items.filter((item) => item.kind === 'alert');
  if (filter === 'reminders') return items.filter((item) => item.kind === 'reminder');
  if (filter === 'operations') return items.filter((item) => item.kind === 'operation');
  return items;
}

export function NotificationsPage() {
  const t = useT();
  const [filter, setFilter] = useState<NotificationFilter>('all');
  const { data, isLoading, error } = useDashboard();
  const notifications = useMemo(
    () => (data ? buildDashboardNotifications(data, t) : []),
    [data, t],
  );
  const visible = filterItems(notifications, filter);
  const navItems: { id: NotificationFilter; label: ReactNode; icon: ReactNode }[] = [
    { id: 'all', label: t('notifications.filter.all'), icon: <Icon.Bell /> },
    { id: 'alerts', label: t('notifications.filter.alerts'), icon: <Icon.Info /> },
    { id: 'reminders', label: t('notifications.filter.reminders'), icon: <Icon.Calendar /> },
    { id: 'operations', label: t('notifications.filter.operations'), icon: <Icon.Archive /> },
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
        {isLoading ? (
          <Loading />
        ) : error ? (
          <ErrorNote error={error} />
        ) : (
          <NotificationList items={visible} emptyTitle={t('notifications.empty')} />
        )}
      </Card>
    </div>
  );
}
