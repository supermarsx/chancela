import { useMemo, useState } from 'react';
import { useDashboard } from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import { useNotificationsExtraT } from '../../i18n/notificationsRetentionFallback';
import {
  Card,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  PageHeader,
  Select,
  SkeletonRegion,
  SubNav,
  type SubNavItem,
} from '../../ui';
import { NotificationList } from './NotificationList';
import { NotificationsSkeleton } from './NotificationsSkeleton';
import {
  buildDashboardNotifications,
  notificationMatchesQuery,
  notificationMatchesTone,
  type NotificationToneFilter,
} from './notifications';
import {
  acknowledgedNotifications,
  activeNotifications,
  dismissedNotifications,
  useNotificationTriage,
  withNotificationTriage,
  type TriagedNotificationItem,
} from './triage';
import type { NotificationTriageEntry } from '../../api/types';

type NotificationFilter =
  'all' | 'alerts' | 'reminders' | 'operations' | 'dismissed' | 'acknowledged';

function tabItems(
  items: TriagedNotificationItem[],
  filter: NotificationFilter,
  entries: NotificationTriageEntry[],
): TriagedNotificationItem[] {
  if (filter === 'dismissed') return dismissedNotifications(items, entries);
  if (filter === 'acknowledged') return acknowledgedNotifications(items);
  const active = activeNotifications(items);
  if (filter === 'alerts') return active.filter((item) => item.kind === 'alert');
  if (filter === 'reminders') return active.filter((item) => item.kind === 'reminder');
  if (filter === 'operations') return active.filter((item) => item.kind === 'operation');
  return active;
}

function emptyTitle(
  filter: NotificationFilter,
  t: TFunction,
  nt: ReturnType<typeof useNotificationsExtraT>,
): string {
  if (filter === 'dismissed') return nt('notifications.empty.dismissed');
  if (filter === 'acknowledged') return nt('notifications.empty.acknowledged');
  return t('notifications.empty');
}

const TONE_FILTER_VALUES: NotificationToneFilter[] = ['all', 'error', 'warn', 'accent', 'neutral'];

export function NotificationsPage() {
  const t = useT();
  const nt = useNotificationsExtraT();
  const [filter, setFilter] = useState<NotificationFilter>('all');
  // The free-text search + tone refinement persist across tab switches so an operator can carry a
  // query from the active list into Descartadas without retyping it (plan §13).
  const [query, setQuery] = useState('');
  const [tone, setTone] = useState<NotificationToneFilter>('all');
  const { data, isLoading, error } = useDashboard();
  const triage = useNotificationTriage();
  const notifications = useMemo(
    () =>
      data ? withNotificationTriage(buildDashboardNotifications(data, t), triage.entries) : [],
    [data, t, triage.entries],
  );

  const tabbed = tabItems(notifications, filter, triage.entries);
  const hasFilters = query.trim() !== '' || tone !== 'all';
  const visible = tabbed.filter(
    (item) => notificationMatchesQuery(item, query) && notificationMatchesTone(item, tone),
  );

  const toneOptions = TONE_FILTER_VALUES.map((value) => ({
    value,
    label: nt(`notifications.filter.tone.${value}` as const),
  }));

  function clearFilters() {
    setQuery('');
    setTone('all');
  }

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
      id: 'dismissed',
      label: nt('notifications.filter.dismissed'),
      tooltipLabel: nt('notifications.filter.dismissed'),
      iconOnly: true,
      icon: <Icon.Trash />,
    },
    {
      id: 'acknowledged',
      label: nt('notifications.filter.acknowledged'),
      tooltipLabel: nt('notifications.filter.acknowledged'),
      iconOnly: true,
      icon: <Icon.Check />,
    },
  ];

  const ready = !isLoading && !triage.isLoading && !error && !triage.error;

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

      {/* Keyed on the filter so switching sub-tab remounts and replays the shared panel
          fade — the same treatment every other SubNav surface already had, and the only
          one that was missing it. Nested inside the Layout's `.route-transition`, so it
          picks up the riseless `panel-enter` variant automatically (theme.css). The
          wrapper takes the `.stack` sibling margin the Card used to take, so spacing is
          unchanged; and it never gates the content — the branch below renders on the same
          paint, the fade only rides on top of whatever is already there. */}
      <div className="route-transition" key={filter} data-subanim-key={filter}>
        <Card>
          {isLoading || triage.isLoading ? (
            /* Was `SkeletonCards` — a metric-card grid that then became a notification
               list, i.e. the exact layout jump a skeleton exists to prevent. */
            <SkeletonRegion>
              <NotificationsSkeleton items={4} compact />
            </SkeletonRegion>
          ) : error || triage.error ? (
            <ErrorNote error={error ?? triage.error} />
          ) : (
            <div className="stack">
              {/* Mirrors the Atas/books NARROW-page filterbar (AtasListPage `.acts-filterbar*`): a
                  role="search" bar of Field + Input[type=search] + Select + clear IconButton,
                  reusing the same UI primitives and the shared `.filter` classes rather than a new
                  component. The Action Center is a narrow reading column (no `wide-page`), so it uses
                  the wrapping narrow-friendly `.acts-*` classes, not the wide non-wrapping entities
                  ones. Applied to the post-tab `visible` list, so it composes with every tab
                  including Descartadas. */}
              <div
                className="stack--tight acts-filters"
                role="search"
                aria-label={nt('notifications.filter.aria')}
              >
                <div className="acts-filterbar filter">
                  <div className="acts-filterbar__primary">
                    <Field
                      label={nt('notifications.filter.search.label')}
                      htmlFor="notifications-search"
                    >
                      <Input
                        id="notifications-search"
                        type="search"
                        value={query}
                        placeholder={nt('notifications.filter.search.placeholder')}
                        onChange={(event) => setQuery(event.target.value)}
                      />
                    </Field>
                    <Field
                      label={nt('notifications.filter.tone.label')}
                      htmlFor="notifications-tone-filter"
                    >
                      <Select
                        id="notifications-tone-filter"
                        value={tone}
                        onChange={(event) => setTone(event.target.value as NotificationToneFilter)}
                        options={toneOptions}
                      />
                    </Field>
                    <IconButton
                      className="acts-filterbar__clear"
                      icon={<Icon.Close />}
                      label={nt('notifications.filter.clear.aria')}
                      disabled={!hasFilters}
                      onClick={clearFilters}
                    />
                  </div>
                </div>
              </div>

              {filter === 'dismissed' && ready ? (
                <p className="notifications-list__empty muted">
                  {nt('notifications.retention.note')}
                </p>
              ) : null}

              <NotificationList
                compact
                items={visible}
                emptyTitle={
                  hasFilters && tabbed.length > 0
                    ? nt('notifications.filter.empty')
                    : emptyTitle(filter, t, nt)
                }
                onTriage={triage.setStatus}
                triageDisabled={triage.isUpdating}
              />
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
