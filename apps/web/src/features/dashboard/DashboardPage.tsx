/**
 * Painel — the WFL-40 dashboard subset (plan t5 §2.7). Counts, the chain-valid
 * indicator, an unresolved-compliance callout, advisory reminders, and the last ledger
 * events. Everything is derived from `GET /v1/dashboard`, which the seal/mutation hooks
 * invalidate, so the numbers stay live.
 */
import { Link, useSearchParams } from 'react-router-dom';
import { useDashboard } from '../../api/hooks';
import { actStateLabels, bookKindLabels } from '../../api/labels';
import type {
  Dashboard,
  DashboardAlert,
  DashboardActStateCounts,
  DashboardLawReference,
  DashboardOpenBook,
  DashboardReminder,
  LedgerEventView,
} from '../../api/types';
import { useLocale, useT, type MessageKey, type TFunction, type TParams } from '../../i18n';
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  Icon,
  InlineWarning,
  PageHeader,
  SkeletonCards,
  SkeletonTable,
  SubNav,
  Tooltip,
} from '../../ui';
import { LedgerTable } from '../ledger/LedgerTable';
import './DashboardPage.css';

const RECENT_EVENTS_LIMIT = 10;
const SUMMARY_LIST_LIMIT = 5;
const DASHBOARD_TAB_PARAM = 'painel';

type QueueTone = 'neutral' | 'accent' | 'warn' | 'error';
type ActivityKind = 'act' | 'book' | 'entity';
type DashboardTab = 'stats' | 'activity' | 'current' | 'queue' | 'events';

interface WorkQueueItem {
  id: string;
  priority: number;
  sortTime: number | null;
  badge: string;
  tone: QueueTone;
  title: string;
  detail: string;
  meta: string[];
  href?: string;
}

interface ActivityItem {
  event: LedgerEventView;
  kind: ActivityKind;
  href?: string;
}

function lawRefSourcePending(ref: DashboardLawReference): boolean {
  return ref.source_complete === false || ref.verification === 'Pending';
}

function lawRefMeta(ref: DashboardLawReference): string {
  const label = `${ref.diploma_id}:${ref.article}`;
  return lawRefSourcePending(ref) ? `Lei ${label} · fonte pendente` : `Lei ${label}`;
}

function compareByRecency(a: LedgerEventView, b: LedgerEventView): number {
  const aTime = Date.parse(a.timestamp);
  const bTime = Date.parse(b.timestamp);
  const aValid = !Number.isNaN(aTime);
  const bValid = !Number.isNaN(bTime);

  if (aValid && bValid && aTime !== bTime) return bTime - aTime;
  if (aValid !== bValid) return aValid ? -1 : 1;
  return b.seq - a.seq;
}

function Metric({ label, value, note }: { label: string; value: number | string; note?: string }) {
  return (
    <li className="card">
      <p className="card__label">{label}</p>
      <p className="card__metric">{value}</p>
      {note ? <p className="card__note">{note}</p> : null}
    </li>
  );
}

function dashboardTabFromParam(value: string | null): DashboardTab {
  if (value === 'activity' || value === 'current' || value === 'queue' || value === 'events') {
    return value;
  }
  return 'stats';
}

function formatDateTime(value: string, locale: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(locale);
}

function shortId(value: string): string {
  return value.slice(0, 8);
}

function idFromScopedValue(value: string, prefix: string): string | undefined {
  const marker = `${prefix}:`;
  return value.startsWith(marker) ? value.slice(marker.length).trim() || undefined : undefined;
}

function firstChainId(event: LedgerEventView, prefix: string): string | undefined {
  for (const chain of event.chains) {
    const id = idFromScopedValue(chain, prefix);
    if (id) return id;
  }
  return undefined;
}

function activityKind(event: LedgerEventView): ActivityKind | null {
  if (event.kind.startsWith('act.') || idFromScopedValue(event.scope, 'act')) return 'act';
  if (
    event.kind.startsWith('book.') ||
    idFromScopedValue(event.scope, 'book') ||
    firstChainId(event, 'book')
  ) {
    return 'book';
  }
  if (
    event.kind.startsWith('entity.') ||
    idFromScopedValue(event.scope, 'entity') ||
    firstChainId(event, 'company')
  ) {
    return 'entity';
  }
  return null;
}

function routeFromActivity(event: LedgerEventView, kind: ActivityKind): string | undefined {
  if (kind === 'act') {
    const actId = idFromScopedValue(event.scope, 'act');
    return actId ? `/atas/${actId}` : undefined;
  }
  if (kind === 'book') {
    const bookId = idFromScopedValue(event.scope, 'book') ?? firstChainId(event, 'book');
    return bookId ? `/livros/${bookId}` : undefined;
  }

  const entityId =
    idFromScopedValue(event.scope, 'entity') ??
    firstChainId(event, 'company') ??
    (!event.scope.includes(':') && event.scope !== 'global' && event.scope !== 'application'
      ? event.scope
      : undefined);
  return entityId ? `/entidades/${entityId}` : undefined;
}

function activityTone(kind: ActivityKind): QueueTone {
  if (kind === 'act') return 'accent';
  if (kind === 'book') return 'neutral';
  return 'warn';
}

function activityLabel(kind: ActivityKind, t: TFunction): string {
  if (kind === 'act') return t('dashboard.activity.kind.act');
  if (kind === 'book') return t('dashboard.activity.kind.book');
  return t('dashboard.activity.kind.entity');
}

function recentActivityItems(events: LedgerEventView[]): ActivityItem[] {
  return events
    .slice()
    .sort(compareByRecency)
    .reduce<ActivityItem[]>((items, event) => {
      if (items.length >= RECENT_EVENTS_LIMIT) return items;
      const kind = activityKind(event);
      if (!kind) return items;
      items.push({ event, kind, href: routeFromActivity(event, kind) });
      return items;
    }, []);
}

function compactScope(scope: string): string {
  const [kind, id] = scope.split(':', 2);
  if (!id) return scope.length > 24 ? `${scope.slice(0, 8)}...` : scope;
  return `${kind}:${shortId(id)}`;
}

function reminderTone(reminder: DashboardReminder): 'neutral' | 'accent' | 'warn' {
  if (reminder.status === 'Overdue') return 'warn';
  if (reminder.status === 'DueSoon') return 'accent';
  return 'neutral';
}

function reminderStatusLabel(status: DashboardReminder['status'], t: TFunction): string {
  if (status === 'Overdue') return t('dashboard.workQueue.status.overdue');
  if (status === 'DueSoon') return t('dashboard.workQueue.status.dueSoon');
  return t('dashboard.workQueue.status.upcoming');
}

function parseReminderDate(value: string): number | null {
  const trimmed = value.trim();
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(trimmed);
  if (!match) return null;

  const [, yearText, monthText, dayText] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const time = Date.UTC(year, month - 1, day);
  const date = new Date(time);

  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day
  ) {
    return null;
  }

  return time;
}

function reminderDateLabel(dueDate: string, t: TFunction): string {
  const trimmed = dueDate.trim();
  if (!trimmed) return t('dashboard.workQueue.date.missing');
  return parseReminderDate(trimmed) === null ? t('dashboard.workQueue.date.invalid') : trimmed;
}

function reminderDateMeta(dueDate: string, t: TFunction): string {
  const label = reminderDateLabel(dueDate, t);
  const missing = t('dashboard.workQueue.date.missing');
  const invalid = t('dashboard.workQueue.date.invalid');
  if (label === missing || label === invalid) return label;
  return t('dashboard.workQueue.date.value', { date: label });
}

function reminderPriority(status: DashboardReminder['status']): number {
  if (status === 'Overdue') return 1;
  if (status === 'DueSoon') return 3;
  return 4;
}

function dedupeReminders(reminders: DashboardReminder[]): DashboardReminder[] {
  const seen = new Set<string>();
  return reminders.filter((reminder) => {
    const key = [
      reminder.entity_id.trim(),
      reminder.source_rule.trim(),
      reminder.source_profile.trim(),
      reminder.due_date.trim(),
      reminder.status,
    ].join('\u0000');

    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function messageKey(value: string | null | undefined): MessageKey | undefined {
  return value?.trim() ? (value.trim() as MessageKey) : undefined;
}

function frontendRouteFromApi(path: string | null | undefined): string | undefined {
  if (!path) return undefined;
  const route = path.trim();
  if (!route) return undefined;
  if (route.startsWith('/entidades/') || route === '/entidades') return route;
  if (route.startsWith('/livros/') || route === '/livros') return route;
  if (route.startsWith('/atas/') || route === '/atas') return route;
  if (route.startsWith('/arquivo') || route.startsWith('/configuracoes')) return route;

  const entity = /^\/v1\/entities\/([^/?#]+)/.exec(route);
  if (entity) return `/entidades/${entity[1]}`;
  const book = /^\/v1\/books\/([^/?#]+)/.exec(route);
  if (book) return `/livros/${book[1]}`;
  const act = /^\/v1\/acts\/([^/?#]+)/.exec(route);
  if (act) return `/atas/${act[1]}`;
  if (route.startsWith('/v1/ledger')) return '/arquivo';
  return undefined;
}

function routeFromAlert(alert: DashboardAlert): string | undefined {
  const metadataRoute =
    frontendRouteFromApi(alert.action?.route) ?? frontendRouteFromApi(alert.action?.api_href);
  if (metadataRoute) return metadataRoute;
  const links = alert.target.links;
  return (
    frontendRouteFromApi(links.act) ??
    (alert.target.act_id?.trim() ? `/atas/${alert.target.act_id.trim()}` : undefined) ??
    frontendRouteFromApi(links.book) ??
    (alert.target.book_id?.trim() ? `/livros/${alert.target.book_id.trim()}` : undefined) ??
    frontendRouteFromApi(links.entity) ??
    (alert.target.entity_id?.trim() ? `/entidades/${alert.target.entity_id.trim()}` : undefined) ??
    frontendRouteFromApi(links.ledger)
  );
}

function routeFromReminder(reminder: DashboardReminder): string | undefined {
  const metadataRoute =
    frontendRouteFromApi(reminder.action?.route) ?? frontendRouteFromApi(reminder.action?.api_href);
  if (metadataRoute) return metadataRoute;
  const entityId = reminder.entity_id.trim();
  return entityId ? `/entidades/${entityId}` : undefined;
}

function alertTone(alert: DashboardAlert): QueueTone {
  if (alert.severity === 'Error' || alert.code === 'ledger.integrity.review_required')
    return 'error';
  if (alert.severity === 'Warning' || alert.label === 'ReviewRequired') return 'warn';
  return 'accent';
}

function alertPriority(alert: DashboardAlert): number {
  if (alert.code === 'ledger.integrity.review_required') return 0;
  if (alert.label === 'ReviewRequired') return 2;
  return 3;
}

const ALERT_COPY: Partial<Record<string, { title: MessageKey; body: MessageKey }>> = {
  'entity.book.no_open_book': {
    title: 'notifications.alert.entity.noOpenBook.title',
    body: 'notifications.alert.entity.noOpenBook.body',
  },
  'entity.manager_remuneration.setup_recommended': {
    title: 'notifications.alert.entity.managerRemuneration.title',
    body: 'notifications.alert.entity.managerRemuneration.body',
  },
  'entity.administrator_remuneration.setup_recommended': {
    title: 'notifications.alert.entity.administratorRemuneration.title',
    body: 'notifications.alert.entity.administratorRemuneration.body',
  },
  'book.termo_abertura.missing_metadata': {
    title: 'notifications.alert.book.missingTermo.title',
    body: 'notifications.alert.book.missingTermo.body',
  },
  'book.acts.none_recorded': {
    title: 'notifications.alert.book.noActs.title',
    body: 'notifications.alert.book.noActs.body',
  },
  'book.legal_hold.active': {
    title: 'notifications.alert.book.legalHold.title',
    body: 'notifications.alert.book.legalHold.body',
  },
  'act.archive.pending': {
    title: 'notifications.alert.act.archivePending.title',
    body: 'notifications.alert.act.archivePending.body',
  },
};

function alertWorkQueueItem(alert: DashboardAlert, index: number, t: TFunction): WorkQueueItem {
  const code = alert.code.trim();
  const copy = ALERT_COPY[code];
  const titleKey = messageKey(alert.i18n?.title_key) ?? copy?.title;
  const bodyKey = messageKey(alert.i18n?.body_key) ?? copy?.body;
  const params: TParams = { ...alert.params, code };
  const lawRefs = (alert.law_refs ?? []).map(lawRefMeta).filter(Boolean);

  return {
    id: `alert:${code || 'unknown'}:${index}`,
    priority: alertPriority(alert),
    sortTime: null,
    badge: t('notifications.badge.alert'),
    tone: alertTone(alert),
    title: titleKey ? t(titleKey, params) : t('notifications.alert.unknown.title', params),
    detail: bodyKey
      ? t(bodyKey, params)
      : alert.message.trim() || t('notifications.alert.fallbackDetail'),
    meta: [
      ...(alert.source ? [t('notifications.alert.source', { source: alert.source })] : []),
      ...lawRefs,
    ],
    href: routeFromAlert(alert),
  };
}

function compareQueueItems(a: WorkQueueItem, b: WorkQueueItem): number {
  if (a.priority !== b.priority) return a.priority - b.priority;
  if (a.sortTime !== null && b.sortTime !== null && a.sortTime !== b.sortTime) {
    return a.sortTime - b.sortTime;
  }
  if (a.sortTime !== null || b.sortTime !== null) return a.sortTime === null ? 1 : -1;
  const byTitle = a.title.localeCompare(b.title, 'pt');
  return byTitle || a.id.localeCompare(b.id);
}

function buildWorkQueue({
  ledgerValid,
  unresolvedCompliance,
  alerts,
  reminders,
  t,
}: {
  ledgerValid: boolean;
  unresolvedCompliance: number;
  alerts: DashboardAlert[];
  reminders: DashboardReminder[];
  t: TFunction;
}): WorkQueueItem[] {
  const items: WorkQueueItem[] = [];

  for (const [index, alert] of alerts.entries()) {
    items.push(alertWorkQueueItem(alert, index, t));
  }

  if (
    !ledgerValid &&
    !items.some((item) => item.id.startsWith('alert:ledger.integrity.review_required:'))
  ) {
    items.push({
      id: 'integrity',
      priority: 0,
      sortTime: null,
      badge: t('dashboard.workQueue.integrity.badge'),
      tone: 'error',
      title: t('dashboard.workQueue.integrity.title'),
      detail: t('dashboard.workQueue.integrity.detail'),
      meta: [t('dashboard.workQueue.integrity.meta')],
      href: '/arquivo',
    });
  }

  for (const reminder of dedupeReminders(reminders)) {
    const dueDate = reminder.due_date.trim();
    const sortTime = dueDate ? parseReminderDate(dueDate) : null;
    const entityName = reminder.entity_name.trim() || t('dashboard.workQueue.entity.unnamed');
    const entityId = reminder.entity_id.trim();
    const sourceRule = reminder.source_rule.trim() || t('dashboard.workQueue.rule.missing');
    const sourceProfile =
      reminder.source_profile.trim() || t('dashboard.workQueue.profile.missing');
    const reason = reminder.reason.trim() || t('dashboard.workQueue.reminder.fallback');
    const params: TParams = {
      ...(reminder.params ?? {}),
      entity_name: entityName,
      due_date: reminderDateLabel(reminder.due_date, t),
      source_rule: sourceRule,
      source_profile: sourceProfile,
      reason,
    };
    const titleKey = messageKey(reminder.i18n?.title_key);
    const bodyKey = messageKey(reminder.i18n?.body_key);

    items.push({
      id: `reminder:${entityId}:${sourceRule}:${sourceProfile}:${dueDate}:${reminder.status}`,
      priority: reminderPriority(reminder.status),
      sortTime,
      badge: reminderStatusLabel(reminder.status, t),
      tone: reminderTone(reminder),
      title: titleKey ? t(titleKey, params) : entityName,
      detail: bodyKey ? t(bodyKey, params) : reason,
      meta: [
        reminderDateMeta(reminder.due_date, t),
        t('dashboard.workQueue.source', { rule: sourceRule, profile: sourceProfile }),
      ],
      href: routeFromReminder(reminder),
    });
  }

  if (unresolvedCompliance > 0) {
    items.push({
      id: 'compliance',
      priority: 2,
      sortTime: null,
      badge: t('dashboard.workQueue.compliance.badge'),
      tone: 'warn',
      title:
        unresolvedCompliance === 1
          ? t('dashboard.workQueue.compliance.title.one', { count: unresolvedCompliance })
          : t('dashboard.workQueue.compliance.title.other', { count: unresolvedCompliance }),
      detail: t('dashboard.workQueue.compliance.detail'),
      meta: [t('dashboard.workQueue.compliance.meta')],
    });
  }

  return items.sort(compareQueueItems);
}

function OperatorWorkQueue({ items }: { items: WorkQueueItem[] }) {
  const t = useT();
  if (items.length === 0) {
    return (
      <Card title={t('dashboard.workQueue.title')}>
        <p className="dashboard-workqueue__empty muted">{t('dashboard.workQueue.empty')}</p>
      </Card>
    );
  }

  return (
    <Card title={t('dashboard.workQueue.title')}>
      <ol className="dashboard-workqueue" aria-label={t('dashboard.workQueue.aria')}>
        {items.map((item) => (
          <li className="dashboard-workqueue__item" key={item.id}>
            <div className="dashboard-workqueue__head">
              <Badge tone={item.tone}>{item.badge}</Badge>
              {item.href ? (
                <Link className="dashboard-workqueue__title" to={item.href}>
                  {item.title}
                </Link>
              ) : (
                <span className="dashboard-workqueue__title">{item.title}</span>
              )}
            </div>
            <p className="dashboard-workqueue__detail muted">{item.detail}</p>
            <div className="dashboard-workqueue__meta">
              {item.meta.map((meta) => (
                <span className="muted" key={meta}>
                  {meta}
                </span>
              ))}
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function RecentActivity({ events }: { events: LedgerEventView[] }) {
  const t = useT();
  const locale = useLocale();
  const items = recentActivityItems(events);

  return (
    <Card title={t('dashboard.activity.title')}>
      {items.length === 0 ? (
        <EmptyState title={t('dashboard.activity.empty')} />
      ) : (
        <ol
          className="dashboard-list dashboard-list--activity"
          aria-label={t('dashboard.activity.aria')}
        >
          {items.map(({ event, kind, href }) => {
            const title = t('dashboard.activity.eventTitle', { kind: event.kind });
            return (
              <li className="dashboard-list__item" key={event.id}>
                <div className="dashboard-list__head">
                  <Badge tone={activityTone(kind)}>{activityLabel(kind, t)}</Badge>
                  {href ? (
                    <Link className="dashboard-list__title" to={href}>
                      {title}
                    </Link>
                  ) : (
                    <span className="dashboard-list__title">{title}</span>
                  )}
                </div>
                <div className="dashboard-list__meta">
                  <span>{formatDateTime(event.timestamp, locale)}</span>
                  <span>{t('dashboard.activity.actor', { actor: event.actor })}</span>
                  <span title={event.scope}>
                    {t('dashboard.activity.scope', { scope: compactScope(event.scope) })}
                  </span>
                  <span>{t('dashboard.activity.sequence', { seq: event.seq })}</span>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}

function sortedOpenBooks(openBooks: DashboardOpenBook[]): DashboardOpenBook[] {
  return openBooks.slice().sort((a, b) => {
    const aTime = a.opening_date ? Date.parse(a.opening_date) : Number.NEGATIVE_INFINITY;
    const bTime = b.opening_date ? Date.parse(b.opening_date) : Number.NEGATIVE_INFINITY;
    const aValid = !Number.isNaN(aTime);
    const bValid = !Number.isNaN(bTime);
    if (aValid && bValid && aTime !== bTime) return bTime - aTime;
    if (aValid !== bValid) return aValid ? -1 : 1;
    return a.entity_name?.localeCompare(b.entity_name ?? '', 'pt') ?? 0;
  });
}

function OpenBooksSummary({ openBooks }: { openBooks: DashboardOpenBook[] }) {
  const t = useT();
  const items = sortedOpenBooks(openBooks).slice(0, SUMMARY_LIST_LIMIT);
  const hidden = Math.max(0, openBooks.length - items.length);

  return (
    <Card title={t('dashboard.openItems.title')}>
      {items.length === 0 ? (
        <EmptyState title={t('dashboard.openItems.empty')} />
      ) : (
        <>
          <ol className="dashboard-list" aria-label={t('dashboard.openItems.aria')}>
            {items.map((book) => {
              const title = book.entity_name?.trim() || t('dashboard.openItems.unnamedEntity');
              const href = frontendRouteFromApi(book.links.book) ?? `/livros/${book.book_id}`;
              return (
                <li className="dashboard-list__item" key={book.book_id}>
                  <div className="dashboard-list__head">
                    <Badge tone="neutral">{bookKindLabels[book.kind]}</Badge>
                    <Link className="dashboard-list__title" to={href}>
                      {title}
                    </Link>
                  </div>
                  <p className="dashboard-list__detail muted">
                    {book.purpose?.trim() || t('dashboard.openItems.noPurpose')}
                  </p>
                  <div className="dashboard-list__meta">
                    <span>
                      {t('dashboard.openItems.nextAta', { number: book.next_ata_number })}
                    </span>
                    <span>{t('dashboard.openItems.openActs', { count: book.open_acts })}</span>
                    <span>{t('dashboard.openItems.totalActs', { count: book.total_acts })}</span>
                    <span>
                      {book.opening_date
                        ? t('dashboard.openItems.openedAt', { date: book.opening_date })
                        : t('dashboard.openItems.openedUnknown')}
                    </span>
                  </div>
                </li>
              );
            })}
          </ol>
          {hidden > 0 ? (
            <p className="dashboard-list__more muted">
              {t('dashboard.openItems.more', { count: hidden })}
            </p>
          ) : null}
        </>
      )}
    </Card>
  );
}

const ACTIVE_ACT_STATES: (keyof DashboardActStateCounts)[] = [
  'Draft',
  'Review',
  'Convened',
  'Deliberated',
  'TextApproved',
  'Signing',
];

function ActStatusSummary({ counts }: { counts: DashboardActStateCounts }) {
  const t = useT();
  const activeTotal = ACTIVE_ACT_STATES.reduce((total, state) => total + counts[state], 0);

  return (
    <Card title={t('dashboard.actStatus.title')}>
      {activeTotal === 0 ? (
        <EmptyState title={t('dashboard.actStatus.empty')} />
      ) : (
        <dl className="dashboard-status-grid" aria-label={t('dashboard.actStatus.aria')}>
          {ACTIVE_ACT_STATES.map((state) => (
            <div className="dashboard-status-grid__item" key={state}>
              <dt>{actStateLabels[state]}</dt>
              <dd>{counts[state]}</dd>
            </div>
          ))}
        </dl>
      )}
    </Card>
  );
}

function ActivityNumberCards({ counts }: { counts: DashboardActStateCounts }) {
  const t = useT();

  return (
    <section className="dashboard-card-section">
      <h3 className="dashboard-card-section__title">{t('dashboard.actStatus.title')}</h3>
      <ul
        className="cards dashboard-metrics dashboard-activity-metrics"
        aria-label={t('dashboard.actStatus.aria')}
      >
        {ACTIVE_ACT_STATES.map((state) => (
          <Metric key={state} label={actStateLabels[state]} value={counts[state]} />
        ))}
      </ul>
    </section>
  );
}

function DashboardStats({ data }: { data: Dashboard }) {
  const t = useT();

  return (
    <div className="dashboard-tab dashboard-tab--stats">
      <ul className="cards dashboard-metrics">
        <Metric label={t('dashboard.metric.entities')} value={data.entities} />
        <Metric
          label={t('dashboard.metric.booksOpen')}
          value={data.books_open}
          note={t('dashboard.metric.booksOpen.note', { total: data.books_total })}
        />
        <Metric
          label={t('dashboard.metric.actsDraft')}
          value={data.acts_draft}
          note={t('dashboard.metric.actsDraft.note', { total: data.acts_total })}
        />
        <Metric
          label={t('dashboard.metric.awaitingSignature')}
          value={data.acts_awaiting_signature}
          note={t('dashboard.metric.awaitingSignature.note')}
        />
        <Metric
          label={t('dashboard.metric.actsSealed')}
          value={data.acts_sealed}
          note={t('dashboard.metric.actsSealed.note')}
        />
        <Metric
          label={t('dashboard.metric.ledger')}
          value={data.ledger_length}
          note={
            data.ledger_valid
              ? t('dashboard.metric.ledger.note.valid')
              : t('dashboard.metric.ledger.note.invalid')
          }
        />
      </ul>

      <div className="row-wrap">
        <div className="chain-status">
          <span className="card__label">{t('dashboard.integrity.label')}</span>{' '}
          {data.ledger_valid ? (
            <Badge tone="ok">{t('dashboard.chain.verified')}</Badge>
          ) : (
            <Badge tone="error">{t('dashboard.chain.compromised')}</Badge>
          )}
        </div>
      </div>

      {data.unresolved_compliance > 0 ? (
        <InlineWarning tone="warn" title={t('dashboard.compliance.title')}>
          {data.unresolved_compliance === 1
            ? t('dashboard.compliance.body.one', { count: data.unresolved_compliance })
            : t('dashboard.compliance.body.other', { count: data.unresolved_compliance })}
        </InlineWarning>
      ) : null}

      <ActivityNumberCards counts={data.current_work.act_counts_by_state} />
    </div>
  );
}

function DashboardHeader({
  active,
  onSelect,
}: {
  active: DashboardTab;
  onSelect: (tab: DashboardTab) => void;
}) {
  const t = useT();

  return (
    <PageHeader title={t('dashboard.title')}>
      <SubNav<DashboardTab>
        ariaLabel={t('dashboard.tabs.aria')}
        active={active}
        onSelect={onSelect}
        items={[
          { id: 'stats', label: t('dashboard.tabs.stats'), icon: <Icon.Sliders /> },
          { id: 'activity', label: t('dashboard.tabs.activity'), icon: <Icon.Bell /> },
          { id: 'current', label: t('dashboard.tabs.current'), icon: <Icon.Calendar /> },
          { id: 'queue', label: t('dashboard.tabs.queue'), icon: <Icon.Tray /> },
          { id: 'events', label: t('dashboard.tabs.events'), icon: <Icon.Archive /> },
        ]}
      />
    </PageHeader>
  );
}

function reminderSortValue(reminder: DashboardReminder): number {
  const date = parseReminderDate(reminder.due_date);
  if (date !== null) return date;
  if (reminder.status === 'Overdue') return Number.NEGATIVE_INFINITY;
  return Number.POSITIVE_INFINITY;
}

function ReminderDatesSummary({ reminders }: { reminders: DashboardReminder[] }) {
  const t = useT();
  const sortedReminders = dedupeReminders(reminders)
    .slice()
    .sort((a, b) => reminderSortValue(a) - reminderSortValue(b));
  const items = sortedReminders.slice(0, SUMMARY_LIST_LIMIT);
  const hidden = Math.max(0, sortedReminders.length - items.length);

  return (
    <Card title={t('dashboard.dates.title')}>
      {items.length === 0 ? (
        <EmptyState title={t('dashboard.dates.empty')} />
      ) : (
        <>
          <ol className="dashboard-list" aria-label={t('dashboard.dates.aria')}>
            {items.map((reminder) => {
              const entityName =
                reminder.entity_name.trim() || t('dashboard.workQueue.entity.unnamed');
              const href = routeFromReminder(reminder);
              const dateLabel = reminderDateLabel(reminder.due_date, t);
              return (
                <li
                  className="dashboard-list__item"
                  key={`${reminder.entity_id}:${reminder.source_rule}:${reminder.source_profile}:${reminder.due_date}:${reminder.status}`}
                >
                  <div className="dashboard-list__head">
                    <Badge tone={reminderTone(reminder)}>
                      {reminderStatusLabel(reminder.status, t)}
                    </Badge>
                    {href ? (
                      <Link className="dashboard-list__title" to={href}>
                        {entityName}
                      </Link>
                    ) : (
                      <span className="dashboard-list__title">{entityName}</span>
                    )}
                  </div>
                  <div className="dashboard-list__meta">
                    <span>{t('dashboard.dates.due', { date: dateLabel })}</span>
                    <span>
                      {t('dashboard.workQueue.source', {
                        rule: reminder.source_rule || t('dashboard.workQueue.rule.missing'),
                        profile:
                          reminder.source_profile || t('dashboard.workQueue.profile.missing'),
                      })}
                    </span>
                  </div>
                </li>
              );
            })}
          </ol>
          {hidden > 0 ? (
            <p className="dashboard-list__more muted">
              {t('dashboard.dates.more', { count: hidden })}
            </p>
          ) : null}
        </>
      )}
    </Card>
  );
}

export function DashboardPage() {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const { data, isLoading, error } = useDashboard();
  const tab = dashboardTabFromParam(params.get(DASHBOARD_TAB_PARAM));

  function selectTab(next: DashboardTab) {
    setParams(
      (prev) => {
        const nextParams = new URLSearchParams(prev);
        if (next === 'stats') nextParams.delete(DASHBOARD_TAB_PARAM);
        else nextParams.set(DASHBOARD_TAB_PARAM, next);
        return nextParams;
      },
      { replace: true },
    );
  }

  if (isLoading) {
    return (
      <div className="stack">
        <DashboardHeader active={tab} onSelect={selectTab} />
        <div className="route-transition dashboard-tab" key={`loading-${tab}`}>
          {tab === 'events' ? (
            <Card title={t('dashboard.recentEvents.title')}>
              <SkeletonTable cols={5} />
            </Card>
          ) : (
            <SkeletonCards />
          )}
        </div>
      </div>
    );
  }
  if (error) return <ErrorNote error={error} />;
  if (!data) return null;

  const recentEvents = data.recent_events
    .slice()
    .sort(compareByRecency)
    .slice(0, RECENT_EVENTS_LIMIT);
  const workQueueItems = buildWorkQueue({
    ledgerValid: data.ledger_valid,
    unresolvedCompliance: data.unresolved_compliance,
    alerts: data.alerts,
    reminders: data.reminders,
    t,
  });

  return (
    <div className="stack">
      <DashboardHeader active={tab} onSelect={selectTab} />

      <div className="route-transition" key={tab}>
        {tab === 'stats' ? <DashboardStats data={data} /> : null}

        {tab === 'activity' ? <RecentActivity events={data.recent_events} /> : null}

        {tab === 'current' ? (
          <div className="dashboard-section-grid">
            <OpenBooksSummary openBooks={data.current_work.open_books} />
            <ActStatusSummary counts={data.current_work.act_counts_by_state} />
            <ReminderDatesSummary reminders={data.reminders} />
          </div>
        ) : null}

        {tab === 'queue' ? <OperatorWorkQueue items={workQueueItems} /> : null}

        {tab === 'events' ? (
          <Card
            title={t('dashboard.recentEvents.title')}
            actions={
              <Tooltip label={t('dashboard.viewFullArchive')} placement="left">
                <Link
                  to="/arquivo"
                  className="btn btn--secondary btn--icon btn--iconOnly dashboard-archive-link"
                  aria-label={t('dashboard.viewFullArchive')}
                >
                  <span className="btn__icon">
                    <Icon.Archive />
                  </span>
                </Link>
              </Tooltip>
            }
          >
            <LedgerTable events={recentEvents} />
          </Card>
        ) : null}
      </div>
    </div>
  );
}
