/**
 * Painel — the WFL-40 dashboard subset (plan t5 §2.7). Counts, the chain-valid
 * indicator, an unresolved-compliance callout, advisory reminders, and the last ledger
 * events. Everything is derived from `GET /v1/dashboard`, which the seal/mutation hooks
 * invalidate, so the numbers stay live.
 */
import { Link, useSearchParams } from 'react-router-dom';
import { useDashboard } from '../../api/hooks';
import { actStateLabels, bookKindLabels, ledgerEventKindLabel } from '../../api/labels';
import type {
  Dashboard,
  DashboardAlert,
  DashboardActStateCounts,
  DashboardCurrentWork,
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
  SkeletonDeflist,
  SkeletonList,
  SkeletonRegion,
  SubNav,
  Tooltip,
  TooltipText,
} from '../../ui';
import { LedgerTable } from '../ledger/LedgerTable';
import { actConveningGuidanceRoute } from '../acts/anchors';
import './DashboardPage.css';

const NO_ACT_COUNTS: DashboardActStateCounts = {
  Draft: 0,
  Review: 0,
  Convened: 0,
  Deliberated: 0,
  TextApproved: 0,
  Signing: 0,
  Sealed: 0,
  Archived: 0,
};

/**
 * Every collection below is required by the contract, so this normalisation should be a no-op
 * against a correct server. It exists because the whole route lives behind a single error
 * boundary: a response that omits `current_work` (or one of the lists) must degrade to the
 * "nothing open" state each summary already renders for a tenant with no work, not to a white
 * screen. Done once here so the summaries downstream stay unconditional.
 */
function withDashboardDefaults(data: Dashboard): Dashboard {
  const currentWork = data.current_work as Partial<DashboardCurrentWork> | undefined;
  return {
    ...data,
    current_work: {
      open_books: currentWork?.open_books ?? [],
      act_counts_by_state: { ...NO_ACT_COUNTS, ...currentWork?.act_counts_by_state },
    },
    alerts: data.alerts ?? [],
    reminders: data.reminders ?? [],
    recent_events: data.recent_events ?? [],
  };
}

const RECENT_EVENTS_LIMIT = 10;
const SUMMARY_LIST_LIMIT = 5;
const DASHBOARD_TAB_PARAM = 'painel';

type QueueTone = 'neutral' | 'accent' | 'warn' | 'error';
type ActivityKind = 'act' | 'book' | 'entity';
type DashboardTab = 'current' | 'stats' | 'activity' | 'dates' | 'queue' | 'events';

export interface WorkQueueItem {
  id: string;
  priority: number;
  sortTime: number | null;
  badge: string;
  tone: QueueTone;
  title: string;
  detail: string;
  meta: string[];
  href?: string;
  actionLabel?: string;
}

interface ReminderCopy {
  title: MessageKey;
  body: MessageKey;
  action: MessageKey;
}

interface ActivityItem {
  event: LedgerEventView;
  kind: ActivityKind;
  href?: string;
}

export function lawRefSourcePending(ref: DashboardLawReference): boolean {
  return ref.source_complete === false || ref.verification === 'Pending';
}

export function lawRefMeta(ref: DashboardLawReference): string {
  const label = `${ref.diploma_id}:${ref.article}`;
  return lawRefSourcePending(ref) ? `Lei ${label} · fonte pendente` : `Lei ${label}`;
}

export function compareByRecency(a: LedgerEventView, b: LedgerEventView): number {
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

/**
 * `current` is the landing panel, so — following the `?sec=` convention the other sub-tab
 * surfaces use — it is the section that carries no param. Every other section, `stats`
 * included, keeps an explicit value, which is why `?painel=stats` has to be recognised here.
 */
export function dashboardTabFromParam(value: string | null): DashboardTab {
  if (
    value === 'stats' ||
    value === 'activity' ||
    value === 'dates' ||
    value === 'queue' ||
    value === 'events'
  ) {
    return value;
  }
  return 'current';
}

export function formatDashboardDateTime(value: string, locale: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(locale);
}

export function shortDashboardId(value: string): string {
  return value.slice(0, 8);
}

export function idFromScopedValue(value: string, prefix: string): string | undefined {
  const marker = `${prefix}:`;
  return value.startsWith(marker) ? value.slice(marker.length).trim() || undefined : undefined;
}

export function firstChainId(event: LedgerEventView, prefix: string): string | undefined {
  for (const chain of event.chains) {
    const id = idFromScopedValue(chain, prefix);
    if (id) return id;
  }
  return undefined;
}

export function dashboardActivityKind(event: LedgerEventView): ActivityKind | null {
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

export function routeFromDashboardActivity(
  event: LedgerEventView,
  kind: ActivityKind,
): string | undefined {
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

export function dashboardActivityTone(kind: ActivityKind): QueueTone {
  if (kind === 'act') return 'accent';
  if (kind === 'book') return 'neutral';
  return 'warn';
}

export function dashboardActivityLabel(kind: ActivityKind, t: TFunction): string {
  if (kind === 'act') return t('dashboard.activity.kind.act');
  if (kind === 'book') return t('dashboard.activity.kind.book');
  return t('dashboard.activity.kind.entity');
}

export function recentActivityItems(events: LedgerEventView[]): ActivityItem[] {
  return events
    .slice()
    .sort(compareByRecency)
    .reduce<ActivityItem[]>((items, event) => {
      if (items.length >= RECENT_EVENTS_LIMIT) return items;
      const kind = dashboardActivityKind(event);
      if (!kind) return items;
      items.push({ event, kind, href: routeFromDashboardActivity(event, kind) });
      return items;
    }, []);
}

export function compactDashboardScope(scope: string): string {
  const [kind, id] = scope.split(':', 2);
  if (!id) return scope.length > 24 ? `${scope.slice(0, 8)}...` : scope;
  return `${kind}:${shortDashboardId(id)}`;
}

/**
 * Human names for the ids that appear in `recent_events[].scope`, harvested from the SAME
 * `/v1/dashboard` payload the activity list is rendered from. `scope` only ever carries an
 * id, so the alternative to this index is one lookup per row; the payload already names the
 * open books' entities and every reminder's entity, which covers the scopes an operator
 * actually recognises. Anything unnamed keeps the compact id.
 */
export function dashboardScopeNames(data: Dashboard): Map<string, string> {
  const names = new Map<string, string>();

  for (const book of data.current_work.open_books) {
    const name = book.entity_name?.trim();
    if (name) names.set(book.book_id.trim(), name);
  }
  for (const reminder of data.reminders) {
    const name = reminder.entity_name.trim();
    const id = reminder.entity_id.trim();
    if (name && id) names.set(id, name);
  }

  return names;
}

/** The scope's human name when the payload knows it, else the compact `kind:id` form. */
export function dashboardScopeLabel(scope: string, names: Map<string, string>): string {
  const [, id] = scope.split(':', 2);
  return names.get((id ?? scope).trim()) ?? compactDashboardScope(scope);
}

export function dashboardReminderTone(reminder: DashboardReminder): 'neutral' | 'accent' | 'warn' {
  if (reminder.status === 'Overdue') return 'warn';
  if (reminder.status === 'DueSoon') return 'accent';
  return 'neutral';
}

export function dashboardReminderStatusLabel(
  status: DashboardReminder['status'],
  t: TFunction,
): string {
  if (status === 'Pending') return t('dashboard.workQueue.status.pending');
  if (status === 'Overdue') return t('dashboard.workQueue.status.overdue');
  if (status === 'DueSoon') return t('dashboard.workQueue.status.dueSoon');
  return t('dashboard.workQueue.status.upcoming');
}

export function parseDashboardReminderDate(value: string): number | null {
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

export function dashboardReminderDateLabel(dueDate: string, t: TFunction): string {
  const trimmed = dueDate.trim();
  if (!trimmed) return t('dashboard.workQueue.date.missing');
  return parseDashboardReminderDate(trimmed) === null
    ? t('dashboard.workQueue.date.invalid')
    : trimmed;
}

export function dashboardReminderDateMeta(dueDate: string, t: TFunction): string {
  const label = dashboardReminderDateLabel(dueDate, t);
  const missing = t('dashboard.workQueue.date.missing');
  const invalid = t('dashboard.workQueue.date.invalid');
  if (label === missing || label === invalid) return label;
  return t('dashboard.workQueue.date.value', { date: label });
}

export function dashboardReminderPriority(status: DashboardReminder['status']): number {
  if (status === 'Overdue') return 1;
  if (status === 'Pending') return 3;
  if (status === 'DueSoon') return 3;
  return 4;
}

export function dedupeDashboardReminders(reminders: DashboardReminder[]): DashboardReminder[] {
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

export function profileCalendarPlanMeta(reminder: DashboardReminder, t: TFunction): string | null {
  const plan = reminder.profile_calendar_plan;
  if (!plan) return null;
  const support = plan.support_status.trim().toLowerCase();
  const review = plan.review_status.trim().toLowerCase();

  if (review === 'pending_source_review') {
    if (support === 'supported') {
      return t('dashboard.profileCalendar.meta.supportedPendingSourceReview');
    }
    if (support === 'unsupported') {
      return t('dashboard.profileCalendar.meta.unsupportedPendingSourceReview');
    }
    return t('dashboard.profileCalendar.meta.pendingSourceReview');
  }

  if (support === 'supported') return t('dashboard.profileCalendar.meta.supportedAdvisory');
  if (support === 'unsupported') return t('dashboard.profileCalendar.meta.unsupportedAdvisory');
  return t('dashboard.profileCalendar.meta.unknownAdvisory');
}

export function dashboardMessageKey(value: string | null | undefined): MessageKey | undefined {
  return value?.trim() ? (value.trim() as MessageKey) : undefined;
}

export function dashboardFrontendRouteFromApi(path: string | null | undefined): string | undefined {
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

export function generatedDispatchDocumentIdFromApi(
  path: string | null | undefined,
): string | undefined {
  const route = path?.trim();
  if (!route) return undefined;
  const match = /^\/v1\/documents\/generated\/([^/?#]+)\/dispatch-evidence(?:[?#/]|$)/.exec(route);
  if (!match) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

export function importedDocumentIdFromApi(path: string | null | undefined): string | undefined {
  const route = path?.trim();
  if (!route) return undefined;
  const match = /^\/v1\/documents\/imported\/([^/?#]+)(?:[?#/]|$)/.exec(route);
  if (!match) return undefined;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

export function generatedDispatchEvidenceRoute(
  actRoute: string | undefined,
  documentId: string | undefined,
): string | undefined {
  const trimmedDocumentId = documentId?.trim();
  if (!actRoute || !trimmedDocumentId) return undefined;
  const url = new URL(actRoute, 'http://chancela.local');
  url.searchParams.set('generated_document_id', trimmedDocumentId);
  url.searchParams.set('focus', 'dispatch-evidence');
  url.hash = 'generated-dispatch-evidence';
  return `${url.pathname}${url.search}${url.hash}`;
}

export function importedDocumentReviewRoute(
  actRoute: string | undefined,
  importedDocumentId: string | undefined,
): string | undefined {
  const trimmedImportedDocumentId = importedDocumentId?.trim();
  if (!actRoute || !trimmedImportedDocumentId) return undefined;
  const url = new URL(actRoute, 'http://chancela.local');
  url.searchParams.set('imported_document_id', trimmedImportedDocumentId);
  url.searchParams.set('focus', 'import-review');
  url.hash = 'imported-documents';
  return `${url.pathname}${url.search}${url.hash}`;
}

export function dashboardReminderActRoute(reminder: DashboardReminder): string | undefined {
  return (
    dashboardFrontendRouteFromApi(reminder.action?.route) ??
    dashboardFrontendRouteFromApi(reminder.action?.api_href) ??
    (reminder.params?.act_id?.trim() ? `/atas/${reminder.params.act_id.trim()}` : undefined)
  );
}

export function isConveningNoticeReminder(reminder: DashboardReminder): boolean {
  return (
    reminder.action?.kind === 'open_act_convening_notice' ||
    reminder.source_rule.trim() === 'act-convening-notice'
  );
}

export function routeFromDashboardAlert(alert: DashboardAlert): string | undefined {
  const metadataRoute =
    dashboardFrontendRouteFromApi(alert.action?.route) ??
    dashboardFrontendRouteFromApi(alert.action?.api_href);
  if (metadataRoute) return metadataRoute;
  const links = alert.target.links;
  return (
    dashboardFrontendRouteFromApi(links.act) ??
    (alert.target.act_id?.trim() ? `/atas/${alert.target.act_id.trim()}` : undefined) ??
    dashboardFrontendRouteFromApi(links.book) ??
    (alert.target.book_id?.trim() ? `/livros/${alert.target.book_id.trim()}` : undefined) ??
    dashboardFrontendRouteFromApi(links.entity) ??
    (alert.target.entity_id?.trim() ? `/entidades/${alert.target.entity_id.trim()}` : undefined) ??
    dashboardFrontendRouteFromApi(links.ledger)
  );
}

export function routeFromDashboardReminder(reminder: DashboardReminder): string | undefined {
  if (isConveningNoticeReminder(reminder)) {
    const route = actConveningGuidanceRoute(dashboardReminderActRoute(reminder));
    if (route) return route;
  }

  if (reminder.action?.kind === 'open_imported_document_review') {
    const actRoute =
      dashboardFrontendRouteFromApi(reminder.action.route) ??
      (reminder.params?.act_id?.trim() ? `/atas/${reminder.params.act_id.trim()}` : undefined);
    const importedDocumentId =
      reminder.params?.imported_document_id?.trim() ??
      importedDocumentIdFromApi(reminder.action.api_href);
    const route = importedDocumentReviewRoute(actRoute, importedDocumentId);
    if (route) return route;
  }

  if (
    reminder.action?.kind === 'open_absent_owner_dispatch_evidence' ||
    reminder.action?.kind === 'open_generated_convening_dispatch_evidence'
  ) {
    const actRoute =
      dashboardFrontendRouteFromApi(reminder.action.route) ??
      (reminder.params?.act_id?.trim() ? `/atas/${reminder.params.act_id.trim()}` : undefined);
    const documentId =
      reminder.params?.generated_document_id?.trim() ??
      reminder.params?.document_id?.trim() ??
      generatedDispatchDocumentIdFromApi(reminder.action.api_href);
    const route = generatedDispatchEvidenceRoute(actRoute, documentId);
    if (route) return route;
  }

  const metadataRoute =
    dashboardFrontendRouteFromApi(reminder.action?.route) ??
    dashboardFrontendRouteFromApi(reminder.action?.api_href);
  if (metadataRoute) return metadataRoute;
  const entityId = reminder.entity_id.trim();
  return entityId ? `/entidades/${entityId}` : undefined;
}

export function dashboardAlertTone(alert: DashboardAlert): QueueTone {
  if (alert.severity === 'Error' || alert.code === 'ledger.integrity.review_required')
    return 'error';
  if (alert.severity === 'Warning' || alert.label === 'ReviewRequired') return 'warn';
  return 'accent';
}

export function dashboardAlertPriority(alert: DashboardAlert): number {
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
  'backup.recovery.freshness_advisory': {
    title: 'notifications.alert.backupRecoveryFreshness.title',
    body: 'notifications.alert.backupRecoveryFreshness.body',
  },
};

const CONVENING_NOTICE_MISSING_MEETING_DATE_BODY: MessageKey =
  'notifications.reminder.act.conveningNotice.missingMeetingDate.body';

const REMINDER_COPY: Partial<Record<string, ReminderCopy>> = {
  'csc-art376-annual': {
    title: 'notifications.reminder.annual.csc.title',
    body: 'notifications.reminder.annual.body',
    action: 'notifications.reminder.annual.action',
  },
  'assoc-annual': {
    title: 'notifications.reminder.annual.assoc.title',
    body: 'notifications.reminder.annual.body',
    action: 'notifications.reminder.annual.action',
  },
  'fundacao-annual': {
    title: 'notifications.reminder.annual.fundacao.title',
    body: 'notifications.reminder.annual.body',
    action: 'notifications.reminder.annual.action',
  },
  'cooperativa-annual': {
    title: 'notifications.reminder.annual.cooperativa.title',
    body: 'notifications.reminder.annual.body',
    action: 'notifications.reminder.annual.action',
  },
  'condominio-annual': {
    title: 'notifications.reminder.annual.condominio.title',
    body: 'notifications.reminder.annual.body',
    action: 'notifications.reminder.annual.action',
  },
  'act-convening-notice': {
    title: 'notifications.reminder.act.conveningNotice.title',
    body: 'notifications.reminder.act.conveningNotice.body',
    action: 'notifications.reminder.act.conveningNotice.action',
  },
};

export function reminderHasMissingMeetingDate(
  reminder: DashboardReminder,
  sourceRule: string,
): boolean {
  if (sourceRule !== 'act-convening-notice') return false;
  const params = reminder.params ?? {};
  const hasMeetingDateParam = Object.prototype.hasOwnProperty.call(params, 'meeting_date');
  const hasNoticeDueDateParam = Object.prototype.hasOwnProperty.call(params, 'notice_due_date');
  return (
    params.evidence_status?.trim() === 'missing_meeting_date' ||
    params.notice_due_date_computable?.trim() === 'false' ||
    (hasMeetingDateParam &&
      hasNoticeDueDateParam &&
      !params.meeting_date?.trim() &&
      !params.notice_due_date?.trim())
  );
}

export function dashboardReminderCopyFor(
  reminder: DashboardReminder,
  sourceRule: string,
): ReminderCopy | undefined {
  const copy = REMINDER_COPY[sourceRule];
  if (!copy) return undefined;
  if (reminderHasMissingMeetingDate(reminder, sourceRule)) {
    return {
      ...copy,
      body: CONVENING_NOTICE_MISSING_MEETING_DATE_BODY,
    };
  }
  return copy;
}

export function dashboardAlertWorkQueueItem(
  alert: DashboardAlert,
  index: number,
  t: TFunction,
): WorkQueueItem {
  const code = alert.code.trim();
  const copy = ALERT_COPY[code];
  const titleKey = dashboardMessageKey(alert.i18n?.title_key) ?? copy?.title;
  const bodyKey = dashboardMessageKey(alert.i18n?.body_key) ?? copy?.body;
  const params: TParams = { ...alert.params, code };
  const lawRefs = (alert.law_refs ?? []).map(lawRefMeta).filter(Boolean);

  return {
    id: `alert:${code || 'unknown'}:${index}`,
    priority: dashboardAlertPriority(alert),
    sortTime: null,
    badge: t('notifications.badge.alert'),
    tone: dashboardAlertTone(alert),
    title: titleKey ? t(titleKey, params) : t('notifications.alert.unknown.title', params),
    detail: bodyKey
      ? t(bodyKey, params)
      : alert.message.trim() || t('notifications.alert.fallbackDetail'),
    meta: [
      ...(alert.source ? [t('notifications.alert.source', { source: alert.source })] : []),
      ...lawRefs,
    ],
    href: routeFromDashboardAlert(alert),
  };
}

export function compareDashboardQueueItems(a: WorkQueueItem, b: WorkQueueItem): number {
  if (a.priority !== b.priority) return a.priority - b.priority;
  if (a.sortTime !== null && b.sortTime !== null && a.sortTime !== b.sortTime) {
    return a.sortTime - b.sortTime;
  }
  if (a.sortTime !== null || b.sortTime !== null) return a.sortTime === null ? 1 : -1;
  const byTitle = a.title.localeCompare(b.title, 'pt');
  return byTitle || a.id.localeCompare(b.id);
}

export function buildDashboardWorkQueue({
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
    items.push(dashboardAlertWorkQueueItem(alert, index, t));
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

  for (const reminder of dedupeDashboardReminders(reminders)) {
    const dueDate = reminder.due_date.trim();
    const sortTime = dueDate ? parseDashboardReminderDate(dueDate) : null;
    const entityName = reminder.entity_name.trim() || t('dashboard.workQueue.entity.unnamed');
    const entityId = reminder.entity_id.trim();
    const sourceRule = reminder.source_rule.trim() || t('dashboard.workQueue.rule.missing');
    const sourceProfile =
      reminder.source_profile.trim() || t('dashboard.workQueue.profile.missing');
    const reason = reminder.reason.trim() || t('dashboard.workQueue.reminder.fallback');
    const params: TParams = {
      ...(reminder.params ?? {}),
      entity_name: entityName,
      due_date: dashboardReminderDateLabel(reminder.due_date, t),
      source_rule: sourceRule,
      source_profile: sourceProfile,
      reason,
    };
    const titleKey = dashboardMessageKey(reminder.i18n?.title_key);
    const bodyKey = dashboardMessageKey(reminder.i18n?.body_key);
    const copy = dashboardReminderCopyFor(reminder, sourceRule);
    const effectiveTitleKey = titleKey ?? copy?.title;
    const effectiveBodyKey = bodyKey ?? copy?.body;
    const actionKey = copy?.action;
    const planMeta = profileCalendarPlanMeta(reminder, t);

    items.push({
      id: `reminder:${entityId}:${sourceRule}:${sourceProfile}:${dueDate}:${reminder.status}`,
      priority: dashboardReminderPriority(reminder.status),
      sortTime,
      badge: dashboardReminderStatusLabel(reminder.status, t),
      tone: dashboardReminderTone(reminder),
      title: effectiveTitleKey ? t(effectiveTitleKey, params) : entityName,
      detail: effectiveBodyKey ? t(effectiveBodyKey, params) : reason,
      meta: [
        dashboardReminderDateMeta(reminder.due_date, t),
        t('dashboard.workQueue.source', { rule: sourceRule, profile: sourceProfile }),
        ...(planMeta ? [planMeta] : []),
      ],
      href: routeFromDashboardReminder(reminder),
      actionLabel: actionKey ? t(actionKey, params) : undefined,
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

  return items.sort(compareDashboardQueueItems);
}

function WorkQueueActionLink({ href, label }: { href: string; label: string }) {
  return (
    <Tooltip label={label} placement="left">
      <Link
        className="btn btn--ghost btn--icon btn--iconOnly dashboard-workqueue__action"
        to={href}
        aria-label={label}
      >
        <span className="btn__icon" aria-hidden="true">
          <Icon.ArrowRight />
        </span>
      </Link>
    </Tooltip>
  );
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
              <span className="dashboard-workqueue__title">{item.title}</span>
              {item.href ? (
                <WorkQueueActionLink href={item.href} label={item.actionLabel ?? item.title} />
              ) : null}
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

function RecentActivity({ data }: { data: Dashboard }) {
  const t = useT();
  const locale = useLocale();
  const items = recentActivityItems(data.recent_events);
  const scopeNames = dashboardScopeNames(data);

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
            const title = ledgerEventKindLabel(event.kind);
            // The raw dotted id is what the Arquivo filter takes, so keep it one hover away.
            const rawKind = t('dashboard.activity.eventTitle', { kind: event.kind });
            return (
              <li className="dashboard-list__item" key={event.id}>
                <div className="dashboard-list__head">
                  <Badge tone={dashboardActivityTone(kind)}>
                    {dashboardActivityLabel(kind, t)}
                  </Badge>
                  {href ? (
                    <Tooltip label={rawKind}>
                      <Link className="dashboard-list__title" to={href}>
                        {title}
                      </Link>
                    </Tooltip>
                  ) : (
                    <TooltipText className="dashboard-list__title" label={rawKind}>
                      {title}
                    </TooltipText>
                  )}
                </div>
                <div className="dashboard-list__meta">
                  <span>{formatDashboardDateTime(event.timestamp, locale)}</span>
                  <span>{t('dashboard.activity.actor', { actor: event.actor })}</span>
                  {/* The name is what an operator recognises; the full scope id stays in the
                      bubble. `TooltipText` drops the bubble when the two are the same string,
                      which is exactly the unnamed-scope case. */}
                  <TooltipText label={event.scope}>
                    {t('dashboard.activity.scope', {
                      scope: dashboardScopeLabel(event.scope, scopeNames),
                    })}
                  </TooltipText>
                  <TooltipText label={t('dashboard.activity.sequence.title')}>
                    {t('dashboard.activity.sequence', { seq: event.seq })}
                  </TooltipText>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}

export function sortedDashboardOpenBooks(openBooks: DashboardOpenBook[]): DashboardOpenBook[] {
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
  const items = sortedDashboardOpenBooks(openBooks).slice(0, SUMMARY_LIST_LIMIT);
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
              const href =
                dashboardFrontendRouteFromApi(book.links.book) ?? `/livros/${book.book_id}`;
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
      <ul
        className="cards dashboard-metrics dashboard-metrics--summary"
        data-dashboard-density="desktop-six"
      >
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

      <section className="dashboard-card-section" aria-labelledby="dashboard-connector-jobs-title">
        <div className="dashboard-card-section__heading">
          <h3 className="dashboard-card-section__title" id="dashboard-connector-jobs-title">
            {t('dashboard.connectors.title')}
          </h3>
          <Link className="btn btn--secondary" to="/operacoes?view=connectors">
            {t('dashboard.connectors.open')}
          </Link>
        </div>
        <ul className="cards dashboard-metrics dashboard-activity-metrics">
          <Metric
            label={t('dashboard.connectors.failedSync')}
            value={data.failed_sync_jobs}
            note={t('dashboard.connectors.failedSync.note')}
          />
          <Metric
            label={t('dashboard.connectors.pendingBackup')}
            value={data.pending_backup_jobs}
            note={t('dashboard.connectors.pendingBackup.note')}
          />
        </ul>
      </section>

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
          { id: 'current', label: t('dashboard.tabs.current'), icon: <Icon.Layers /> },
          { id: 'stats', label: t('dashboard.tabs.stats'), icon: <Icon.Sliders /> },
          { id: 'activity', label: t('dashboard.tabs.activity'), icon: <Icon.Bell /> },
          { id: 'dates', label: t('dashboard.tabs.dates'), icon: <Icon.Calendar /> },
          { id: 'queue', label: t('dashboard.tabs.queue'), icon: <Icon.Tray /> },
          { id: 'events', label: t('dashboard.tabs.events'), icon: <Icon.Archive /> },
        ]}
      />
    </PageHeader>
  );
}

function reminderSortValue(reminder: DashboardReminder): number {
  const date = parseDashboardReminderDate(reminder.due_date);
  if (date !== null) return date;
  if (reminder.status === 'Overdue') return Number.NEGATIVE_INFINITY;
  if (reminder.status === 'Pending') return Number.POSITIVE_INFINITY - 1;
  return Number.POSITIVE_INFINITY;
}

function ReminderDatesSummary({ reminders }: { reminders: DashboardReminder[] }) {
  const t = useT();
  const sortedReminders = dedupeDashboardReminders(reminders)
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
              const href = routeFromDashboardReminder(reminder);
              const dateLabel = dashboardReminderDateLabel(reminder.due_date, t);
              const planMeta = profileCalendarPlanMeta(reminder, t);
              return (
                <li
                  className="dashboard-list__item"
                  key={`${reminder.entity_id}:${reminder.source_rule}:${reminder.source_profile}:${reminder.due_date}:${reminder.status}`}
                >
                  <div className="dashboard-list__head">
                    <Badge tone={dashboardReminderTone(reminder)}>
                      {dashboardReminderStatusLabel(reminder.status, t)}
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
                    {planMeta ? <span>{planMeta}</span> : null}
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
  const { data: payload, isLoading, error } = useDashboard();
  const tab = dashboardTabFromParam(params.get(DASHBOARD_TAB_PARAM));

  function selectTab(next: DashboardTab) {
    setParams(
      (prev) => {
        const nextParams = new URLSearchParams(prev);
        if (next === 'current') nextParams.delete(DASHBOARD_TAB_PARAM);
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
        {/* Each tab gets the skeleton shaped like the panel it is about to become, and
            keeps that panel's real Card heading, so the content lands where the
            placeholder was instead of a metric grid collapsing into a list. */}
        <SkeletonRegion className="route-transition dashboard-tab" key={`loading-${tab}`}>
          {tab === 'current' ? (
            <div className="dashboard-section-grid">
              <Card title={t('dashboard.openItems.title')}>
                <SkeletonList items={3} />
              </Card>
              <Card title={t('dashboard.actStatus.title')}>
                <SkeletonDeflist rows={4} />
              </Card>
            </div>
          ) : null}

          {tab === 'stats' ? <SkeletonCards /> : null}

          {tab === 'activity' ? (
            <Card title={t('dashboard.activity.title')}>
              <SkeletonList />
            </Card>
          ) : null}

          {tab === 'dates' ? (
            <Card title={t('dashboard.dates.title')}>
              <SkeletonList items={3} />
            </Card>
          ) : null}

          {tab === 'queue' ? (
            <Card title={t('dashboard.workQueue.title')}>
              <SkeletonList items={3} />
            </Card>
          ) : null}

          {tab === 'events' ? (
            <Card title={t('dashboard.recentEvents.title')}>
              <SkeletonTable cols={5} />
            </Card>
          ) : null}
        </SkeletonRegion>
      </div>
    );
  }
  if (error) return <ErrorNote error={error} />;
  if (!payload) return null;

  const data = withDashboardDefaults(payload);
  const recentEvents = data.recent_events
    .slice()
    .sort(compareByRecency)
    .slice(0, RECENT_EVENTS_LIMIT);
  const workQueueItems = buildDashboardWorkQueue({
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
        {tab === 'current' ? (
          <div className="dashboard-section-grid">
            <OpenBooksSummary openBooks={data.current_work.open_books} />
            <ActStatusSummary counts={data.current_work.act_counts_by_state} />
          </div>
        ) : null}

        {tab === 'stats' ? <DashboardStats data={data} /> : null}

        {tab === 'activity' ? <RecentActivity data={data} /> : null}

        {tab === 'dates' ? <ReminderDatesSummary reminders={data.reminders} /> : null}

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
