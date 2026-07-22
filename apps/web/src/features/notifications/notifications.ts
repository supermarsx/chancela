import {
  dashboardAlertSourceLabel,
  dashboardReminderRuleLabel,
  ledgerEventKindLabel,
} from '../../api/labels';
import type {
  Dashboard,
  DashboardAlert,
  DashboardReminder,
  LedgerEventView,
  NotificationSnapshot,
} from '../../api/types';
import { normalizeLegacyRoute } from '../../app/legacySlugs';
import type { MessageKey, TFunction, TParams } from '../../i18n';
import { actConveningGuidanceRoute } from '../acts/anchors';

export type NotificationKind = 'alert' | 'reminder' | 'operation';
export type NotificationTone = 'neutral' | 'accent' | 'warn' | 'error';

export interface NotificationAction {
  href: string;
  label: string;
}

export interface NotificationItem {
  id: string;
  kind: NotificationKind;
  priority: number;
  sortTime: number | null;
  tone: NotificationTone;
  badge: string;
  title: string;
  detail: string;
  meta: string[];
  action?: NotificationAction;
  timestamp?: string;
  seq?: number;
}

interface AlertCopy {
  title: MessageKey;
  body: MessageKey;
  action?: MessageKey;
}

interface ReminderCopy {
  title: MessageKey;
  body: MessageKey;
  action: MessageKey;
}

const SETTINGS_ROUTE = '/settings';
const CONVENING_NOTICE_MISSING_MEETING_DATE_BODY: MessageKey =
  'notifications.reminder.act.conveningNotice.missingMeetingDate.body';

const ALERT_COPY: Record<string, AlertCopy> = {
  'ledger.integrity.review_required': {
    title: 'notifications.alert.ledger.integrity.title',
    body: 'notifications.alert.ledger.integrity.body',
    action: 'notifications.alert.ledger.integrity.action',
  },
  'act.compliance.review_required': {
    title: 'notifications.alert.act.compliance.title',
    body: 'notifications.alert.act.compliance.body',
    action: 'notifications.alert.act.compliance.action',
  },
  'registry.provenance.expired': {
    title: 'notifications.alert.registry.expired.title',
    body: 'notifications.alert.registry.expired.body',
    action: 'notifications.alert.registry.expired.action',
  },
  'registry.provenance.expiring_soon': {
    title: 'notifications.alert.registry.expiringSoon.title',
    body: 'notifications.alert.registry.expiringSoon.body',
    action: 'notifications.alert.registry.expiringSoon.action',
  },
  'entity.book.no_open_book': {
    title: 'notifications.alert.entity.noOpenBook.title',
    body: 'notifications.alert.entity.noOpenBook.body',
    action: 'notifications.alert.entity.noOpenBook.action',
  },
  'entity.manager_remuneration.setup_recommended': {
    title: 'notifications.alert.entity.managerRemuneration.title',
    body: 'notifications.alert.entity.managerRemuneration.body',
    action: 'notifications.alert.entity.managerRemuneration.action',
  },
  'book.termo_abertura.missing_metadata': {
    title: 'notifications.alert.book.missingTermo.title',
    body: 'notifications.alert.book.missingTermo.body',
    action: 'notifications.alert.book.missingTermo.action',
  },
  'book.acts.none_recorded': {
    title: 'notifications.alert.book.noActs.title',
    body: 'notifications.alert.book.noActs.body',
    action: 'notifications.alert.book.noActs.action',
  },
  'act.lifecycle.advance_available': {
    title: 'notifications.alert.act.advanceAvailable.title',
    body: 'notifications.alert.act.advanceAvailable.body',
    action: 'notifications.alert.act.advanceAvailable.action',
  },
  'act.lifecycle.signing_ready': {
    title: 'notifications.alert.act.signingReady.title',
    body: 'notifications.alert.act.signingReady.body',
    action: 'notifications.alert.act.signingReady.action',
  },
  'backup.recovery.freshness_advisory': {
    title: 'notifications.alert.backupRecoveryFreshness.title',
    body: 'notifications.alert.backupRecoveryFreshness.body',
    action: 'notifications.alert.backupRecoveryFreshness.action',
  },
};

const REMINDER_COPY: Record<string, ReminderCopy> = {
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
  'act-attendance-missing': {
    title: 'notifications.reminder.act.attendance.title',
    body: 'notifications.reminder.act.attendance.body',
    action: 'notifications.reminder.act.attendance.action',
  },
  'act-convening-notice': {
    title: 'notifications.reminder.act.conveningNotice.title',
    body: 'notifications.reminder.act.conveningNotice.body',
    action: 'notifications.reminder.act.conveningNotice.action',
  },
  'imported-document-review-required': {
    title: 'notifications.reminder.importedDocumentReview.title',
    body: 'notifications.reminder.importedDocumentReview.body',
    action: 'notifications.reminder.importedDocumentReview.action',
  },
};

function reminderHasMissingMeetingDate(reminder: DashboardReminder, sourceRule: string): boolean {
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

function reminderCopyFor(
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

function parseDate(value: string): number | null {
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

export function parseNotificationTimestamp(value?: string): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isNaN(time) ? null : time;
}

const parseTimestamp = parseNotificationTimestamp;

function reminderTone(reminder: DashboardReminder): NotificationTone {
  if (reminder.status === 'Overdue') return 'warn';
  if (reminder.status === 'DueSoon') return 'accent';
  return 'neutral';
}

function reminderStatusLabel(status: DashboardReminder['status'], t: TFunction): string {
  if (status === 'Pending') return t('dashboard.workQueue.status.pending');
  if (status === 'Overdue') return t('dashboard.workQueue.status.overdue');
  if (status === 'DueSoon') return t('dashboard.workQueue.status.dueSoon');
  return t('dashboard.workQueue.status.upcoming');
}

function reminderDateLabel(dueDate: string, t: TFunction): string {
  const trimmed = dueDate.trim();
  if (!trimmed) return t('dashboard.workQueue.date.missing');
  return parseDate(trimmed) === null ? t('dashboard.workQueue.date.invalid') : trimmed;
}

function reminderDateMeta(dueDate: string, t: TFunction): string {
  const label = reminderDateLabel(dueDate, t);
  const missing = t('dashboard.workQueue.date.missing');
  const invalid = t('dashboard.workQueue.date.invalid');
  if (label === missing || label === invalid) return label;
  return t('dashboard.workQueue.date.value', { date: label });
}

/**
 * The "Fonte" line for a reminder. Named generators read as copy; an unnamed one keeps the raw
 * `rule / profile` pair the server sent, so it still identifies itself rather than going blank.
 */
function reminderSourceMeta(reminder: DashboardReminder, t: TFunction): string {
  const label = dashboardReminderRuleLabel(
    reminder.source_rule,
    reminder.profile_calendar_plan?.preset_label,
  );
  if (label) return t('notifications.alert.source', { source: label });
  return t('dashboard.workQueue.source', {
    rule: reminder.source_rule.trim() || t('dashboard.workQueue.rule.missing'),
    profile: reminder.source_profile.trim() || t('dashboard.workQueue.profile.missing'),
  });
}

function reminderPriority(status: DashboardReminder['status']): number {
  if (status === 'Overdue') return 1;
  if (status === 'Pending') return 3;
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

function alertPriorityAndTone(alert: DashboardAlert): { priority: number; tone: NotificationTone } {
  if (alert.code === 'ledger.integrity.review_required') return { priority: 0, tone: 'error' };
  if (alert.label === 'ReviewRequired') return { priority: 2, tone: 'warn' };
  return { priority: 3, tone: 'accent' };
}

export function frontendNotificationRouteFromApi(
  path: string | null | undefined,
): string | undefined {
  if (!path) return undefined;
  // The server still emits the Portuguese addresses (`/configuracoes?sec=dados`), and these
  // arrive as DATA rather than as navigations, so the router's redirect never sees them.
  // Normalising here means the rendered link is the real address, not one that bounces.
  const route = normalizeLegacyRoute(path.trim());
  if (!route) return undefined;
  if (route.startsWith('/entities/') || route === '/entities') return route;
  if (route.startsWith('/books/') || route === '/books') return route;
  if (route.startsWith('/acts/') || route === '/acts') return route;
  if (route.startsWith('/archive') || route.startsWith('/settings')) return route;

  const entity = /^\/v1\/entities\/([^/?#]+)/.exec(route);
  if (entity) return `/entities/${entity[1]}`;
  const book = /^\/v1\/books\/([^/?#]+)/.exec(route);
  if (book) return `/books/${book[1]}`;
  const act = /^\/v1\/acts\/([^/?#]+)/.exec(route);
  if (act) return `/acts/${act[1]}`;
  if (route.startsWith('/v1/ledger')) return '/archive';
  if (route.startsWith('/v1/settings')) return '/settings';
  return undefined;
}

const frontendRouteFromApi = frontendNotificationRouteFromApi;

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

function paramText(params: TParams | undefined, key: string): string | undefined {
  const value = params?.[key];
  const text = value == null ? undefined : String(value).trim();
  return text || undefined;
}

function generatedDispatchEvidenceRoute(
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

function importedDocumentReviewRoute(
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

function isConveningNoticeReminder(reminder: DashboardReminder): boolean {
  return (
    reminder.action?.kind === 'open_act_convening_notice' ||
    reminder.source_rule.trim() === 'act-convening-notice'
  );
}

function routeFromTargetId(prefix: string, id: string | null | undefined): string | undefined {
  const trimmed = id?.trim();
  return trimmed ? `${prefix}/${trimmed}` : undefined;
}

function routeAction(
  href: string,
  label: MessageKey,
  t: TFunction,
  params?: TParams,
): NotificationAction {
  return { href, label: t(label, params) };
}

function messageKey(value: string | null | undefined): MessageKey | undefined {
  return value?.trim() ? (value.trim() as MessageKey) : undefined;
}

function actionFromMetadata(
  action: DashboardAlert['action'] | DashboardReminder['action'] | null | undefined,
  t: TFunction,
  params?: TParams,
): NotificationAction | undefined {
  if (!action) return undefined;
  const href =
    action.kind === 'open_act_convening_notice'
      ? actConveningGuidanceRoute(
          frontendRouteFromApi(action.route) ??
            frontendRouteFromApi(action.api_href) ??
            (paramText(params, 'act_id') ? `/acts/${paramText(params, 'act_id')}` : undefined),
        )
      : action.kind === 'open_imported_document_review'
        ? importedDocumentReviewRoute(
            frontendRouteFromApi(action.route) ??
              (paramText(params, 'act_id') ? `/acts/${paramText(params, 'act_id')}` : undefined),
            paramText(params, 'imported_document_id') ?? importedDocumentIdFromApi(action.api_href),
          )
        : action.kind === 'open_absent_owner_dispatch_evidence' ||
            action.kind === 'open_generated_convening_dispatch_evidence'
          ? generatedDispatchEvidenceRoute(
              frontendRouteFromApi(action.route) ??
                (paramText(params, 'act_id') ? `/acts/${paramText(params, 'act_id')}` : undefined),
              paramText(params, 'generated_document_id') ??
                paramText(params, 'document_id') ??
                generatedDispatchDocumentIdFromApi(action.api_href),
            )
          : (frontendRouteFromApi(action.route) ?? frontendRouteFromApi(action.api_href));
  const labelKey = messageKey(action.label_key);
  if (!href || !labelKey) return undefined;
  return { href, label: t(labelKey, params) };
}

function actionFromTarget(
  alert: DashboardAlert,
  t: TFunction,
  preferredLabel?: MessageKey,
  params?: TParams,
): NotificationAction | undefined {
  const links = alert.target.links;
  const ordered = [
    {
      href: frontendRouteFromApi(links.act) ?? routeFromTargetId('/acts', alert.target.act_id),
      label: preferredLabel ?? 'notifications.action.openAct',
    },
    {
      href: frontendRouteFromApi(links.book) ?? routeFromTargetId('/books', alert.target.book_id),
      label: preferredLabel ?? 'notifications.action.openBook',
    },
    {
      href:
        frontendRouteFromApi(links.entity) ??
        routeFromTargetId('/entities', alert.target.entity_id),
      label: preferredLabel ?? 'notifications.action.openEntity',
    },
    {
      href: frontendRouteFromApi(links.ledger),
      label: preferredLabel ?? 'notifications.action.openLedger',
    },
  ];
  const hit = ordered.find((item) => item.href);
  return hit?.href ? { href: hit.href, label: t(hit.label, params) } : undefined;
}

function fallbackAlertAction(
  alert: DashboardAlert,
  t: TFunction,
  preferredLabel?: MessageKey,
  params?: TParams,
): NotificationAction {
  const code = alert.code.trim();
  if (code === 'ledger.integrity.review_required') {
    return routeAction('/archive', preferredLabel ?? 'notifications.action.openLedger', t, params);
  }
  if (alert.target.act_id?.trim()) {
    return routeAction(
      `/acts/${alert.target.act_id.trim()}`,
      preferredLabel ?? 'notifications.action.openAct',
      t,
      params,
    );
  }
  if (alert.target.book_id?.trim()) {
    return routeAction(
      `/books/${alert.target.book_id.trim()}`,
      preferredLabel ?? 'notifications.action.openBook',
      t,
      params,
    );
  }
  if (alert.target.entity_id?.trim()) {
    return routeAction(
      `/entities/${alert.target.entity_id.trim()}`,
      preferredLabel ?? 'notifications.action.openEntity',
      t,
      params,
    );
  }
  return routeAction(SETTINGS_ROUTE, 'notifications.action.openSettings', t, params);
}

function alertAction(
  alert: DashboardAlert,
  t: TFunction,
  preferredLabel?: MessageKey,
  params?: TParams,
): NotificationAction {
  return (
    actionFromMetadata(alert.action, t, params) ??
    actionFromTarget(alert, t, preferredLabel, params) ??
    fallbackAlertAction(alert, t, preferredLabel, params)
  );
}

function paramId(
  params: Record<string, string> | undefined,
  key: 'act_id' | 'book_id' | 'entity_id',
): string | undefined {
  const value = params?.[key]?.trim();
  return value || undefined;
}

function actionFromReminderTarget(
  reminder: DashboardReminder,
  t: TFunction,
  preferredLabel?: MessageKey,
  params?: TParams,
): NotificationAction | undefined {
  const actId = paramId(reminder.params, 'act_id');
  if (actId) {
    const href = isConveningNoticeReminder(reminder)
      ? (actConveningGuidanceRoute(`/acts/${actId}`) ?? `/acts/${actId}`)
      : `/acts/${actId}`;
    return routeAction(href, preferredLabel ?? 'notifications.action.openAct', t, params);
  }

  const bookId = paramId(reminder.params, 'book_id');
  if (bookId) {
    return routeAction(
      `/books/${bookId}`,
      preferredLabel ?? 'notifications.action.openBook',
      t,
      params,
    );
  }

  const entityId = reminder.entity_id.trim() || paramId(reminder.params, 'entity_id');
  if (entityId) {
    return routeAction(
      `/entities/${entityId}`,
      preferredLabel ?? 'notifications.action.openEntity',
      t,
      params,
    );
  }

  return undefined;
}

function alertId(alert: DashboardAlert, index: number): string {
  return [
    'alert',
    alert.code.trim() || 'unknown',
    alert.target.entity_id?.trim() || '-',
    alert.target.book_id?.trim() || '-',
    alert.target.act_id?.trim() || '-',
    index,
  ].join(':');
}

function buildAlertNotification(
  alert: DashboardAlert,
  index: number,
  t: TFunction,
): NotificationItem {
  const { priority, tone } = alertPriorityAndTone(alert);
  const source = alert.source?.trim();
  const code = alert.code.trim() || 'unknown';
  const copy = ALERT_COPY[code];
  const i18nTitle = messageKey(alert.i18n?.title_key);
  const i18nBody = messageKey(alert.i18n?.body_key);
  const i18nAction = messageKey(alert.i18n?.action_key);
  const params: TParams = { ...alert.params, code };
  const unknownParams: TParams = {
    ...params,
    message: alert.message.trim() || t('notifications.alert.fallbackDetail'),
  };
  return {
    id: alertId(alert, index),
    kind: 'alert',
    priority,
    sortTime: null,
    tone,
    badge: t('notifications.badge.alert'),
    title: i18nTitle
      ? t(i18nTitle, params)
      : copy
        ? t(copy.title, params)
        : t('notifications.alert.unknown.title', unknownParams),
    detail: i18nBody
      ? t(i18nBody, params)
      : copy
        ? t(copy.body, params)
        : t('notifications.alert.unknown.body', unknownParams),
    meta: source
      ? [t('notifications.alert.source', { source: dashboardAlertSourceLabel(source) })]
      : [],
    action: alertAction(alert, t, i18nAction ?? copy?.action, params),
  };
}

export function compareEventsByRecency(a: LedgerEventView, b: LedgerEventView): number {
  const aTime = parseNotificationTimestamp(a.timestamp);
  const bTime = parseNotificationTimestamp(b.timestamp);
  if (aTime !== null && bTime !== null && aTime !== bTime) return bTime - aTime;
  if (aTime !== null || bTime !== null) return aTime === null ? 1 : -1;
  return b.seq - a.seq;
}

function buildEventNotification(event: LedgerEventView, t: TFunction): NotificationItem {
  return {
    id: `event:${event.id}`,
    kind: 'operation',
    priority: 8,
    sortTime: parseTimestamp(event.timestamp),
    tone: 'neutral',
    badge: t('notifications.badge.operation'),
    title: t('notifications.operation.title', { kind: ledgerEventKindLabel(event.kind) }),
    detail: t('notifications.operation.detail', { actor: event.actor, scope: event.scope }),
    meta: [t('notifications.operation.meta', { seq: event.seq })],
    action: { href: '/archive', label: t('notifications.action.openLedger') },
    timestamp: event.timestamp,
    seq: event.seq,
  };
}

export function compareNotifications(a: NotificationItem, b: NotificationItem): number {
  if (a.priority !== b.priority) return a.priority - b.priority;

  const descTime = a.kind === 'operation' || b.kind === 'operation';
  if (a.sortTime !== null && b.sortTime !== null && a.sortTime !== b.sortTime) {
    return descTime ? b.sortTime - a.sortTime : a.sortTime - b.sortTime;
  }
  if (a.sortTime !== null || b.sortTime !== null) return a.sortTime === null ? 1 : -1;

  if (a.seq !== undefined && b.seq !== undefined && a.seq !== b.seq) return b.seq - a.seq;
  const byTitle = a.title.localeCompare(b.title, 'pt');
  return byTitle || a.id.localeCompare(b.id);
}

export function buildDashboardNotifications(
  dashboard: Dashboard,
  t: TFunction,
): NotificationItem[] {
  const items: NotificationItem[] = [];

  for (const [index, alert] of (dashboard.alerts ?? []).entries()) {
    items.push(buildAlertNotification(alert, index, t));
  }

  if (
    !dashboard.ledger_valid &&
    !items.some((item) => item.id.startsWith('alert:ledger.integrity.review_required:'))
  ) {
    items.push({
      id: 'integrity',
      kind: 'alert',
      priority: 0,
      sortTime: null,
      tone: 'error',
      badge: t('dashboard.workQueue.integrity.badge'),
      title: t('dashboard.workQueue.integrity.title'),
      detail: t('dashboard.workQueue.integrity.detail'),
      meta: [t('dashboard.workQueue.integrity.meta')],
      action: { href: '/archive', label: t('notifications.action.openLedger') },
    });
  }

  for (const reminder of dedupeReminders(dashboard.reminders ?? [])) {
    const dueDate = reminder.due_date.trim();
    const entityName = reminder.entity_name.trim() || t('dashboard.workQueue.entity.unnamed');
    const entityId = reminder.entity_id.trim();
    const sourceRule = reminder.source_rule.trim() || t('dashboard.workQueue.rule.missing');
    const sourceProfile =
      reminder.source_profile.trim() || t('dashboard.workQueue.profile.missing');
    const reason = reminder.reason.trim() || t('dashboard.workQueue.reminder.fallback');
    const copy = reminderCopyFor(reminder, sourceRule);
    const i18nTitle = messageKey(reminder.i18n?.title_key);
    const i18nBody = messageKey(reminder.i18n?.body_key);
    const i18nAction = messageKey(reminder.i18n?.action_key);
    const params: TParams = {
      ...(reminder.params ?? {}),
      entity_name: entityName,
      due_date: reminderDateLabel(reminder.due_date, t),
      source_rule: sourceRule,
      source_profile: sourceProfile,
      reason,
    };

    items.push({
      id: `reminder:${entityId}:${sourceRule}:${sourceProfile}:${dueDate}:${reminder.status}`,
      kind: 'reminder',
      priority: reminderPriority(reminder.status),
      sortTime: dueDate ? parseDate(dueDate) : null,
      tone: reminderTone(reminder),
      badge: reminderStatusLabel(reminder.status, t),
      title: i18nTitle
        ? t(i18nTitle, params)
        : copy
          ? t(copy.title, params)
          : t('notifications.reminder.unknown.title', params),
      detail: i18nBody
        ? t(i18nBody, params)
        : copy
          ? t(copy.body, params)
          : t('notifications.reminder.unknown.body', params),
      meta: [reminderDateMeta(reminder.due_date, t), reminderSourceMeta(reminder, t)],
      action: actionFromMetadata(reminder.action, t, params) ??
        actionFromReminderTarget(reminder, t, i18nAction ?? copy?.action, params) ?? {
          href: SETTINGS_ROUTE,
          label: t('notifications.action.openSettings'),
        },
    });
  }

  if (dashboard.unresolved_compliance > 0) {
    items.push({
      id: 'compliance',
      kind: 'alert',
      priority: 2,
      sortTime: null,
      tone: 'warn',
      badge: t('dashboard.workQueue.compliance.badge'),
      title:
        dashboard.unresolved_compliance === 1
          ? t('dashboard.workQueue.compliance.title.one', {
              count: dashboard.unresolved_compliance,
            })
          : t('dashboard.workQueue.compliance.title.other', {
              count: dashboard.unresolved_compliance,
            }),
      detail: t('dashboard.workQueue.compliance.detail'),
      meta: [t('dashboard.workQueue.compliance.meta')],
      action: { href: SETTINGS_ROUTE, label: t('notifications.action.openSettings') },
    });
  }

  for (const event of (dashboard.recent_events ?? []).slice().sort(compareEventsByRecency)) {
    items.push(buildEventNotification(event, t));
  }

  return items.sort(compareNotifications);
}

export function isActionableNotification(item: NotificationItem): boolean {
  return item.kind !== 'operation';
}

export function popupNotifications<T extends NotificationItem>(items: T[], limit: number): T[] {
  const actionable = items.filter(isActionableNotification);
  return (actionable.length > 0 ? actionable : items).slice(0, limit);
}

// — Dismissal snapshots (t17) ————————————————————————————————————————————————
// A dismissed notification's content is reconstructed from the live dashboard only while the
// condition that generated it persists. To make the Dismissed tab and the 120-day retention clock
// meaningful, the client freezes a small display snapshot on dismiss and sends it in the PATCH body;
// the server stores it opaquely and echoes it back. These helpers author the snapshot within the
// server's byte caps (so a valid dismiss never trips the 422 length/control-char guard) and rebuild
// a display item from a stored snapshot.

// Byte caps mirror the server's `NotificationSnapshot` validation (notifications.rs).
const SNAPSHOT_KIND_MAX_BYTES = 64;
const SNAPSHOT_TONE_MAX_BYTES = 64;
const SNAPSHOT_BADGE_MAX_BYTES = 128;
const SNAPSHOT_TITLE_MAX_BYTES = 256;
const SNAPSHOT_DETAIL_MAX_BYTES = 1024;
const SNAPSHOT_TIMESTAMP_MAX_BYTES = 64;
const SNAPSHOT_LABEL_MAX_BYTES = 128;
const SNAPSHOT_HREF_MAX_BYTES = 512;

const SNAPSHOT_ENCODER = new TextEncoder();

function truncateToBytes(value: string, maxBytes: number): string {
  if (SNAPSHOT_ENCODER.encode(value).length <= maxBytes) return value;
  let result = '';
  // Iterate by code point (spread) so a multi-byte character is never split across the cap.
  for (const ch of value) {
    if (SNAPSHOT_ENCODER.encode(result + ch).length > maxBytes) break;
    result += ch;
  }
  return result;
}

// Fold C0 controls + DEL to a space. The server rejects any of these, so folding them keeps a valid
// value (a title with a stray newline still archives, just flattened) instead of tripping the 422.
// Done as a code-point scan rather than a regex so it needs no `no-control-regex` exception.
function stripControlChars(value: string): string {
  let result = '';
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    result += code < 0x20 || code === 0x7f ? ' ' : ch;
  }
  return result;
}

function sanitizeSnapshotText(value: string, maxBytes: number): string {
  return truncateToBytes(stripControlChars(value), maxBytes);
}

export function notificationSnapshotFromItem(item: NotificationItem): NotificationSnapshot {
  const snapshot: NotificationSnapshot = {
    kind: sanitizeSnapshotText(item.kind, SNAPSHOT_KIND_MAX_BYTES),
    tone: sanitizeSnapshotText(item.tone, SNAPSHOT_TONE_MAX_BYTES),
    badge: sanitizeSnapshotText(item.badge, SNAPSHOT_BADGE_MAX_BYTES),
    title: sanitizeSnapshotText(item.title, SNAPSHOT_TITLE_MAX_BYTES),
    detail: sanitizeSnapshotText(item.detail, SNAPSHOT_DETAIL_MAX_BYTES),
  };
  if (item.timestamp) {
    snapshot.timestamp = sanitizeSnapshotText(item.timestamp, SNAPSHOT_TIMESTAMP_MAX_BYTES);
  }
  if (item.action) {
    snapshot.action = {
      href: sanitizeSnapshotText(item.action.href, SNAPSHOT_HREF_MAX_BYTES),
      label: sanitizeSnapshotText(item.action.label, SNAPSHOT_LABEL_MAX_BYTES),
    };
  }
  return snapshot;
}

const NOTIFICATION_KINDS: readonly NotificationKind[] = ['alert', 'reminder', 'operation'];
const NOTIFICATION_TONES: readonly NotificationTone[] = ['neutral', 'accent', 'warn', 'error'];

function snapshotKind(value: string): NotificationKind {
  return (NOTIFICATION_KINDS as readonly string[]).includes(value)
    ? (value as NotificationKind)
    : 'operation';
}

function snapshotTone(value: string): NotificationTone {
  return (NOTIFICATION_TONES as readonly string[]).includes(value)
    ? (value as NotificationTone)
    : 'neutral';
}

/**
 * Rebuild a display item from a stored dismissal snapshot. Used for dismissed entries the dashboard
 * no longer generates; the fields the snapshot does not carry (priority, meta) take inert defaults —
 * the item is an archive row, not a live notification competing for sort position.
 */
export function notificationItemFromSnapshot(
  id: string,
  snapshot: NotificationSnapshot,
): NotificationItem {
  return {
    id,
    kind: snapshotKind(snapshot.kind),
    priority: 5,
    sortTime: parseNotificationTimestamp(snapshot.timestamp),
    tone: snapshotTone(snapshot.tone),
    badge: snapshot.badge,
    title: snapshot.title,
    detail: snapshot.detail,
    meta: [],
    action: snapshot.action
      ? { href: snapshot.action.href, label: snapshot.action.label }
      : undefined,
    timestamp: snapshot.timestamp,
  };
}

// — Entities-style free-text filter (t17) ————————————————————————————————————
// Mirrors the entities list search: NFD-fold + strip diacritics + lowercase, then substring-match a
// flattened haystack of the row's visible text. Pure so it can be unit-tested like the entities one.

export function normalizeNotificationSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase();
}

export function notificationSearchText(item: NotificationItem): string {
  return normalizeNotificationSearch([item.title, item.detail, item.badge, ...item.meta].join(' '));
}

export function notificationMatchesQuery(item: NotificationItem, query: string): boolean {
  const normalized = normalizeNotificationSearch(query.trim());
  if (!normalized) return true;
  return notificationSearchText(item).includes(normalized);
}

export type NotificationToneFilter = 'all' | NotificationTone;

export function notificationMatchesTone(
  item: NotificationItem,
  tone: NotificationToneFilter,
): boolean {
  return tone === 'all' || item.tone === tone;
}
