import type {
  Dashboard,
  DashboardAlert,
  DashboardReminder,
  LedgerEventView,
} from '../../api/types';
import type { MessageKey, TFunction, TParams } from '../../i18n';

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

const SETTINGS_ROUTE = '/configuracoes';

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
  'act-attendance-missing': {
    title: 'notifications.reminder.act.attendance.title',
    body: 'notifications.reminder.act.attendance.body',
    action: 'notifications.reminder.act.attendance.action',
  },
  'imported-document-review-required': {
    title: 'notifications.reminder.importedDocumentReview.title',
    body: 'notifications.reminder.importedDocumentReview.body',
    action: 'notifications.reminder.importedDocumentReview.action',
  },
};

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

function parseTimestamp(value?: string): number | null {
  if (!value) return null;
  const time = Date.parse(value);
  return Number.isNaN(time) ? null : time;
}

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
  if (route.startsWith('/v1/settings')) return '/configuracoes';
  return undefined;
}

function generatedDispatchDocumentIdFromApi(path: string | null | undefined): string | undefined {
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

function importedDocumentIdFromApi(path: string | null | undefined): string | undefined {
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
    action.kind === 'open_imported_document_review'
      ? importedDocumentReviewRoute(
          frontendRouteFromApi(action.route) ??
            (paramText(params, 'act_id') ? `/atas/${paramText(params, 'act_id')}` : undefined),
          paramText(params, 'imported_document_id') ?? importedDocumentIdFromApi(action.api_href),
        )
      : action.kind === 'open_absent_owner_dispatch_evidence'
        ? generatedDispatchEvidenceRoute(
            frontendRouteFromApi(action.route) ??
              (paramText(params, 'act_id') ? `/atas/${paramText(params, 'act_id')}` : undefined),
            paramText(params, 'document_id') ?? generatedDispatchDocumentIdFromApi(action.api_href),
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
      href: frontendRouteFromApi(links.act) ?? routeFromTargetId('/atas', alert.target.act_id),
      label: preferredLabel ?? 'notifications.action.openAct',
    },
    {
      href: frontendRouteFromApi(links.book) ?? routeFromTargetId('/livros', alert.target.book_id),
      label: preferredLabel ?? 'notifications.action.openBook',
    },
    {
      href:
        frontendRouteFromApi(links.entity) ??
        routeFromTargetId('/entidades', alert.target.entity_id),
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
    return routeAction('/arquivo', preferredLabel ?? 'notifications.action.openLedger', t, params);
  }
  if (alert.target.act_id?.trim()) {
    return routeAction(
      `/atas/${alert.target.act_id.trim()}`,
      preferredLabel ?? 'notifications.action.openAct',
      t,
      params,
    );
  }
  if (alert.target.book_id?.trim()) {
    return routeAction(
      `/livros/${alert.target.book_id.trim()}`,
      preferredLabel ?? 'notifications.action.openBook',
      t,
      params,
    );
  }
  if (alert.target.entity_id?.trim()) {
    return routeAction(
      `/entidades/${alert.target.entity_id.trim()}`,
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
    return routeAction(
      `/atas/${actId}`,
      preferredLabel ?? 'notifications.action.openAct',
      t,
      params,
    );
  }

  const bookId = paramId(reminder.params, 'book_id');
  if (bookId) {
    return routeAction(
      `/livros/${bookId}`,
      preferredLabel ?? 'notifications.action.openBook',
      t,
      params,
    );
  }

  const entityId = reminder.entity_id.trim() || paramId(reminder.params, 'entity_id');
  if (entityId) {
    return routeAction(
      `/entidades/${entityId}`,
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
    meta: source ? [t('notifications.alert.source', { source })] : [],
    action: alertAction(alert, t, i18nAction ?? copy?.action, params),
  };
}

function compareEventsByRecency(a: LedgerEventView, b: LedgerEventView): number {
  const aTime = parseTimestamp(a.timestamp);
  const bTime = parseTimestamp(b.timestamp);
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
    title: t('notifications.operation.title', { kind: event.kind }),
    detail: t('notifications.operation.detail', { actor: event.actor, scope: event.scope }),
    meta: [t('notifications.operation.meta', { seq: event.seq })],
    action: { href: '/arquivo', label: t('notifications.action.openLedger') },
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
      action: { href: '/arquivo', label: t('notifications.action.openLedger') },
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
    const copy = REMINDER_COPY[sourceRule];
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
      meta: [
        reminderDateMeta(reminder.due_date, t),
        t('dashboard.workQueue.source', { rule: sourceRule, profile: sourceProfile }),
      ],
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
