import { describe, expect, it } from 'vitest';
import type {
  DashboardAlert,
  DashboardLawReference,
  DashboardOpenBook,
  DashboardReminder,
  LedgerEventView,
} from '../../api/types';
import type { TFunction } from '../../i18n';
import {
  buildDashboardWorkQueue,
  compactDashboardScope,
  dashboardScopeLabel,
  dashboardScopeNames,
  compareByRecency,
  compareDashboardQueueItems,
  dashboardActivityKind,
  dashboardActivityLabel,
  dashboardActivityTone,
  dashboardAlertPriority,
  dashboardAlertTone,
  dashboardAlertWorkQueueItem,
  dashboardFrontendRouteFromApi,
  dashboardMessageKey,
  dashboardReminderActRoute,
  dashboardReminderCopyFor,
  dashboardReminderDateLabel,
  dashboardReminderDateMeta,
  dashboardReminderPriority,
  dashboardReminderStatusLabel,
  dashboardReminderTone,
  dashboardTabFromParam,
  dedupeDashboardReminders,
  firstChainId,
  generatedDispatchDocumentIdFromApi,
  generatedDispatchEvidenceRoute,
  idFromScopedValue,
  importedDocumentIdFromApi,
  importedDocumentReviewRoute,
  isConveningNoticeReminder,
  lawRefMeta,
  lawRefSourcePending,
  parseDashboardReminderDate,
  profileCalendarPlanMeta,
  recentActivityItems,
  reminderHasMissingMeetingDate,
  routeFromDashboardActivity,
  routeFromDashboardAlert,
  routeFromDashboardReminder,
  shortDashboardId,
  sortedDashboardOpenBooks,
  type WorkQueueItem,
} from './DashboardPage';

const t = ((key: string) => key) as TFunction;

function event(overrides: Partial<LedgerEventView> = {}): LedgerEventView {
  return {
    id: 'EV1',
    seq: 1,
    actor: 'operator',
    justification: null,
    timestamp: '2026-07-16T10:00:00Z',
    scope: 'global',
    kind: 'system.event',
    payload_digest: 'a'.repeat(64),
    prev_hash: 'b'.repeat(64),
    hash: 'c'.repeat(64),
    chains: ['global'],
    attestation: null,
    ...overrides,
  };
}

function reminder(overrides: Partial<DashboardReminder> = {}): DashboardReminder {
  return {
    due_date: '2026-07-20',
    severity: 'Advisory',
    status: 'Upcoming',
    reason: 'Annual meeting',
    entity_id: 'E1',
    entity_name: 'Entidade Um',
    source_rule: 'csc-art376-annual',
    source_profile: 'commercial',
    ...overrides,
  };
}

function alert(overrides: Partial<DashboardAlert> = {}): DashboardAlert {
  return {
    code: 'entity.book.no_open_book',
    label: 'Advisory',
    severity: 'Info',
    category: 'entity',
    message: 'Create a book',
    params: {},
    target: {
      entity_id: 'E1',
      book_id: null,
      act_id: null,
      links: { entity: '/v1/entities/E1', book: null, act: null, ledger: null },
    },
    source: 'dashboard',
    ...overrides,
  };
}

describe('Dashboard pure routing, ordering, and queue logic', () => {
  it('normalizes tabs, timestamps, ids, and scoped values defensively', () => {
    expect(
      ['stats', 'activity', 'current', 'dates', 'queue', 'events'].map(dashboardTabFromParam),
    ).toEqual(['stats', 'activity', 'current', 'dates', 'queue', 'events']);
    expect(dashboardTabFromParam('unknown')).toBe('current');
    expect(dashboardTabFromParam(null)).toBe('current');
    // Timestamp rendering moved to the shared `format.ts` family (t66); the old local helper
    // echoed an unparseable value back to the page, which is precisely what it now refuses to do.
    expect(shortDashboardId('1234567890')).toBe('12345678');
    expect(idFromScopedValue('book:B1', 'book')).toBe('B1');
    expect(idFromScopedValue('book:   ', 'book')).toBeUndefined();
    expect(idFromScopedValue('act:A1', 'book')).toBeUndefined();
    expect(compactDashboardScope('application')).toBe('application');
    expect(compactDashboardScope('a-very-long-unscoped-identifier')).toBe('a-very-l...');
    expect(compactDashboardScope('book:1234567890')).toBe('book:12345678');
  });

  it('names event scopes from the dashboard payload and keeps the compact id otherwise', () => {
    const data = {
      current_work: {
        open_books: [
          { book_id: 'book-1234567890', entity_name: 'Encosto Estratégico Lda' },
          { book_id: 'book-unnamed', entity_name: '  ' },
        ] as unknown as DashboardOpenBook[],
        act_counts_by_state: {},
      },
      reminders: [reminder({ entity_id: 'entity-42', entity_name: 'Amélia Marques Unipessoal' })],
    } as unknown as Parameters<typeof dashboardScopeNames>[0];

    const names = dashboardScopeNames(data);
    expect(names.get('book-1234567890')).toBe('Encosto Estratégico Lda');
    expect(names.has('book-unnamed')).toBe(false);

    // A named scope reads as the entity; everything else keeps the truncated identifier.
    expect(dashboardScopeLabel('book:book-1234567890', names)).toBe('Encosto Estratégico Lda');
    expect(dashboardScopeLabel('entity-42', names)).toBe('Amélia Marques Unipessoal');
    expect(dashboardScopeLabel('book:book-unnamed', names)).toBe('book:book-unn');
    expect(dashboardScopeLabel('application', names)).toBe('application');
    // No extra request is implied: an id the payload never named still renders.
    expect(dashboardScopeLabel('act:6c6f17eb-0000-0000-0000-000000000000', names)).toBe(
      'act:6c6f17eb',
    );
  });

  it('orders valid and invalid event timestamps and infers every activity route', () => {
    const validNew = event({ seq: 1, timestamp: '2026-07-17T00:00:00Z' });
    const validOld = event({ seq: 9, timestamp: '2026-07-16T00:00:00Z' });
    const invalidHigh = event({ seq: 20, timestamp: 'bad' });
    const invalidLow = event({ seq: 10, timestamp: 'also-bad' });
    expect(compareByRecency(validNew, validOld)).toBeLessThan(0);
    expect(compareByRecency(validNew, invalidHigh)).toBeLessThan(0);
    expect(compareByRecency(invalidHigh, validNew)).toBeGreaterThan(0);
    expect(compareByRecency(invalidHigh, invalidLow)).toBeLessThan(0);

    const actEvent = event({ kind: 'act.updated', scope: 'act:A1' });
    const bookEvent = event({ kind: 'other', scope: 'global', chains: ['book:B1'] });
    const entityEvent = event({ kind: 'entity.updated', scope: 'entity:E1' });
    const plainEntity = event({ kind: 'entity.updated', scope: 'E2' });
    expect(dashboardActivityKind(actEvent)).toBe('act');
    expect(dashboardActivityKind(bookEvent)).toBe('book');
    expect(dashboardActivityKind(entityEvent)).toBe('entity');
    expect(dashboardActivityKind(event())).toBeNull();
    expect(routeFromDashboardActivity(actEvent, 'act')).toBe('/acts/A1');
    expect(routeFromDashboardActivity(event({ scope: 'global' }), 'act')).toBeUndefined();
    expect(routeFromDashboardActivity(bookEvent, 'book')).toBe('/books/B1');
    expect(routeFromDashboardActivity(entityEvent, 'entity')).toBe('/entities/E1');
    expect(routeFromDashboardActivity(plainEntity, 'entity')).toBe('/entities/E2');
    expect(routeFromDashboardActivity(event(), 'entity')).toBeUndefined();
    expect(firstChainId(bookEvent, 'book')).toBe('B1');
    expect(firstChainId(event(), 'book')).toBeUndefined();
    expect((['act', 'book', 'entity'] as const).map(dashboardActivityTone)).toEqual([
      'accent',
      'neutral',
      'warn',
    ]);
    expect(
      ['act', 'book', 'entity'].map((kind) => dashboardActivityLabel(kind as never, t)),
    ).toEqual([
      'dashboard.activity.kind.act',
      'dashboard.activity.kind.book',
      'dashboard.activity.kind.entity',
    ]);
    expect(
      recentActivityItems([
        event(),
        ...Array.from({ length: 12 }, (_, i) =>
          event({
            id: `A${i}`,
            seq: i,
            kind: 'act.updated',
            scope: `act:A${i}`,
          }),
        ),
      ]),
    ).toHaveLength(10);
  });

  it('validates reminder dates, status presentation, deduplication, and calendar metadata', () => {
    expect(parseDashboardReminderDate('2026-02-29')).toBeNull();
    expect(parseDashboardReminderDate('2026-13-01')).toBeNull();
    expect(parseDashboardReminderDate('not-date')).toBeNull();
    expect(parseDashboardReminderDate(' 2026-07-20 ')).toBe(Date.UTC(2026, 6, 20));
    expect(dashboardReminderDateLabel(' ', t)).toBe('dashboard.workQueue.date.missing');
    expect(dashboardReminderDateLabel('bad', t)).toBe('dashboard.workQueue.date.invalid');
    expect(dashboardReminderDateLabel('2026-07-20', t)).toBe('2026-07-20');
    expect(dashboardReminderDateMeta('', t)).toBe('dashboard.workQueue.date.missing');
    expect(dashboardReminderDateMeta('bad', t)).toBe('dashboard.workQueue.date.invalid');
    expect(dashboardReminderDateMeta('2026-07-20', t)).toBe('dashboard.workQueue.date.value');

    const statuses: DashboardReminder['status'][] = ['Pending', 'Overdue', 'DueSoon', 'Upcoming'];
    expect(statuses.map((status) => dashboardReminderStatusLabel(status, t))).toEqual([
      'dashboard.workQueue.status.pending',
      'dashboard.workQueue.status.overdue',
      'dashboard.workQueue.status.dueSoon',
      'dashboard.workQueue.status.upcoming',
    ]);
    expect(statuses.map(dashboardReminderPriority)).toEqual([3, 1, 3, 4]);
    expect(statuses.map((status) => dashboardReminderTone(reminder({ status })))).toEqual([
      'neutral',
      'warn',
      'accent',
      'neutral',
    ]);
    expect(
      dedupeDashboardReminders([reminder(), reminder(), reminder({ status: 'Overdue' })]),
    ).toHaveLength(2);

    expect(profileCalendarPlanMeta(reminder(), t)).toBeNull();
    const plan = (support_status: string, review_status: string) =>
      reminder({ profile_calendar_plan: { support_status, review_status } as never });
    expect(profileCalendarPlanMeta(plan('supported', 'pending_source_review'), t)).toContain(
      'supportedPending',
    );
    expect(profileCalendarPlanMeta(plan('unsupported', 'pending_source_review'), t)).toContain(
      'unsupportedPending',
    );
    expect(profileCalendarPlanMeta(plan('unknown', 'pending_source_review'), t)).toContain(
      'pendingSourceReview',
    );
    expect(profileCalendarPlanMeta(plan('supported', 'reviewed'), t)).toContain(
      'supportedAdvisory',
    );
    expect(profileCalendarPlanMeta(plan('unsupported', 'reviewed'), t)).toContain(
      'unsupportedAdvisory',
    );
    expect(profileCalendarPlanMeta(plan('unknown', 'reviewed'), t)).toContain('unknownAdvisory');
  });

  it('maps API links and preserves malformed encoded resource ids without throwing', () => {
    expect(dashboardMessageKey('  dashboard.metric.entities ')).toBe('dashboard.metric.entities');
    expect(dashboardMessageKey('  ')).toBeUndefined();
    expect(dashboardMessageKey(undefined)).toBeUndefined();
    for (const route of [
      '/entities',
      '/books/B1',
      '/acts/A1',
      '/archive?q=x',
      '/settings',
    ]) {
      expect(dashboardFrontendRouteFromApi(route)).toBe(route);
    }
    expect(dashboardFrontendRouteFromApi('/v1/entities/E1?x=1')).toBe('/entities/E1');
    expect(dashboardFrontendRouteFromApi('/v1/books/B1')).toBe('/books/B1');
    expect(dashboardFrontendRouteFromApi('/v1/acts/A1')).toBe('/acts/A1');
    expect(dashboardFrontendRouteFromApi('/v1/ledger/events')).toBe('/archive');
    expect(dashboardFrontendRouteFromApi('/health')).toBeUndefined();
    expect(dashboardFrontendRouteFromApi(' ')).toBeUndefined();

    expect(
      generatedDispatchDocumentIdFromApi('/v1/documents/generated/doc%2Fone/dispatch-evidence'),
    ).toBe('doc/one');
    expect(
      generatedDispatchDocumentIdFromApi('/v1/documents/generated/%E0%A4/dispatch-evidence'),
    ).toBe('%E0%A4');
    expect(generatedDispatchDocumentIdFromApi('/v1/documents/generated/x')).toBeUndefined();
    expect(importedDocumentIdFromApi('/v1/documents/imported/doc%2Fone/review')).toBe('doc/one');
    expect(importedDocumentIdFromApi('/v1/documents/imported/%E0%A4')).toBe('%E0%A4');
    expect(importedDocumentIdFromApi('/other')).toBeUndefined();

    expect(generatedDispatchEvidenceRoute('/acts/A1?old=1', 'DOC1')).toContain(
      'focus=dispatch-evidence',
    );
    expect(generatedDispatchEvidenceRoute(undefined, 'DOC1')).toBeUndefined();
    expect(generatedDispatchEvidenceRoute('/acts/A1', ' ')).toBeUndefined();
    expect(importedDocumentReviewRoute('/acts/A1', 'IMP1')).toContain('focus=import-review');
    expect(importedDocumentReviewRoute(undefined, 'IMP1')).toBeUndefined();
  });

  it('routes convening, imported-review, dispatch-evidence, and fallback reminders', () => {
    const convening = reminder({
      source_rule: 'act-convening-notice',
      params: { act_id: 'A1' },
    });
    expect(isConveningNoticeReminder(convening)).toBe(true);
    expect(dashboardReminderActRoute(convening)).toBe('/acts/A1');
    expect(routeFromDashboardReminder(convening)).toContain('/acts/A1');

    const imported = reminder({
      action: {
        kind: 'open_imported_document_review',
        label_key: 'x',
        route: '/acts/A2',
        api_href: '/v1/documents/imported/IMP%2F2',
      },
    });
    expect(routeFromDashboardReminder(imported)).toContain('imported_document_id=IMP%2F2');

    const dispatch = reminder({
      action: {
        kind: 'open_generated_convening_dispatch_evidence',
        label_key: 'x',
        route: '/acts/A3',
        api_href: '/v1/documents/generated/DOC3/dispatch-evidence',
      },
    });
    expect(routeFromDashboardReminder(dispatch)).toContain('generated_document_id=DOC3');
    expect(routeFromDashboardReminder(reminder({ action: null }))).toBe('/entities/E1');
    expect(routeFromDashboardReminder(reminder({ entity_id: '', action: null }))).toBeUndefined();

    expect(reminderHasMissingMeetingDate(convening, 'different')).toBe(false);
    expect(
      reminderHasMissingMeetingDate(
        reminder({ params: { evidence_status: 'missing_meeting_date' } }),
        'act-convening-notice',
      ),
    ).toBe(true);
    expect(
      reminderHasMissingMeetingDate(
        reminder({ params: { notice_due_date_computable: 'false' } }),
        'act-convening-notice',
      ),
    ).toBe(true);
    expect(
      reminderHasMissingMeetingDate(
        reminder({ params: { meeting_date: '', notice_due_date: '' } }),
        'act-convening-notice',
      ),
    ).toBe(true);
    expect(dashboardReminderCopyFor(convening, 'act-convening-notice')?.body).toContain(
      'conveningNotice',
    );
    expect(dashboardReminderCopyFor(reminder(), 'unknown')).toBeUndefined();
  });

  it('prioritizes and routes alerts through metadata then safe target fallbacks', () => {
    const law: DashboardLawReference = {
      diploma_id: 'CSC',
      article: '376',
      label: 'CSC',
      heading: 'Annual meeting',
      verification: 'Pending',
      source_url: null,
      source_complete: false,
      review_method: null,
      review_note: null,
    };
    expect(lawRefSourcePending(law)).toBe(true);
    expect(lawRefMeta(law)).toContain('fonte pendente');
    expect(lawRefSourcePending({ ...law, verification: 'Verified', source_complete: true })).toBe(
      false,
    );
    expect(lawRefMeta({ ...law, verification: 'Verified', source_complete: true })).toBe(
      'Lei CSC:376',
    );

    expect(routeFromDashboardAlert(alert())).toBe('/entities/E1');
    expect(
      routeFromDashboardAlert(
        alert({ action: { kind: 'open', label_key: 'x', route: '/archive', api_href: null } }),
      ),
    ).toBe('/archive');
    expect(
      routeFromDashboardAlert(
        alert({
          target: {
            entity_id: null,
            book_id: 'B1',
            act_id: 'A1',
            links: { entity: null, book: null, act: null, ledger: null },
          },
        }),
      ),
    ).toBe('/acts/A1');
    expect(
      routeFromDashboardAlert(
        alert({
          target: {
            entity_id: null,
            book_id: 'B1',
            act_id: null,
            links: { entity: null, book: null, act: null, ledger: null },
          },
        }),
      ),
    ).toBe('/books/B1');
    expect(dashboardAlertTone(alert({ severity: 'Error' }))).toBe('error');
    expect(dashboardAlertTone(alert({ severity: 'Warning' }))).toBe('warn');
    expect(dashboardAlertTone(alert())).toBe('accent');
    expect(dashboardAlertPriority(alert({ code: 'ledger.integrity.review_required' }))).toBe(0);
    expect(dashboardAlertPriority(alert({ label: 'ReviewRequired' }))).toBe(2);
    expect(dashboardAlertPriority(alert())).toBe(3);

    const item = dashboardAlertWorkQueueItem(
      alert({ law_refs: [law], i18n: null, source: null, message: '' }),
      2,
      t,
    );
    expect(item.id).toContain(':2');
    expect(item.meta).toContain('Lei CSC:376 · fonte pendente');
  });

  it('builds, deduplicates, and deterministically sorts the complete operator queue', () => {
    const queue = buildDashboardWorkQueue({
      ledgerValid: false,
      unresolvedCompliance: 2,
      alerts: [alert()],
      reminders: [
        reminder({ status: 'Overdue', due_date: '2026-07-01' }),
        reminder({ status: 'Overdue', due_date: '2026-07-01' }),
        reminder({
          entity_id: '',
          entity_name: '',
          source_rule: '',
          source_profile: '',
          reason: '',
        }),
      ],
      t,
    });
    expect(queue.filter((item) => item.id.startsWith('reminder:'))).toHaveLength(2);
    expect(queue.some((item) => item.id === 'integrity')).toBe(true);
    expect(queue.some((item) => item.id === 'compliance')).toBe(true);
    expect(queue[0]?.priority).toBe(0);

    const base: WorkQueueItem = {
      id: 'b',
      priority: 3,
      sortTime: null,
      badge: 'b',
      tone: 'neutral',
      title: 'Beta',
      detail: '',
      meta: [],
    };
    expect(compareDashboardQueueItems({ ...base, priority: 1 }, base)).toBeLessThan(0);
    expect(
      compareDashboardQueueItems({ ...base, sortTime: 1 }, { ...base, id: 'c', sortTime: 2 }),
    ).toBeLessThan(0);
    expect(compareDashboardQueueItems({ ...base, sortTime: 1 }, base)).toBeLessThan(0);
    expect(compareDashboardQueueItems(base, { ...base, id: 'a', title: 'Alpha' })).toBeGreaterThan(
      0,
    );
  });

  it('sorts open books by valid recency then entity name without mutating input', () => {
    const books = [
      { book_id: 'B1', opening_date: null, entity_name: 'Zulu' },
      { book_id: 'B2', opening_date: 'bad', entity_name: 'Alpha' },
      { book_id: 'B3', opening_date: '2026-07-01', entity_name: 'Beta' },
      { book_id: 'B4', opening_date: '2026-07-02', entity_name: 'Gamma' },
    ] as DashboardOpenBook[];
    expect(sortedDashboardOpenBooks(books).map((book) => book.book_id)).toEqual([
      'B4',
      'B3',
      'B1',
      'B2',
    ]);
    expect(books[0]?.book_id).toBe('B1');
  });
});
