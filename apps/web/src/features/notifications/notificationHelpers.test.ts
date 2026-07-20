import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../../api/client';
import type { LedgerEventView, NotificationTriageEntry } from '../../api/types';
import {
  compareEventsByRecency,
  frontendNotificationRouteFromApi,
  generatedDispatchDocumentIdFromApi,
  importedDocumentIdFromApi,
  parseNotificationTimestamp,
} from './notifications';
import {
  applyNotificationTriageStatus,
  normalizeNotificationTriageEntries,
  patchLocalNotificationTriage,
  readLocalNotificationTriageEntries,
  shouldUseLocalNotificationTriageFallback,
  writeLocalNotificationTriageEntries,
} from './triage';

const event = (timestamp: string, seq: number) => ({ timestamp, seq }) as LedgerEventView;

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('notification routing and ordering helpers', () => {
  it('parses timestamps and maps both frontend and API routes', () => {
    expect(parseNotificationTimestamp()).toBeNull();
    expect(parseNotificationTimestamp('not-a-date')).toBeNull();
    expect(parseNotificationTimestamp('2026-07-16T10:00:00Z')).toBe(
      Date.parse('2026-07-16T10:00:00Z'),
    );

    expect(frontendNotificationRouteFromApi(undefined)).toBeUndefined();
    expect(frontendNotificationRouteFromApi('  ')).toBeUndefined();
    expect(frontendNotificationRouteFromApi('/entidades/entity-1')).toBe('/entidades/entity-1');
    expect(frontendNotificationRouteFromApi('/livros')).toBe('/livros');
    expect(frontendNotificationRouteFromApi('/atas/act-1')).toBe('/atas/act-1');
    expect(frontendNotificationRouteFromApi('/arquivo?kind=sealed')).toBe('/arquivo?kind=sealed');
    expect(frontendNotificationRouteFromApi('/configuracoes#privacy')).toBe(
      '/configuracoes#privacy',
    );
    expect(frontendNotificationRouteFromApi('/v1/entities/entity-2?x=1')).toBe(
      '/entidades/entity-2',
    );
    expect(frontendNotificationRouteFromApi('/v1/books/book-2')).toBe('/livros/book-2');
    expect(frontendNotificationRouteFromApi('/v1/acts/act-2')).toBe('/atas/act-2');
    expect(frontendNotificationRouteFromApi('/v1/ledger/events')).toBe('/arquivo');
    expect(frontendNotificationRouteFromApi('/v1/settings')).toBe('/configuracoes');
    expect(frontendNotificationRouteFromApi('/v1/unknown')).toBeUndefined();
  });

  it('extracts generated and imported document ids defensively', () => {
    expect(generatedDispatchDocumentIdFromApi(undefined)).toBeUndefined();
    expect(generatedDispatchDocumentIdFromApi('/v1/documents/generated/id')).toBeUndefined();
    expect(
      generatedDispatchDocumentIdFromApi(
        '/v1/documents/generated/doc%201/dispatch-evidence?download=1',
      ),
    ).toBe('doc 1');
    expect(
      generatedDispatchDocumentIdFromApi('/v1/documents/generated/%ZZ/dispatch-evidence'),
    ).toBe('%ZZ');

    expect(importedDocumentIdFromApi(' ')).toBeUndefined();
    expect(importedDocumentIdFromApi('/v1/documents/generated/id')).toBeUndefined();
    expect(importedDocumentIdFromApi('/v1/documents/imported/doc%202/review')).toBe('doc 2');
    expect(importedDocumentIdFromApi('/v1/documents/imported/%ZZ')).toBe('%ZZ');
  });

  it('orders events by valid time, timestamp availability, then sequence', () => {
    expect(
      compareEventsByRecency(event('2026-07-15T10:00:00Z', 1), event('2026-07-16T10:00:00Z', 2)),
    ).toBeGreaterThan(0);
    expect(compareEventsByRecency(event('invalid', 3), event('2026-07-16T10:00:00Z', 2))).toBe(1);
    expect(compareEventsByRecency(event('2026-07-16T10:00:00Z', 2), event('invalid', 3))).toBe(-1);
    expect(compareEventsByRecency(event('invalid', 3), event('also-invalid', 9))).toBe(6);
  });
});

describe('notification triage local fallback helpers', () => {
  const entry = (
    notificationId: string,
    status: NotificationTriageEntry['status'] = 'read',
    updatedAt = '2026-07-16T10:00:00Z',
  ): NotificationTriageEntry => ({
    notification_id: notificationId,
    status,
    updated_at: updatedAt,
  });

  it('normalizes, validates, deduplicates, sorts, and bounds persisted entries', () => {
    expect(normalizeNotificationTriageEntries(null)).toEqual([]);
    const values: unknown[] = [
      null,
      'invalid',
      {},
      { notification_id: ' ', status: 'read' },
      { notification_id: 'bad', status: 'unread' },
      { notification_id: 'same', status: 'read', updated_at: '' },
      { notification_id: 'same', status: 'dismissed', updated_at: '2026-07-16T12:00:00Z' },
      {
        notification_id: 'owned',
        status: 'acknowledged',
        owner: 'operator',
        updated_at: '2099-01-01T00:00:00Z',
      },
      ...Array.from({ length: 501 }, (_, index) =>
        entry(
          `bulk-${String(index).padStart(3, '0')}`,
          'read',
          `2026-01-01T00:00:${String(index % 60).padStart(2, '0')}Z`,
        ),
      ),
    ];
    const normalized = normalizeNotificationTriageEntries(values);
    expect(normalized).toHaveLength(500);
    expect(normalized.find((item) => item.notification_id === 'same')?.status).toBe('dismissed');
    expect(normalized.find((item) => item.notification_id === 'owned')?.owner).toBe('operator');
    expect(normalized.every((item) => item.updated_at.length > 0)).toBe(true);
  });

  it('reads and writes best-effort local storage', () => {
    writeLocalNotificationTriageEntries([entry('one')]);
    expect(readLocalNotificationTriageEntries()).toEqual([entry('one')]);

    window.localStorage.setItem('chancela.notificationTriage.v1', '{broken');
    expect(readLocalNotificationTriageEntries()).toEqual([]);

    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota');
    });
    expect(() => writeLocalNotificationTriageEntries([entry('two')])).not.toThrow();

    vi.stubGlobal('window', undefined);
    expect(readLocalNotificationTriageEntries()).toEqual([]);
    expect(() => writeLocalNotificationTriageEntries([entry('three')])).not.toThrow();
  });

  it('applies statuses and creates durable local patch responses', () => {
    expect(applyNotificationTriageStatus([entry('one')], 'one', 'unread')).toEqual([]);
    expect(
      applyNotificationTriageStatus([], 'two', 'dismissed', entry('two', 'dismissed')),
    ).toEqual([entry('two', 'dismissed')]);
    const generated = applyNotificationTriageStatus([], 'three', 'acknowledged');
    expect(generated[0]).toMatchObject({
      notification_id: 'three',
      status: 'acknowledged',
    });

    const response = patchLocalNotificationTriage('four', 'read');
    expect(response).toMatchObject({ status: 'read', durable: true });
    expect(response.entry).toMatchObject({ notification_id: 'four', status: 'read' });
    const cleared = patchLocalNotificationTriage('four', 'unread');
    expect(cleared.entry).toBeNull();
  });

  it('limits fallback to capability errors while tolerating transport failures', () => {
    for (const status of [200, 404, 405, 501]) {
      expect(shouldUseLocalNotificationTriageFallback(new ApiError(status, { error: 'x' }))).toBe(
        true,
      );
    }
    expect(shouldUseLocalNotificationTriageFallback(new ApiError(403, { error: 'x' }))).toBe(false);
    expect(shouldUseLocalNotificationTriageFallback(new Error('offline'))).toBe(true);
  });
});
