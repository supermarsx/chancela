import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api } from '../../api/client';
import type {
  NotificationSnapshot,
  NotificationSnapshotAction,
  NotificationTriageEntry,
  NotificationTriageStatus,
  NotificationTriageUpdateBody,
  NotificationTriageUpdateResponse,
} from '../../api/types';
import { notificationItemFromSnapshot, type NotificationItem } from './notifications';

const LOCAL_STORAGE_KEY = 'chancela.notificationTriage.v1';
const LOCAL_MAX_ENTRIES = 500;

export const notificationTriageKey = ['notifications', 'triage'] as const;

export type TriagedNotificationItem = NotificationItem & {
  triageStatus: NotificationTriageStatus;
};

interface NotificationTriageQueryData {
  entries: NotificationTriageEntry[];
  durable: boolean;
  source: 'server' | 'local';
  maxEntries: number;
}

function isStoredStatus(value: unknown): value is NotificationTriageEntry['status'] {
  return value === 'read' || value === 'dismissed' || value === 'acknowledged';
}

function isSnapshotAction(value: unknown): value is NotificationSnapshotAction {
  if (!value || typeof value !== 'object') return false;
  const action = value as Record<string, unknown>;
  return typeof action.href === 'string' && typeof action.label === 'string';
}

/**
 * Keep a snapshot only when it carries the full required display shape. A partial or tampered blob
 * (localStorage is user-writable) is dropped, degrading that entry to live-reconstruction rather
 * than rendering a half-built card. The server already length-caps and control-char-checks the copy
 * before it stores it, so this is a shape guard, not a re-validation of every byte.
 */
function normalizeSnapshot(value: unknown): NotificationSnapshot | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const snapshot = value as Record<string, unknown>;
  if (
    typeof snapshot.kind !== 'string' ||
    typeof snapshot.tone !== 'string' ||
    typeof snapshot.badge !== 'string' ||
    typeof snapshot.title !== 'string' ||
    typeof snapshot.detail !== 'string'
  ) {
    return undefined;
  }
  const normalized: NotificationSnapshot = {
    kind: snapshot.kind,
    tone: snapshot.tone,
    badge: snapshot.badge,
    title: snapshot.title,
    detail: snapshot.detail,
  };
  if (typeof snapshot.timestamp === 'string') normalized.timestamp = snapshot.timestamp;
  if (isSnapshotAction(snapshot.action)) {
    normalized.action = { href: snapshot.action.href, label: snapshot.action.label };
  }
  return normalized;
}

export function normalizeNotificationTriageEntries(value: unknown): NotificationTriageEntry[] {
  if (!Array.isArray(value)) return [];
  const byId = new Map<string, NotificationTriageEntry>();
  for (const raw of value) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as Partial<NotificationTriageEntry>;
    if (
      typeof entry.notification_id !== 'string' ||
      !entry.notification_id.trim() ||
      !isStoredStatus(entry.status)
    ) {
      continue;
    }
    const dismissedAt =
      typeof entry.dismissed_at === 'string' && entry.dismissed_at ? entry.dismissed_at : undefined;
    const snapshot = normalizeSnapshot(entry.snapshot);
    byId.set(entry.notification_id, {
      notification_id: entry.notification_id,
      status: entry.status,
      updated_at:
        typeof entry.updated_at === 'string' && entry.updated_at
          ? entry.updated_at
          : new Date(0).toISOString(),
      ...(dismissedAt ? { dismissed_at: dismissedAt } : {}),
      ...(snapshot ? { snapshot } : {}),
      ...(typeof entry.owner === 'string' ? { owner: entry.owner } : {}),
    });
  }
  return Array.from(byId.values())
    .sort(
      (a, b) =>
        b.updated_at.localeCompare(a.updated_at) ||
        a.notification_id.localeCompare(b.notification_id),
    )
    .slice(0, LOCAL_MAX_ENTRIES);
}

export function readLocalNotificationTriageEntries(): NotificationTriageEntry[] {
  if (typeof window === 'undefined') return [];
  try {
    return normalizeEntries(JSON.parse(window.localStorage.getItem(LOCAL_STORAGE_KEY) ?? '[]'));
  } catch {
    return [];
  }
}

export function writeLocalNotificationTriageEntries(entries: NotificationTriageEntry[]): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(LOCAL_STORAGE_KEY, JSON.stringify(normalizeEntries(entries)));
  } catch {
    // Local fallback is best-effort; the UI state still updates through the query cache.
  }
}

export function applyNotificationTriageStatus(
  entries: NotificationTriageEntry[],
  notificationId: string,
  status: NotificationTriageStatus,
  responseEntry?: NotificationTriageEntry | null,
  snapshot?: NotificationSnapshot,
): NotificationTriageEntry[] {
  const next = entries.filter((entry) => entry.notification_id !== notificationId);
  if (status !== 'unread') {
    const now = new Date().toISOString();
    next.unshift(
      responseEntry ?? {
        notification_id: notificationId,
        status,
        updated_at: now,
        // A locally-authored dismiss carries its own retention clock and display snapshot, so the
        // fallback entry behaves like the server one — visible in Descartadas, aged out on the same
        // 120-day terms once the server is reachable again.
        ...(status === 'dismissed' ? { dismissed_at: now, ...(snapshot ? { snapshot } : {}) } : {}),
      },
    );
  }
  return normalizeEntries(next);
}

export function patchLocalNotificationTriage(
  notificationId: string,
  status: NotificationTriageStatus,
  snapshot?: NotificationSnapshot,
): NotificationTriageUpdateResponse {
  const entries = applyStatus(readLocalEntries(), notificationId, status, undefined, snapshot);
  writeLocalEntries(entries);
  return {
    status,
    entry: entries.find((entry) => entry.notification_id === notificationId) ?? null,
    durable: true,
  };
}

export function shouldUseLocalNotificationTriageFallback(error: unknown): boolean {
  if (error instanceof ApiError) {
    return (
      error.status === 200 || error.status === 404 || error.status === 405 || error.status === 501
    );
  }
  return true;
}

const normalizeEntries = normalizeNotificationTriageEntries;
const readLocalEntries = readLocalNotificationTriageEntries;
const writeLocalEntries = writeLocalNotificationTriageEntries;
const applyStatus = applyNotificationTriageStatus;
const localPatch = patchLocalNotificationTriage;
const shouldUseLocalFallback = shouldUseLocalNotificationTriageFallback;

export function triageStatusFor(
  entries: NotificationTriageEntry[],
  notificationId: string,
): NotificationTriageStatus {
  return entries.find((entry) => entry.notification_id === notificationId)?.status ?? 'unread';
}

export function withNotificationTriage(
  items: NotificationItem[],
  entries: NotificationTriageEntry[],
): TriagedNotificationItem[] {
  return items.map((item) => ({
    ...item,
    triageStatus: triageStatusFor(entries, item.id),
  }));
}

export function isResolvedNotification(item: TriagedNotificationItem): boolean {
  return item.triageStatus === 'dismissed' || item.triageStatus === 'acknowledged';
}

export function activeNotifications(items: TriagedNotificationItem[]): TriagedNotificationItem[] {
  return items.filter((item) => !isResolvedNotification(item));
}

export function unreadNotifications(items: TriagedNotificationItem[]): TriagedNotificationItem[] {
  return activeNotifications(items).filter((item) => item.triageStatus === 'unread');
}

export function resolvedNotifications(items: TriagedNotificationItem[]): TriagedNotificationItem[] {
  return items.filter(isResolvedNotification);
}

export function acknowledgedNotifications(
  items: TriagedNotificationItem[],
): TriagedNotificationItem[] {
  return items.filter((item) => item.triageStatus === 'acknowledged');
}

/**
 * The Descartadas list: every dismissed notification, whether the dashboard still generates it or
 * not. Live-reconstructed items win over their stored snapshot (freshest copy), and entries whose
 * condition has cleared are rebuilt from the snapshot the client froze on dismiss. Sorted by the
 * dismissal instant (newest first), falling back to `updated_at` for pre-snapshot entries.
 */
export function dismissedNotifications(
  items: TriagedNotificationItem[],
  entries: NotificationTriageEntry[],
): TriagedNotificationItem[] {
  const live = items.filter((item) => item.triageStatus === 'dismissed');
  const liveIds = new Set(live.map((item) => item.id));
  const snapshotOnly: TriagedNotificationItem[] = entries
    .filter(
      (entry) =>
        entry.status === 'dismissed' && entry.snapshot && !liveIds.has(entry.notification_id),
    )
    .map((entry) => ({
      ...notificationItemFromSnapshot(
        entry.notification_id,
        entry.snapshot as NotificationSnapshot,
      ),
      triageStatus: 'dismissed' as const,
    }));
  const clockById = new Map(
    entries.map(
      (entry) => [entry.notification_id, entry.dismissed_at ?? entry.updated_at] as const,
    ),
  );
  const clock = (id: string): string => clockById.get(id) ?? '';
  return [...live, ...snapshotOnly].sort(
    (a, b) => clock(b.id).localeCompare(clock(a.id)) || a.id.localeCompare(b.id),
  );
}

export function useNotificationTriage() {
  const queryClient = useQueryClient();
  const query = useQuery<NotificationTriageQueryData>({
    queryKey: notificationTriageKey,
    queryFn: async () => {
      try {
        const response = await api.getNotificationTriage();
        return {
          entries: normalizeEntries(response.entries),
          durable: response.durable,
          source: 'server',
          maxEntries: response.max_entries_per_owner,
        };
      } catch (error) {
        if (!shouldUseLocalFallback(error)) throw error;
        return {
          entries: readLocalEntries(),
          durable: true,
          source: 'local',
          maxEntries: LOCAL_MAX_ENTRIES,
        };
      }
    },
    staleTime: 30_000,
  });

  const mutation = useMutation({
    mutationFn: async ({
      notificationId,
      status,
      snapshot,
    }: {
      notificationId: string;
      status: NotificationTriageStatus;
      snapshot?: NotificationSnapshot;
    }) => {
      const source =
        queryClient.getQueryData<NotificationTriageQueryData>(notificationTriageKey)?.source;
      if (source === 'local') return localPatch(notificationId, status, snapshot);
      const body: NotificationTriageUpdateBody = { status };
      // The snapshot only means anything on a dismiss — it is what Descartadas renders once the
      // dashboard stops generating the item. Never sent for read/acknowledge/restore.
      if (status === 'dismissed' && snapshot) body.snapshot = snapshot;
      try {
        return await api.patchNotificationTriage(notificationId, body);
      } catch (error) {
        if (!shouldUseLocalFallback(error)) throw error;
        return localPatch(notificationId, status, snapshot);
      }
    },
    onSuccess: (response, variables) => {
      queryClient.setQueryData<NotificationTriageQueryData>(notificationTriageKey, (current) => {
        const source = current?.source ?? (response.durable ? 'server' : 'local');
        const entries = applyStatus(
          current?.entries ?? readLocalEntries(),
          variables.notificationId,
          response.status,
          response.entry,
          variables.snapshot,
        );
        if (source === 'local') writeLocalEntries(entries);
        return {
          entries,
          durable: current?.durable ?? response.durable,
          source,
          maxEntries: current?.maxEntries ?? LOCAL_MAX_ENTRIES,
        };
      });
    },
  });

  return {
    entries: query.data?.entries ?? [],
    isLoading: query.isLoading,
    error: query.error,
    source: query.data?.source ?? 'server',
    durable: query.data?.durable ?? false,
    isUpdating: mutation.isPending,
    setStatus: (
      notificationId: string,
      status: NotificationTriageStatus,
      snapshot?: NotificationSnapshot,
    ) => mutation.mutate({ notificationId, status, snapshot }),
  };
}
