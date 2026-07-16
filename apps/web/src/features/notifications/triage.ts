import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api } from '../../api/client';
import type {
  NotificationTriageEntry,
  NotificationTriageStatus,
  NotificationTriageUpdateResponse,
} from '../../api/types';
import type { NotificationItem } from './notifications';

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
    byId.set(entry.notification_id, {
      notification_id: entry.notification_id,
      status: entry.status,
      updated_at:
        typeof entry.updated_at === 'string' && entry.updated_at
          ? entry.updated_at
          : new Date(0).toISOString(),
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
): NotificationTriageEntry[] {
  const next = entries.filter((entry) => entry.notification_id !== notificationId);
  if (status !== 'unread') {
    next.unshift(
      responseEntry ?? {
        notification_id: notificationId,
        status,
        updated_at: new Date().toISOString(),
      },
    );
  }
  return normalizeEntries(next);
}

export function patchLocalNotificationTriage(
  notificationId: string,
  status: NotificationTriageStatus,
): NotificationTriageUpdateResponse {
  const entries = applyStatus(readLocalEntries(), notificationId, status);
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
    }: {
      notificationId: string;
      status: NotificationTriageStatus;
    }) => {
      const source =
        queryClient.getQueryData<NotificationTriageQueryData>(notificationTriageKey)?.source;
      if (source === 'local') return localPatch(notificationId, status);
      try {
        return await api.patchNotificationTriage(notificationId, { status });
      } catch (error) {
        if (!shouldUseLocalFallback(error)) throw error;
        return localPatch(notificationId, status);
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
    setStatus: (notificationId: string, status: NotificationTriageStatus) =>
      mutation.mutate({ notificationId, status }),
  };
}
