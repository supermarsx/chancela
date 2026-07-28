/**
 * The per-user informational-notice dismissal registry, and the hook the `InlineWarning` dismiss
 * capability is built on.
 *
 * A dismissal is durable personal state, not component state: it is one entry in the self-scoped
 * `/v1/me/preferences` document, keyed by a closed `NoticeKey` enum that the API mirrors. So a
 * notice the operator hid stays hidden on their next session and on their other machine, and
 * hiding one notice never touches another.
 *
 * Moved here from `features/notices/` when dismissal became a UI capability rather than three
 * pages' private logic: the primitives layer is now the only production consumer.
 */
import { useCallback } from 'react';
import type { NoticeDismissal, NoticeKey, Settings, UserPreferences } from '../api/types';
import { useSettings, useUpdateNoticeDismissal, useUserPreferences } from '../api/hooks';
import { useNoticeDismissCopy, type NoticeDismissCopy } from '../i18n/noticeDismissFallback';
import { useToast } from './toast';

export const DEFAULT_INFORMATIONAL_NOTICE_SNOOZE_DAYS = 90;

/** All informational notices share the configured external-notice policy until it is renamed. */
export function informationalNoticeHideDays(settings: Settings | undefined): number {
  const configured = settings?.ui.external_signature_notice_snooze_days;
  return Number.isInteger(configured) && configured !== undefined && configured > 0
    ? configured
    : DEFAULT_INFORMATIONAL_NOTICE_SNOOZE_DAYS;
}

export function informationalNoticeIsHidden(
  dismissal: NoticeDismissal | null | undefined,
  now = Date.now(),
): boolean {
  if (!dismissal) return false;
  if (dismissal.mode === 'permanent') return true;
  const until = Date.parse(dismissal.until);
  return Number.isFinite(until) && until > now;
}

/** Read one registry entry while preserving the pre-registry external-signature value. */
export function noticeDismissalFromPreferences(
  preferences: UserPreferences | undefined,
  notice: NoticeKey,
): NoticeDismissal | null | undefined {
  return (
    preferences?.notice_dismissals?.[notice] ??
    (notice === 'external_signing' ? preferences?.external_signature_notice_dismissal : undefined)
  );
}

export function createNoticeDismissal(
  mode: NoticeDismissal['mode'],
  temporaryHideDays: number,
  now = Date.now(),
): NoticeDismissal {
  return mode === 'permanent'
    ? { mode }
    : {
        mode: 'snoozed',
        until: new Date(now + temporaryHideDays * 24 * 60 * 60 * 1000).toISOString(),
      };
}

export interface NoticeDismissalControls {
  /**
   * The preferences document has not arrived yet. Callers render NOTHING while this holds: a
   * banner shown now and retracted a moment later is worse than a beat of nothing, because the
   * operator already told us they did not want to see it.
   */
  loading: boolean;
  /**
   * The document arrived, so the controls would reflect the operator's real choice. False on a
   * failed load, where the notice still shows but offers no dismissal — a PUT built on a
   * preferences document we never read would silently drop their table columns.
   */
  ready: boolean;
  hidden: boolean;
  /** A dismissal or restore is in flight; the controls disable themselves (CONVENTIONS §5). */
  pending: boolean;
  copy: NoticeDismissCopy;
  hide: (mode: NoticeDismissal['mode']) => void;
  restore: () => void;
}

/**
 * Wire one notice key to the registry: whether it is currently hidden, and the two writes that
 * change that. Owns the success/failure toasts (CONVENTIONS §2/§3) so every dismissable notice
 * confirms itself the same way.
 */
export function useNoticeDismissal(notice: NoticeKey): NoticeDismissalControls {
  const toast = useToast();
  const settings = useSettings();
  const preferences = useUserPreferences();
  const update = useUpdateNoticeDismissal(notice);
  const temporaryHideDays = informationalNoticeHideDays(settings.data);
  const copy = useNoticeDismissCopy(notice, temporaryHideDays);

  const hide = useCallback(
    (mode: NoticeDismissal['mode']) => {
      update.mutate(createNoticeDismissal(mode, temporaryHideDays), {
        onSuccess: () =>
          toast.success(mode === 'permanent' ? copy.hiddenPermanent : copy.hiddenTemporary),
        onError: (error) => toast.error(error),
      });
    },
    [copy.hiddenPermanent, copy.hiddenTemporary, temporaryHideDays, toast, update],
  );

  const restore = useCallback(() => {
    const confirmation = copy.restore?.confirmation;
    if (confirmation === undefined) return;
    update.mutate(null, {
      onSuccess: () => toast.success(confirmation),
      onError: (error) => toast.error(error),
    });
  }, [copy.restore?.confirmation, toast, update]);

  return {
    loading: preferences.isLoading,
    ready: preferences.isSuccess,
    hidden: informationalNoticeIsHidden(noticeDismissalFromPreferences(preferences.data, notice)),
    pending: update.isPending,
    copy,
    hide,
    restore,
  };
}
