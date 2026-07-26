import type { NoticeDismissal, NoticeKey, Settings, UserPreferences } from '../../api/types';

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
