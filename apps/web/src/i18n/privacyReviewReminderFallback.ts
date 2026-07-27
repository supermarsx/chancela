/**
 * Copy for the dashboard/notification-centre "local privacy review" reminder, raised by
 * `privacy_review_reminder_from_summary` (`crates/chancela-action-center/src/lib.rs`,
 * `crates/chancela-api/src/dashboard.rs`) for a DPIA, a breach-response playbook, or a transfer
 * control whose local review/drill cadence has lapsed or has no receipt.
 *
 * **Why this crashed.** The reminder ships `i18n.title_key` / `body_key` / `action_key` set to
 * `notifications.reminder.privacy.review.*`, and `NotificationBell`/`NotificationsPage` resolve
 * any server-supplied key straight through `t()` without checking it exists — `messageKey()` in
 * `notifications.ts` casts the raw server string to `MessageKey` on faith. These three keys were
 * never added to the catalogs, so `i18nStore.message()` returned `undefined` and
 * `interpolate()` crashed on `undefined.replace`. The fix is these keys existing somewhere `t()`
 * can find them — not `interpolate` tolerating a missing template.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are `Catalog` — a total type — so one new key
 * fails `tsc -b` for all fourteen at once, and several are held by other lanes right now. This
 * module owns its key set end to end, same shape as `reminderSettingsFallback.ts`. Fold it into
 * the catalogs once all fourteen locale files are in one hand.
 *
 * **Why one title/body/action for all three registers.** Which register raised the reminder
 * (DPIA, breach playbook, transfer control) is already carried by the reminder's own "Fonte"
 * meta line (`reminderSourceMeta` → `dashboardReminderRuleLabel` → `dashboardSourceLabels.ts`,
 * which already ships all three `privacy-*-review` rule labels in all fourteen locales). Repeating
 * the register name here would be redundant, so the copy stays generic and leads with
 * `{record_label}` — the record's own title/name — instead.
 */
import { i18nStore } from './store';
import { interpolate, type TParams } from './interpolate';

export const privacyReviewReminderPtPT = {
  'notifications.reminder.privacy.review.title': 'Revisão de privacidade pendente: {record_label}',
  'notifications.reminder.privacy.review.body':
    '{record_label} não tem uma revisão ou simulação local registada dentro do intervalo previsto. Registe um recibo de revisão ou simulação quando existir evidência do operador. Lembrete consultivo e local; não notifica autoridades ou titulares dos dados, não apresenta nem certifica conformidade.',
  'notifications.reminder.privacy.review.action': 'Rever privacidade',
} as const;

export type PrivacyReviewReminderCopyKey = keyof typeof privacyReviewReminderPtPT;

// en-US is the authoring source for the fallback tier; en-GB and every other unlisted locale
// share it until native review lands, matching `reminderSettingsFallback.ts`.
export const privacyReviewReminderEnglish = {
  'notifications.reminder.privacy.review.title': 'Privacy review pending: {record_label}',
  'notifications.reminder.privacy.review.body':
    '{record_label} has no local review or drill receipt recorded within the expected interval. Record a review or drill receipt when operator evidence exists. Local, advisory reminder only; it does not notify authorities or data subjects, and does not assert or certify compliance.',
  'notifications.reminder.privacy.review.action': 'Review privacy item',
} as const satisfies Record<PrivacyReviewReminderCopyKey, string>;

const PRIVACY_REVIEW_REMINDER_KEYS: ReadonlySet<string> = new Set(
  Object.keys(privacyReviewReminderPtPT),
);

/** Whether `key` (a raw string off the wire) belongs to this fallback module's key set. */
export function isPrivacyReviewReminderKey(key: string): key is PrivacyReviewReminderCopyKey {
  return PRIVACY_REVIEW_REMINDER_KEYS.has(key);
}

/**
 * Non-React resolver — `buildDashboardNotifications` is a plain function, not a component, so
 * this reads the active locale straight from the store, exactly as the module-level `t()` in
 * `useT.ts` does.
 */
export function privacyReviewReminderT(
  key: PrivacyReviewReminderCopyKey,
  params?: TParams,
): string {
  const copy =
    i18nStore.getActiveLocale() === 'pt-PT' ? privacyReviewReminderPtPT : privacyReviewReminderEnglish;
  return interpolate(copy[key], params);
}
