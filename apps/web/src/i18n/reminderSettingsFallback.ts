/**
 * Additive copy for the compact reminder settings rows and Settings restore-default dialogs.
 * pt-PT is the reviewed source; other locales receive the English fallback until these keys are
 * folded into the shared catalogs.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';

export const reminderSettingsPtPT = {
  'settings.reminders.sources.profileCalendar.hint':
    'Datas e prazos do perfil da entidade que podem exigir acompanhamento.',
  'settings.reminders.sources.actFollowUps.hint':
    'Tarefas de seguimento registadas nas atas e nos respetivos fluxos.',
  'settings.reminders.sources.attendanceHygiene.hint':
    'Atos próximos cuja lista de presenças ainda está incompleta.',
  'settings.reminders.sources.privacyReviews.hint':
    'Revisões de controlos e obrigações de privacidade que se aproximam.',
  'settings.restore.theme.title': 'Repor cores predefinidas do tema?',
  'settings.restore.theme.body':
    'Esta ação remove todas as cores personalizadas deste navegador e volta a usar as cores do tema ativo.',
  'settings.restore.theme.confirm': 'Repor cores',
  'settings.restore.tsl.title': 'Repor URL predefinido da lista de confiança?',
  'settings.restore.tsl.body':
    'O URL alternativo atual será substituído pelo URL predefinido da lista de confiança. A alteração continua sujeita à validação e gravação automática das configurações.',
  'settings.restore.tsl.confirm': 'Repor URL da TSL',
  'settings.restore.tsa.title': 'Repor URL predefinido da autoridade de selo temporal?',
  'settings.restore.tsa.body':
    'O URL alternativo atual será substituído pelo URL predefinido da autoridade de selo temporal. A alteração continua sujeita à validação e gravação automática das configurações.',
  'settings.restore.tsa.confirm': 'Repor URL da TSA',
  'settings.restore.pending': 'A repor…',
} as const;

export type ReminderSettingsCopyKey = keyof typeof reminderSettingsPtPT;

export const reminderSettingsEnglish = {
  'settings.reminders.sources.profileCalendar.hint':
    'Entity profile dates and deadlines that may need follow-up.',
  'settings.reminders.sources.actFollowUps.hint':
    'Follow-up tasks recorded in minutes and their workflows.',
  'settings.reminders.sources.attendanceHygiene.hint':
    'Upcoming acts whose attendance list is still incomplete.',
  'settings.reminders.sources.privacyReviews.hint':
    'Approaching privacy control and obligation reviews.',
  'settings.restore.theme.title': 'Restore the theme default colors?',
  'settings.restore.theme.body':
    'This removes every custom color from this browser and returns to the active theme colors.',
  'settings.restore.theme.confirm': 'Restore colors',
  'settings.restore.tsl.title': 'Restore the default trusted-list URL?',
  'settings.restore.tsl.body':
    'The current fallback URL will be replaced by the default trusted-list URL. The change remains subject to settings validation and autosave.',
  'settings.restore.tsl.confirm': 'Restore TSL URL',
  'settings.restore.tsa.title': 'Restore the default timestamp-authority URL?',
  'settings.restore.tsa.body':
    'The current fallback URL will be replaced by the default timestamp-authority URL. The change remains subject to settings validation and autosave.',
  'settings.restore.tsa.confirm': 'Restore TSA URL',
  'settings.restore.pending': 'Restoring…',
} as const satisfies Record<ReminderSettingsCopyKey, string>;

export function useReminderSettingsT(): (key: ReminderSettingsCopyKey) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? reminderSettingsPtPT : reminderSettingsEnglish;
  return useMemo(() => (key) => copy[key], [copy]);
}
