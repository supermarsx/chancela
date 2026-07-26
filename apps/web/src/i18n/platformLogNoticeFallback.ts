import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

export const platformLogNoticePtPT = {
  'platformLogs.notice.dismissActions': 'Opções para ocultar o aviso sobre o âmbito dos logs',
  'platformLogs.notice.hideTemporary': 'Ocultar durante {days} dias',
  'platformLogs.notice.hidePermanent': 'Ocultar permanentemente',
  'platformLogs.notice.restore': 'Repor aviso sobre o âmbito dos logs',
  'platformLogs.notice.hiddenTemporary': 'Aviso ocultado durante {days} dias.',
  'platformLogs.notice.hiddenPermanent': 'Aviso ocultado permanentemente.',
  'platformLogs.notice.restored': 'Aviso sobre o âmbito dos logs reposto.',
} as const;

export type PlatformLogNoticeCopyKey = keyof typeof platformLogNoticePtPT;

export const platformLogNoticeEnglish = {
  'platformLogs.notice.dismissActions': 'Options for hiding the log-scope notice',
  'platformLogs.notice.hideTemporary': 'Hide for {days} days',
  'platformLogs.notice.hidePermanent': 'Hide permanently',
  'platformLogs.notice.restore': 'Restore log-scope notice',
  'platformLogs.notice.hiddenTemporary': 'Notice hidden for {days} days.',
  'platformLogs.notice.hiddenPermanent': 'Notice hidden permanently.',
  'platformLogs.notice.restored': 'Log-scope notice restored.',
} as const satisfies Record<PlatformLogNoticeCopyKey, string>;

export function usePlatformLogNoticeT(): (
  key: PlatformLogNoticeCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? platformLogNoticePtPT : platformLogNoticeEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
