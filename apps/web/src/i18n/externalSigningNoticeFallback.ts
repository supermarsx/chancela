/**
 * Additive copy for the external-signing informational-notice dismissal controls. Kept outside
 * the shared locale catalogs while the matching settings/preferences contract is pending.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const externalSigningNoticePtPT = {
  'externalSigning.notice.dismissActions': 'Opções para ocultar este aviso',
  'externalSigning.notice.hideTemporary': 'Ocultar durante {days} dias',
  'externalSigning.notice.hidePermanent': 'Ocultar permanentemente',
  'externalSigning.notice.hiddenTemporary': 'Aviso ocultado durante {days} dias.',
  'externalSigning.notice.hiddenPermanent': 'Aviso ocultado permanentemente.',
} as const;

export type ExternalSigningNoticeCopyKey = keyof typeof externalSigningNoticePtPT;

export const externalSigningNoticeEnglish = {
  'externalSigning.notice.dismissActions': 'Options for hiding this notice',
  'externalSigning.notice.hideTemporary': 'Hide for {days} days',
  'externalSigning.notice.hidePermanent': 'Hide permanently',
  'externalSigning.notice.hiddenTemporary': 'Notice hidden for {days} days.',
  'externalSigning.notice.hiddenPermanent': 'Notice hidden permanently.',
} as const satisfies Record<ExternalSigningNoticeCopyKey, string>;

export function useExternalSigningNoticeT(): (
  key: ExternalSigningNoticeCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? externalSigningNoticePtPT : externalSigningNoticeEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
