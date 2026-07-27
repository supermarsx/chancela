/**
 * Additive copy for the legislation corpus reader's pinned-citations caveat dismissal controls.
 * Kept outside the shared locale catalogs, mirroring `externalSigningNoticeFallback.ts` /
 * `platformLogNoticeFallback.ts` — a small, additive slice pt-anchored plus an English fallback
 * for every other shipped locale, rather than a full 16-catalog translation for a few strings.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

export const legCitationsNoticePtPT = {
  'legCitations.notice.dismissActions': 'Opções para ocultar este aviso',
  'legCitations.notice.hideTemporary': 'Ocultar durante {days} dias',
  'legCitations.notice.hidePermanent': 'Ocultar permanentemente',
  'legCitations.notice.restore': 'Repor aviso sobre as citações',
  'legCitations.notice.hiddenTemporary': 'Aviso ocultado durante {days} dias.',
  'legCitations.notice.hiddenPermanent': 'Aviso ocultado permanentemente.',
  'legCitations.notice.restored': 'Aviso sobre as citações reposto.',
} as const;

export type LegCitationsNoticeCopyKey = keyof typeof legCitationsNoticePtPT;

export const legCitationsNoticeEnglish = {
  'legCitations.notice.dismissActions': 'Options for hiding this notice',
  'legCitations.notice.hideTemporary': 'Hide for {days} days',
  'legCitations.notice.hidePermanent': 'Hide permanently',
  'legCitations.notice.restore': 'Restore citations notice',
  'legCitations.notice.hiddenTemporary': 'Notice hidden for {days} days.',
  'legCitations.notice.hiddenPermanent': 'Notice hidden permanently.',
  'legCitations.notice.restored': 'Citations notice restored.',
} as const satisfies Record<LegCitationsNoticeCopyKey, string>;

export function useLegCitationsNoticeT(): (
  key: LegCitationsNoticeCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? legCitationsNoticePtPT : legCitationsNoticeEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
