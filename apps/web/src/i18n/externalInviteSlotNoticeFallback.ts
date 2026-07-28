/**
 * Additive counterparty-facing copy explaining what an external-envelope slot status does and does
 * not assert. Kept outside the shared locale catalogs, mirroring `noticeDismissFallback.ts` — a small, additive slice pt-anchored plus an English fallback
 * for every other shipped locale, rather than a full 14-catalog translation for two strings.
 *
 * The reader here is an outside signatory on the unauthenticated invite page, not a trained
 * operator: they never see the operator guardrail. The wording is deliberately narrow. Act
 * co-signature slots are *recorded* — `chancela_core::external_signing` performs no cryptography on
 * that path — so the status is workflow tracking, and the copy says so. It must not be widened into
 * a claim that the product does not sign: `chancela_signing`'s production pipeline is wired through
 * `signature.rs` / `termo.rs`, and termo signing produces real PAdES today.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

export const externalInviteSlotNoticePtPT = {
  'externalInviteSlot.notice.title': 'O que significa este estado',
  'externalInviteSlot.notice.body':
    'Este estado acompanha a recolha de assinaturas deste ato e regista a evidência associada a cada signatário. Por si só, não é uma assinatura nem confirma a validade de uma assinatura, e a Chancela não cria aqui qualquer assinatura. Se assinou com as suas próprias ferramentas, a sua assinatura permanece no ficheiro que assinou e é aí que pode ser verificada.',
} as const;

export type ExternalInviteSlotNoticeCopyKey = keyof typeof externalInviteSlotNoticePtPT;

export const externalInviteSlotNoticeEnglish = {
  'externalInviteSlot.notice.title': 'What this status means',
  'externalInviteSlot.notice.body':
    'This status tracks how signatures for this act are being collected, and records the evidence attached to each signatory. On its own it is neither a signature nor a confirmation that a signature is valid, and Chancela creates no signature here. If you signed using your own tools, your signature stays in the file you signed, and that is where it can be verified.',
} as const satisfies Record<ExternalInviteSlotNoticeCopyKey, string>;

export function useExternalInviteSlotNoticeT(): (
  key: ExternalInviteSlotNoticeCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? externalInviteSlotNoticePtPT : externalInviteSlotNoticeEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
