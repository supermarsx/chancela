/**
 * Additive copy explaining what an external-signing envelope slot's `signed` status does and does
 * not assert. Kept outside the shared locale catalogs because `Catalog` is a total type: a new key
 * fails `tsc -b` for all fourteen locales at once, and eleven of them are owned by another lane.
 * Same shape as `noticeDismissFallback.ts`.
 *
 * Fold this into the catalogs once all fourteen locale files are in one hand.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const envelopeSlotStatusPtPT = {
  'signing.envelopes.slot.status.signed.hint':
    '«Assinatura registada» indica que o slot tem evidência associada a uma assinatura: uma referência registada pelo operador ou um PDF assinado enviado pelo signatário. O estado do slot acompanha o fluxo e não é, por si só, uma verificação criptográfica. A assinatura eletrónica qualificada da ata, quando existe, aparece no topo deste painel, com certificado, data e digest.',
} as const;

export type EnvelopeSlotStatusCopyKey = keyof typeof envelopeSlotStatusPtPT;

export const envelopeSlotStatusEnglish = {
  'signing.envelopes.slot.status.signed.hint':
    '“Signature recorded” means the slot has evidence attached to a signature: a reference recorded by the operator, or a signed PDF uploaded by the signatory. The slot status tracks workflow and is not by itself a cryptographic verification. The qualified electronic signature of these minutes, where one exists, is shown at the top of this panel with its certificate, time and digest.',
} as const satisfies Record<EnvelopeSlotStatusCopyKey, string>;

export function useEnvelopeSlotStatusT(): (
  key: EnvelopeSlotStatusCopyKey,
  params?: TParams,
) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? envelopeSlotStatusPtPT : envelopeSlotStatusEnglish;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
