/**
 * Ata lifecycle REVERSE copy (t30) — the "Voltar" revert control, the guarded "Reabrir para
 * correção" control, their reason prompts and toasts.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are coordinated additively across several
 * in-flight tasks, so rather than take the "one import + one spread line per locale" wiring under a
 * shared lock, t30's web copy owns its keys end to end and exposes its own locale-aware resolver
 * ({@link useActLifecycleT}). `AtaEditorPage` reads this copy through that resolver exactly as it
 * would through `useT`, so nothing in the shared catalog moves and the catalog-leak / literal-copy
 * gates never see these strings. It follows the shape of `notificationsRetentionFallback.ts` and
 * `serverEnvFallback.ts` (a pt-PT source object plus an English fallback that `satisfies` the key
 * set); folding these into the catalogs later is a mechanical spread.
 *
 * Copy rule: **no legal / evidentiary claim.** A backward lifecycle move is workflow housekeeping —
 * the copy says what the operation does and that it is recorded in the history, never anything about
 * "valor probatório" (memory `tagline-no-valor-probatorio`). pt-PT is the source; no anglicisms.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const actLifecyclePtPT = {
  // — "Voltar": revert among the pre-signature drafting states (D1 = jump to any earlier) ————
  'acts.revert.button': 'Voltar',
  'acts.revert.title': 'Reverter a ata para um estado anterior',
  'acts.revert.body':
    'A ata regressa a um estado de elaboração anterior. Só recuam estados anteriores à recolha de assinaturas; nada assinado é afetado. O movimento fica registado no histórico.',
  'acts.revert.target.label': 'Estado de destino',
  'acts.revert.reason.label': 'Motivo',
  'acts.revert.reason.hint': 'Explique porque a ata recua. Fica registado no histórico.',
  'acts.revert.confirm': 'Reverter',
  'acts.reverting': 'A reverter…',

  // — "Reabrir para correção": the one guarded reverse edge, Signing → Texto aprovado ————————
  'acts.reopen.button': 'Reabrir para correção',
  'acts.reopen.title': 'Reabrir a ata para correção',
  'acts.reopen.body':
    'A ata sai da recolha de assinaturas e regressa a «Texto aprovado» para correção. Só é possível enquanto nenhuma assinatura tiver sido recolhida. O movimento fica registado no histórico.',
  'acts.reopen.reason.label': 'Motivo',
  'acts.reopen.reason.hint': 'Explique porque a ata é reaberta. Fica registado no histórico.',
  'acts.reopen.confirm': 'Reabrir',
  'acts.reopening': 'A reabrir…',

  // — Toasts ————————————————————————————————————————————————————————————————
  'toast.ata.reverted': 'Ata revertida para o estado anterior.',
  'toast.ata.reopened': 'Ata reaberta para correção.',
} as const;

/** The key set the ata reverse-lifecycle copy resolves. */
export type ActLifecycleCopyKey = keyof typeof actLifecyclePtPT;

export const actLifecycleEnglish = {
  'acts.revert.button': 'Go back',
  'acts.revert.title': 'Revert the minutes to an earlier state',
  'acts.revert.body':
    'The minutes return to an earlier drafting state. Only pre-signature states move back; nothing signed is affected. The move is recorded in the history.',
  'acts.revert.target.label': 'Target state',
  'acts.revert.reason.label': 'Reason',
  'acts.revert.reason.hint':
    'Explain why the minutes are moving back. It is recorded in the history.',
  'acts.revert.confirm': 'Revert',
  'acts.reverting': 'Reverting…',

  'acts.reopen.button': 'Reopen for correction',
  'acts.reopen.title': 'Reopen the minutes for correction',
  'acts.reopen.body':
    'The minutes leave signature collection and return to "Text approved" for correction. This is only possible while no signature has been collected. The move is recorded in the history.',
  'acts.reopen.reason.label': 'Reason',
  'acts.reopen.reason.hint': 'Explain why the minutes are reopened. It is recorded in the history.',
  'acts.reopen.confirm': 'Reopen',
  'acts.reopening': 'Reopening…',

  'toast.ata.reverted': 'Minutes reverted to the earlier state.',
  'toast.ata.reopened': 'Minutes reopened for correction.',
} as const satisfies Record<ActLifecycleCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useActLifecycleCopy(): Record<ActLifecycleCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? actLifecyclePtPT : actLifecycleEnglish;
}

/**
 * The page's reverse-lifecycle translate hook, shaped like {@link useT}:
 * `const rt = useActLifecycleT(); rt('acts.revert.button')`.
 */
export function useActLifecycleT(): (key: ActLifecycleCopyKey, params?: TParams) => string {
  const copy = useActLifecycleCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
