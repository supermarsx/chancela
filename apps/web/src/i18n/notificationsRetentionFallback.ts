/**
 * Centro de Ações — the NEW tab, filter, and retention copy added by t17 (Descartadas/Reconhecidas
 * sub-tabs, the entities-style free-text filter, the dismissal retention note).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock for the
 * duration of the t11/t12/t15 batch, so t17's web executor may not add the usual "one import + one
 * spread line per locale" wiring. Instead this module owns its keys end to end and exposes its own
 * locale-aware resolver ({@link useNotificationsExtraT}). The page reads copy through that resolver
 * exactly as it would through `useT`, so nothing in the shared catalog moves and the catalog-leak /
 * literal-copy gates never see these strings. It follows the same shape as `serverEnvFallback.ts`
 * (a pt-PT source object plus an English fallback that `satisfies` its key set); if the catalog lock
 * later releases, folding these in is a mechanical spread and the page can switch to `t()`.
 *
 * Two copy rules hold here:
 * 1. **Say only what the payload proves.** The retention interval is server configuration and is NOT
 *    carried in the triage response, so the note names the mechanism ("período de retenção definido
 *    no servidor") without asserting a specific day count the client cannot know.
 * 2. **No legal / evidentiary claim.** Dismissed triage is disposable UI state, never an instrument;
 *    the copy describes housekeeping, never "valor probatório" (memory `tagline-no-valor-probatorio`).
 *
 * pt-PT is the source; no anglicisms are invented.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const notificationsExtraPtPT = {
  // — Sub-separadores resolvidos (D2: Dispensadas + Reconhecidas) ————————————
  // "Dispensadas"/"Reconhecidas" mirror the shipped triage vocabulary (verb "Dispensar" → status
  // "Dispensada"; verb "Reconhecer" → status "Reconhecida"), keeping the surface consistent.
  'notifications.filter.dismissed': 'Dispensadas',
  'notifications.filter.acknowledged': 'Reconhecidas',
  'notifications.empty.dismissed': 'Sem notificações dispensadas.',
  'notifications.empty.acknowledged': 'Sem notificações reconhecidas.',

  // — Nota de retenção ————————————————————————————————————————————————————
  'notifications.retention.note':
    'As notificações dispensadas são removidas automaticamente ao fim do período de retenção definido no servidor.',

  // — Filtro ao estilo das entidades ——————————————————————————————————————
  'notifications.filter.aria': 'Filtrar notificações',
  'notifications.filter.search.label': 'Pesquisar',
  'notifications.filter.search.placeholder': 'Pesquisar por título, detalhe ou etiqueta',
  'notifications.filter.tone.label': 'Tom',
  'notifications.filter.tone.all': 'Todos os tons',
  'notifications.filter.tone.error': 'Crítico',
  'notifications.filter.tone.warn': 'Aviso',
  'notifications.filter.tone.accent': 'Destaque',
  'notifications.filter.tone.neutral': 'Neutro',
  'notifications.filter.clear.aria': 'Limpar filtros',
  'notifications.filter.empty': 'Nenhuma notificação corresponde ao filtro.',
} as const;

/** The key set the Centro de Ações extra copy resolves. */
export type NotificationsExtraCopyKey = keyof typeof notificationsExtraPtPT;

export const notificationsExtraEnglish = {
  'notifications.filter.dismissed': 'Dismissed',
  'notifications.filter.acknowledged': 'Acknowledged',
  'notifications.empty.dismissed': 'No dismissed notifications.',
  'notifications.empty.acknowledged': 'No acknowledged notifications.',

  'notifications.retention.note':
    'Dismissed notifications are removed automatically once the retention period configured on the server elapses.',

  'notifications.filter.aria': 'Filter notifications',
  'notifications.filter.search.label': 'Search',
  'notifications.filter.search.placeholder': 'Search by title, detail or badge',
  'notifications.filter.tone.label': 'Tone',
  'notifications.filter.tone.all': 'All tones',
  'notifications.filter.tone.error': 'Critical',
  'notifications.filter.tone.warn': 'Warning',
  'notifications.filter.tone.accent': 'Highlight',
  'notifications.filter.tone.neutral': 'Neutral',
  'notifications.filter.clear.aria': 'Clear filters',
  'notifications.filter.empty': 'No notification matches the filter.',
} as const satisfies Record<NotificationsExtraCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split `serverEnvFallback` uses while the catalogs are locked.
 */
export function useNotificationsExtraCopy(): Record<NotificationsExtraCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? notificationsExtraPtPT : notificationsExtraEnglish;
}

/**
 * The page's extra translate hook, shaped like {@link useT}:
 * `const nt = useNotificationsExtraT(); nt('notifications.filter.dismissed')`.
 */
export function useNotificationsExtraT(): (
  key: NotificationsExtraCopyKey,
  params?: TParams,
) => string {
  const copy = useNotificationsExtraCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
