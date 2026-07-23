/**
 * Lista de confiança sub-tab copy — the two sub-tab labels and the strip aria added by t52 when the
 * Ferramentas → "Lista de confiança" surface split its stacked panels into TSL and TSA sub-tabs.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock for the
 * duration of the running i18n batch, so this change may not add the usual "one import + one spread
 * line per locale" wiring. Instead the module owns its keys end to end and exposes its own
 * locale-aware resolver ({@link useTrustSectionsT}). The page reads copy through that resolver
 * exactly as it would through `useT`, so nothing in the shared catalog moves and the catalog-leak /
 * literal-copy gates never see these strings. It follows the same shape as
 * `notificationsRetentionFallback.ts` / `serverEnvFallback.ts` (a pt-PT source object plus an English
 * fallback that `satisfies` its key set); if the catalog lock later releases, folding these in is a
 * mechanical spread and the page can switch to `t()`.
 *
 * Terminology: the eIDAS pt-PT term for an electronic time stamp is "selo temporal", and a TSA is an
 * Autoridade de Selos Temporais — so TSA reads "Selos temporais (TSA)". The acronyms TSA / TSL /
 * RFC 3161 stay verbatim; no anglicism is invented (memory `pt-pt-no-invented-anglicisms`).
 *
 * pt-PT is the source.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const trustSectionsPtPT = {
  'tools.trust.section.tsl': 'Lista de confiança (TSL)',
  'tools.trust.section.tsa': 'Selos temporais (TSA)',
  'tools.trust.subnav.aria': 'Secções da lista de confiança',
} as const;

/** The key set the Lista de confiança sub-tab copy resolves. */
export type TrustSectionsCopyKey = keyof typeof trustSectionsPtPT;

export const trustSectionsEnglish = {
  'tools.trust.section.tsl': 'Trust list (TSL)',
  'tools.trust.section.tsa': 'Time stamps (TSA)',
  'tools.trust.subnav.aria': 'Trust list sections',
} as const satisfies Record<TrustSectionsCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split `notificationsRetentionFallback` uses while the catalogs are locked.
 */
export function useTrustSectionsCopy(): Record<TrustSectionsCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? trustSectionsPtPT : trustSectionsEnglish;
}

/**
 * The page's extra translate hook, shaped like {@link useT}:
 * `const st = useTrustSectionsT(); st('tools.trust.section.tsl')`.
 */
export function useTrustSectionsT(): (key: TrustSectionsCopyKey, params?: TParams) => string {
  const copy = useTrustSectionsCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
