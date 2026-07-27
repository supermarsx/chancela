/**
 * Column headers for the legal-hold / disposal status table in Configurações → Privacidade
 * (`settings.privacy.legalHold.*`), added by t54-e3 when that panel's `<dl className="deflist">`
 * became a real `<Table>`.
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are held under a single-writer serial lock across
 * successive i18n batches, so t54 may not add the usual "one import + one spread line per locale"
 * wiring. This module owns its two keys end to end and exposes its own locale-aware resolver
 * ({@link usePrivacyLegalHoldT}), shaped exactly like `useT`. It follows
 * `notificationsRetentionFallback.ts`; if the catalog lock later releases, folding these in is a
 * mechanical spread and the panel can switch to `t()`.
 *
 * **Scope, deliberately two keys.** Only the column headers live here. The row labels
 * (`settings.privacy.legalHold.dl.*`) are already in the catalogs and stay there, and the three
 * `no_claims` flag identifiers are NOT copy at all — see the panel's own comment. Every locale here
 * carries its own correctly-inflected word; no anglicism is invented, and nothing is interpolated
 * into an inflected sentence (these are bare nouns).
 */
import { useMemo } from 'react';
import type { Locale } from '../api/types';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const privacyLegalHoldPtPT = {
  'settings.privacy.legalHold.column.indicator': 'Indicador',
  'settings.privacy.legalHold.column.value': 'Valor',
} as const;

/** The key set this module resolves. */
export type PrivacyLegalHoldCopyKey = keyof typeof privacyLegalHoldPtPT;

type PrivacyLegalHoldCopy = Record<PrivacyLegalHoldCopyKey, string>;

// en-US is the authoring source (t40); en-GB shares it — no divergent spelling in this key set.
export const privacyLegalHoldEnglish = {
  'settings.privacy.legalHold.column.indicator': 'Indicator',
  'settings.privacy.legalHold.column.value': 'Value',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldPtBR = {
  'settings.privacy.legalHold.column.indicator': 'Indicador',
  'settings.privacy.legalHold.column.value': 'Valor',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldEsES = {
  'settings.privacy.legalHold.column.indicator': 'Indicador',
  'settings.privacy.legalHold.column.value': 'Valor',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldFrFR = {
  'settings.privacy.legalHold.column.indicator': 'Indicateur',
  'settings.privacy.legalHold.column.value': 'Valeur',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldDeDE = {
  'settings.privacy.legalHold.column.indicator': 'Indikator',
  'settings.privacy.legalHold.column.value': 'Wert',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldItIT = {
  'settings.privacy.legalHold.column.indicator': 'Indicatore',
  'settings.privacy.legalHold.column.value': 'Valore',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldNlNL = {
  'settings.privacy.legalHold.column.indicator': 'Indicator',
  'settings.privacy.legalHold.column.value': 'Waarde',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldDaDK = {
  'settings.privacy.legalHold.column.indicator': 'Indikator',
  'settings.privacy.legalHold.column.value': 'Værdi',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldSvSE = {
  'settings.privacy.legalHold.column.indicator': 'Indikator',
  'settings.privacy.legalHold.column.value': 'Värde',
} as const satisfies PrivacyLegalHoldCopy;

// "Mittari" is the ordinary Finnish word for a measured indicator; the loan "indikaattori" would
// read as jargon here.
const privacyLegalHoldFiFI = {
  'settings.privacy.legalHold.column.indicator': 'Mittari',
  'settings.privacy.legalHold.column.value': 'Arvo',
} as const satisfies PrivacyLegalHoldCopy;

const privacyLegalHoldPlPL = {
  'settings.privacy.legalHold.column.indicator': 'Wskaźnik',
  'settings.privacy.legalHold.column.value': 'Wartość',
} as const satisfies PrivacyLegalHoldCopy;

/**
 * Per-locale copy. The map is deliberately complete, so every shipped locale renders its own words;
 * a locale absent here would fall through to the English source tier. sv-FI reuses sv-SE
 * (Finland-Swedish is orthographically identical for this key set).
 */
const PRIVACY_LEGAL_HOLD_BY_LOCALE: Partial<Record<Locale, PrivacyLegalHoldCopy>> = {
  'en-US': privacyLegalHoldEnglish,
  'en-GB': privacyLegalHoldEnglish,
  'pt-PT': privacyLegalHoldPtPT,
  'pt-BR': privacyLegalHoldPtBR,
  'es-ES': privacyLegalHoldEsES,
  'fr-FR': privacyLegalHoldFrFR,
  'de-DE': privacyLegalHoldDeDE,
  'it-IT': privacyLegalHoldItIT,
  'nl-NL': privacyLegalHoldNlNL,
  'da-DK': privacyLegalHoldDaDK,
  'sv-SE': privacyLegalHoldSvSE,
  'sv-FI': privacyLegalHoldSvSE,
  'fi-FI': privacyLegalHoldFiFI,
  'pl-PL': privacyLegalHoldPlPL,
};

/** The active copy map: the active locale's reviewed strings, or the English source tier. */
export function usePrivacyLegalHoldCopy(): PrivacyLegalHoldCopy {
  const locale = useActiveLocale();
  return PRIVACY_LEGAL_HOLD_BY_LOCALE[locale] ?? privacyLegalHoldEnglish;
}

/**
 * The panel's extra translate hook, shaped like {@link useT}:
 * `const lt = usePrivacyLegalHoldT(); lt('settings.privacy.legalHold.column.indicator')`.
 */
export function usePrivacyLegalHoldT(): (
  key: PrivacyLegalHoldCopyKey,
  params?: TParams,
) => string {
  const copy = usePrivacyLegalHoldCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
