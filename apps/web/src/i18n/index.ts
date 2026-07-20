/**
 * Public i18n surface. Import from `../i18n` (or relative depth) app-wide:
 *
 *   import { useT } from '../../i18n';
 *   const t = useT();
 *   <h1>{t('entities.title')}</h1>
 *   <p>{t('cae.explorer.noResults.body', { term })}</p>
 *
 * `useLocale` gives the raw BCP-47 tag for `Intl` formatting (dates, numbers).
 */
export { useT, useActiveLocale, useActiveLocale as useLocale, t } from './useT';
export { interpolate } from './interpolate';
export type { TParams } from './interpolate';
export type { MessageKey, Catalog, TFunction } from './types';
export {
  SHIPPED_LOCALES,
  LOCALE_QUALITY,
  LOCALE_LOADERS,
  type TranslationQuality,
} from './registry';
export { i18nStore } from './store';
export { LABELLED_LEDGER_EVENT_KINDS } from './ledgerEventLabels';
