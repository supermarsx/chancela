import { useMemo } from 'react';
import { useActiveLocale } from '../i18n';

const dateInputPtPT = {
  'dateInput.today': 'Definir para hoje',
} as const;

type DateInputCopyKey = keyof typeof dateInputPtPT;

const dateInputEnglish = {
  'dateInput.today': 'Set to today',
} as const satisfies Record<DateInputCopyKey, string>;

/**
 * Small fallback catalog for the shared date primitive. The primary Portuguese locale gets native
 * copy; every other locale gets the English source sentence until the next full catalog pass.
 */
export function useDateInputT(): (key: DateInputCopyKey) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? dateInputPtPT : dateInputEnglish;
  return useMemo(() => (key) => copy[key], [copy]);
}
