import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

const ptPT = {
  aria: 'Paginação da lista',
  previous: 'Página anterior',
  next: 'Página seguinte',
  range: 'Itens {from}–{to}',
  pageCount: '{count} itens nesta página',
} as const;

type CollectionPagerCopy = keyof typeof ptPT;

const english = {
  aria: 'List pagination',
  previous: 'Previous page',
  next: 'Next page',
  range: 'Items {from}–{to}',
  pageCount: '{count} items on this page',
} as const satisfies Record<CollectionPagerCopy, string>;

export function useCollectionPagerT(): (key: CollectionPagerCopy, params?: TParams) => string {
  const locale = useActiveLocale();
  const copy = locale === 'pt-PT' ? ptPT : english;
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
