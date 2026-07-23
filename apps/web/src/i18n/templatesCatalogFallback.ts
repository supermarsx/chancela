/**
 * Small, concurrency-safe copy surface for the template catalogue's origin filter and
 * read-only authored preview.
 *
 * The main locale catalogues are a shared integration hotspot. This follows the existing
 * template-editor fallback pattern: reviewed pt-PT copy, an English fallback for every other
 * locale, and the same `(key, params)` call shape as `useT`.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

export const templatesCatalogPtPT = {
  'templates.catalog.source.all': 'Todas as origens',
  'templates.catalog.preview.action': 'Pré-visualizar modelo',
  'templates.catalog.preview.title': 'Pré-visualização do modelo',
  'templates.catalog.preview.hint':
    'Esta leitura mostra a estrutura escrita no modelo. Os campos substituíveis permanecem visíveis tal como foram escritos e só recebem dados quando uma ata é gerada.',
  'templates.catalog.preview.narrative':
    'O corpo narrativo da ata é inserido aqui durante a geração.',
  'templates.catalog.preview.error.title': 'Não foi possível pré-visualizar o corpo',
  'templates.catalog.preview.error.body':
    'O compilador recusou o corpo guardado. O modelo não foi alterado; reveja o corpo no editor antes de o utilizar.',
} as const;

export type TemplatesCatalogCopyKey = keyof typeof templatesCatalogPtPT;

export const templatesCatalogEnglish = {
  'templates.catalog.source.all': 'All origins',
  'templates.catalog.preview.action': 'Preview template',
  'templates.catalog.preview.title': 'Template preview',
  'templates.catalog.preview.hint':
    'This read-only view shows the structure authored in the template. Replaceable fields remain visible exactly as written and only receive data when minutes are generated.',
  'templates.catalog.preview.narrative':
    'The minutes narrative body is inserted here during generation.',
  'templates.catalog.preview.error.title': 'The body could not be previewed',
  'templates.catalog.preview.error.body':
    'The compiler rejected the stored body. The template was not changed; review the body in the editor before using it.',
} as const satisfies Record<TemplatesCatalogCopyKey, string>;

export function useTemplatesCatalogCopy(): Record<TemplatesCatalogCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? templatesCatalogPtPT : templatesCatalogEnglish;
}

export function useTemplatesCatalogT(): (key: TemplatesCatalogCopyKey, params?: TParams) => string {
  const copy = useTemplatesCatalogCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
