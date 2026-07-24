/**
 * Focused copy for the stateless template PDF/A proof.
 *
 * Template authoring is still migrating into the shared locale catalogues. Keeping this small
 * reviewed pt-PT map beside an English fallback avoids widening that shared integration hotspot.
 */
import { useMemo } from 'react';
import { interpolate, type TParams } from './interpolate';
import { useActiveLocale } from './useT';

export const templatesPdfPreviewPtPT = {
  'templates.pdfPreview.title': 'Pré-visualização PDF/A estrutural',
  'templates.pdfPreview.description':
    'É um PDF/A real, mas não é uma ata final: não existe contexto de ata nesta página, por isso os campos substituíveis e as coleções permanecem visíveis por resolver.',
  'templates.pdfPreview.empty': 'Ainda não existe um rascunho válido para pré-visualizar.',
  'templates.pdfPreview.loading': 'A gerar a pré-visualização PDF/A…',
  'templates.pdfPreview.updating': 'A atualizar a pré-visualização PDF/A…',
  'templates.pdfPreview.lastGood':
    'É apresentada a última pré-visualização válida enquanto o rascunho atual é verificado.',
  'templates.pdfPreview.error.title': 'Não foi possível gerar a pré-visualização PDF/A',
  'templates.pdfPreview.retry': 'Tentar novamente',
  'templates.pdfPreview.open': 'Abrir PDF',
  'templates.pdfPreview.download': 'Descarregar PDF',
  'templates.pdfPreview.previous': 'Página anterior',
  'templates.pdfPreview.next': 'Página seguinte',
  'templates.pdfPreview.page': 'Página {current} de {total}',
  'templates.pdfPreview.canvas':
    'Página {current} de {total} da pré-visualização PDF/A estrutural. Use Abrir PDF para uma leitura acessível no visualizador instalado.',
} as const;

export type TemplatesPdfPreviewCopyKey = keyof typeof templatesPdfPreviewPtPT;

export const templatesPdfPreviewEnglish = {
  'templates.pdfPreview.title': 'Structural PDF/A preview',
  'templates.pdfPreview.description':
    'This is a real PDF/A, but not a final set of minutes: no act context exists on this page, so replaceable fields and collections remain visibly unresolved.',
  'templates.pdfPreview.empty': 'There is no valid draft to preview yet.',
  'templates.pdfPreview.loading': 'Generating the PDF/A preview…',
  'templates.pdfPreview.updating': 'Updating the PDF/A preview…',
  'templates.pdfPreview.lastGood':
    'The last valid preview remains visible while the current draft is checked.',
  'templates.pdfPreview.error.title': 'The PDF/A preview could not be generated',
  'templates.pdfPreview.retry': 'Try again',
  'templates.pdfPreview.open': 'Open PDF',
  'templates.pdfPreview.download': 'Download PDF',
  'templates.pdfPreview.previous': 'Previous page',
  'templates.pdfPreview.next': 'Next page',
  'templates.pdfPreview.page': 'Page {current} of {total}',
  'templates.pdfPreview.canvas':
    'Page {current} of {total} of the structural PDF/A preview. Use Open PDF for accessible reading in your installed viewer.',
} as const satisfies Record<TemplatesPdfPreviewCopyKey, string>;

export function useTemplatesPdfPreviewCopy(): Record<TemplatesPdfPreviewCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? templatesPdfPreviewPtPT : templatesPdfPreviewEnglish;
}

export function useTemplatesPdfPreviewT(): (
  key: TemplatesPdfPreviewCopyKey,
  params?: TParams,
) => string {
  const copy = useTemplatesPdfPreviewCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
