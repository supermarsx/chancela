/**
 * Template narrative-body editor copy (t56) — the WYSIWYG body surface and its live preview mounted
 * on the full-width template pages (`TemplateEditPage`, `TemplateCreatePage`): the body card title
 * and guidance, the side preview pane's title/hint/empty state, and the hint shown when a template's
 * blocks carry no `NarrativeBody` placement anchor (so the body would not reach the generated
 * document).
 *
 * **Why this module is self-contained, not folded into the catalogs.** The 14 locale catalogs
 * (`locales/*.ts` + `reviewedIdenticalValues.ts`) are edited additively by several in-flight tasks
 * under a shared lock, so t56's web copy owns its keys end to end and exposes its own locale-aware
 * resolver ({@link useTemplatesEditorT}). The pages read this copy through that resolver exactly as
 * they would through `useT`, so nothing in the shared catalog moves and the catalog-leak / literal-
 * copy gates never see these strings. It follows the shape of `actBodyFallback.ts` (a pt-PT source
 * object plus an English fallback that `satisfies` the key set); folding these into the catalogs
 * later is a mechanical spread.
 *
 * The reused strings — the page titles (`templates.editor.title.*`), the save/cancel actions
 * (`templates.actions.*`), the fork warnings (`templates.fork.*`) and the shared intro
 * (`templates.editor.intro`) — already live in all 14 catalogs and are read through `useT`; they are
 * NOT duplicated here. This module only adds the body-editor + preview chrome that did not exist.
 *
 * Copy rule: **no legal / evidentiary claim.** The body is where the author writes the template's
 * prose; the copy says what the field is and how its merge tags behave, never anything about "valor
 * probatório" (memory `tagline-no-valor-probatorio`). pt-PT is the source; no anglicisms — the term
 * for a template stays "modelo", matching the editor surfaces' existing vocabulary.
 */
import { useMemo } from 'react';
import { useActiveLocale } from './useT';
import { interpolate, type TParams } from './interpolate';

export const templatesEditorPtPT = {
  // — The narrative-body card (the WYSIWYG surface) ——————————————————————————————————
  'templates.editor.body.title': 'Corpo do modelo',
  'templates.editor.body.hint':
    'Escreva aqui o corpo da narrativa com formatação. Os campos substituíveis mantêm-se tal como os escreve e só são preenchidos quando uma ata é gerada a partir deste modelo.',

  // — The live side preview pane ———————————————————————————————————————————————————
  'templates.editor.preview.title': 'Pré-visualização do corpo',
  'templates.editor.preview.hint':
    'Os campos substituíveis aparecem tal como escritos; o preenchimento acontece na geração de uma ata, não aqui.',
  'templates.editor.preview.empty': 'Ainda não há corpo para pré-visualizar.',

  // — The no-anchor hint (the body has nowhere to render in this template) ——————————————
  'templates.editor.noAnchor.title': 'O corpo não será incluído no documento',
  'templates.editor.noAnchor.body':
    'Os blocos deste modelo não incluem um marcador de corpo da narrativa (um bloco NarrativeBody), por isso o texto acima não é inserido no documento gerado. Acrescente esse bloco aos blocos do modelo para o incluir.',
} as const;

/** The key set the template-editor body/preview copy resolves. */
export type TemplatesEditorCopyKey = keyof typeof templatesEditorPtPT;

export const templatesEditorEnglish = {
  'templates.editor.body.title': 'Template body',
  'templates.editor.body.hint':
    'Write the narrative body here, with formatting. Replaceable fields are kept exactly as you type them and are only filled in when a set of minutes is generated from this template.',

  'templates.editor.preview.title': 'Body preview',
  'templates.editor.preview.hint':
    'Replaceable fields appear exactly as written; they are filled in when minutes are generated, not here.',
  'templates.editor.preview.empty': 'There is no body to preview yet.',

  'templates.editor.noAnchor.title': 'The body will not be included in the document',
  'templates.editor.noAnchor.body':
    'This template’s blocks do not include a narrative-body placement marker (a NarrativeBody block), so the text above is not inserted into the generated document. Add that block to the template’s blocks to include it.',
} as const satisfies Record<TemplatesEditorCopyKey, string>;

/**
 * The active copy map: pt-PT gets the reviewed source strings, every other locale gets the English
 * fallback — the same split the sibling fallback modules use while off the shared catalog chain.
 */
export function useTemplatesEditorCopy(): Record<TemplatesEditorCopyKey, string> {
  const locale = useActiveLocale();
  return locale === 'pt-PT' ? templatesEditorPtPT : templatesEditorEnglish;
}

/**
 * The template body/preview translate hook, shaped like {@link useT}:
 * `const bt = useTemplatesEditorT(); bt('templates.editor.body.title')`.
 */
export function useTemplatesEditorT(): (key: TemplatesEditorCopyKey, params?: TParams) => string {
  const copy = useTemplatesEditorCopy();
  return useMemo(() => (key, params) => interpolate(copy[key], params), [copy]);
}
