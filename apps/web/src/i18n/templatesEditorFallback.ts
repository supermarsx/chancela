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
  // — Authoring tabs ——————————————————————————————————————————————————————————————
  'templates.editor.tabs.aria': 'Secções do editor de modelos',
  'templates.editor.tabs.content': 'Editor e pré-visualização',
  'templates.editor.tabs.properties': 'Propriedades',
  'templates.editor.tabs.versions': 'Histórico de versões',
  'templates.editor.versions.restoreBlockedDirty':
    'Existem alterações locais por guardar. Guarde-as ou descarte-as antes de repor uma versão, para não perder trabalho.',

  // — Named saves ————————————————————————————————————————————————————————————————
  'templates.editor.saveName.label': 'Nome desta versão (opcional)',
  'templates.editor.saveName.hint':
    'Identifique esta gravação no histórico. Até 200 caracteres; deixe em branco para guardar sem nome.',
  'templates.editor.saveName.placeholder': 'Ex.: Revisão antes da assembleia',
  'templates.editor.saveName.tooLong': 'O nome não pode exceder 200 caracteres.',

  // — Structured block editor ——————————————————————————————————————————————————————
  'templates.editor.blocks.intro':
    'Construa o documento por blocos. Abra um bloco para editar os respetivos campos; a ordem apresentada é a ordem do documento.',
  'templates.editor.blocks.item': 'Bloco {number}',
  'templates.editor.blocks.kind': 'Tipo de bloco',
  'templates.editor.blocks.addKind': 'Tipo do novo bloco',
  'templates.editor.blocks.add': 'Adicionar bloco',
  'templates.editor.blocks.moveUp': 'Subir bloco',
  'templates.editor.blocks.moveDown': 'Descer bloco',
  'templates.editor.blocks.remove': 'Remover bloco',
  'templates.editor.blocks.changeKind.title': 'Alterar o tipo deste bloco?',
  'templates.editor.blocks.changeKind.intro':
    'Alterar de {from} para {to} remove todos os campos atuais deste bloco. A alteração só será aplicada depois de confirmar.',
  'templates.editor.blocks.changeKind.confirm': 'Alterar tipo',
  'templates.editor.blocks.changeKind.pending': 'A alterar…',
  'templates.editor.blocks.empty': 'Ainda não existem blocos.',
  'templates.editor.blocks.addRow': 'Adicionar linha',
  'templates.editor.blocks.removeRow': 'Remover linha',
  'templates.editor.blocks.raw.summary': 'JSON avançado',
  'templates.editor.blocks.raw.hint':
    'Use esta opção apenas quando precisar de um campo ainda não exposto no editor. O JSON é validado antes de voltar ao editor estruturado.',
  'templates.editor.blocks.raw.invalidJson': 'O JSON dos blocos não é válido.',
  'templates.editor.blocks.raw.notArray': 'O JSON tem de ser uma lista de blocos.',
  'templates.editor.blocks.raw.empty': 'O modelo tem de conter pelo menos um bloco.',
  'templates.editor.blocks.raw.unknownKind':
    'Existe um bloco com um tipo desconhecido. Corrija-o no JSON avançado.',
  'templates.editor.blocks.raw.invalidShape':
    'Um bloco tem campos em falta ou com um formato inválido. Corrija-o no JSON avançado.',
  'templates.editor.blocks.marker.pageBreak':
    'Força o conteúdo seguinte a começar numa nova página.',
  'templates.editor.blocks.marker.rule': 'Insere uma linha horizontal no documento.',
  'templates.editor.blocks.marker.narrativeBody':
    'Insere aqui o corpo narrativo escrito no editor e mostrado na pré-visualização.',

  'templates.editor.blocks.kind.heading': 'Título',
  'templates.editor.blocks.kind.paragraph': 'Parágrafo',
  'templates.editor.blocks.kind.keyValue': 'Tabela de propriedades',
  'templates.editor.blocks.kind.voteTable': 'Tabela de votação',
  'templates.editor.blocks.kind.signatureBlock': 'Assinaturas',
  'templates.editor.blocks.kind.pageBreak': 'Quebra de página',
  'templates.editor.blocks.kind.rule': 'Linha horizontal',
  'templates.editor.blocks.kind.narrativeBody': 'Corpo narrativo',

  'templates.editor.blocks.field.level': 'Nível do título',
  'templates.editor.blocks.field.template': 'Texto do modelo',
  'templates.editor.blocks.field.items': 'Lista de origem (opcional)',
  'templates.editor.blocks.field.rows': 'Linhas',
  'templates.editor.blocks.field.key': 'Rótulo',
  'templates.editor.blocks.field.value': 'Valor',
  'templates.editor.blocks.field.label': 'Rótulo de cada votação',
  'templates.editor.blocks.field.voteField': 'Campo da votação',
  'templates.editor.blocks.field.unanimousTotal': 'Total em unanimidade (opcional)',
  'templates.editor.blocks.field.source': 'Lista de signatários',
  'templates.editor.blocks.field.role': 'Modelo da qualidade',
  'templates.editor.blocks.field.name': 'Modelo do nome',

  // — The narrative-body card (the WYSIWYG surface) ——————————————————————————————————
  'templates.editor.body.title': 'Corpo do modelo',
  'templates.editor.body.hint':
    'Escreva aqui o corpo da narrativa com formatação. Os campos substituíveis mantêm-se tal como os escreve e só são preenchidos quando uma ata é gerada a partir deste modelo.',
  'templates.editor.body.editorLabel': 'Corpo narrativo do modelo',
  'templates.editor.body.toolbar.aria': 'Formatação do corpo narrativo',
  'templates.editor.body.toolbar.paragraph': 'Parágrafo',
  'templates.editor.body.toolbar.heading': 'Título de nível {level}',
  'templates.editor.body.toolbar.bold': 'Negrito',
  'templates.editor.body.toolbar.italic': 'Itálico',
  'templates.editor.body.toolbar.rule': 'Linha horizontal',
  'templates.editor.body.toolbar.undo': 'Desfazer',
  'templates.editor.body.toolbar.redo': 'Refazer',

  // — Document structure (secondary, under Properties) —————————————————————————————
  'templates.editor.structure.summary': 'Estrutura avançada do documento',
  'templates.editor.structure.hint':
    'Ajuste blocos estruturados, tabelas e marcadores de posição apenas quando o corpo narrativo não for suficiente.',

  // — The exclusive PDF / markdown preview surface —————————————————————————————————
  'templates.editor.preview.title': 'Pré-visualização do modelo',
  'templates.editor.preview.hint':
    'Escolha um formato de cada vez. A origem Markdown é o texto exato guardado; a vista PDF só será apresentada quando o PDF real estiver disponível.',
  'templates.editor.preview.empty': 'Ainda não há corpo para pré-visualizar.',
  'templates.editor.preview.tabs.aria': 'Formato da pré-visualização',
  'templates.editor.preview.tabs.pdf': 'PDF',
  'templates.editor.preview.tabs.markdown': 'Markdown',
  'templates.editor.preview.pdf.loading.title': 'A preparar a pré-visualização PDF',
  'templates.editor.preview.pdf.loading.body':
    'O PDF real está a ser gerado. Esta área não apresenta uma imitação em HTML.',
  'templates.editor.preview.pdf.unavailable.title': 'Pré-visualização PDF indisponível',
  'templates.editor.preview.pdf.unavailable.body':
    'O PDF real ainda não está disponível nesta sessão. Não é apresentada uma aproximação em HTML como se fosse o documento final.',
  'templates.editor.preview.markdown.note':
    'Esta vista mostra exatamente a origem body_markdown guardada. Não representa a paginação nem a aparência final do PDF.',
  'templates.editor.preview.markdown.sourceLabel': 'Origem body_markdown',
  'templates.editor.preview.markdown.copy': 'Copiar Markdown',
  'templates.editor.preview.markdown.copied': 'Markdown copiado',
  'templates.editor.preview.markdown.copyFailed': 'Não foi possível copiar o Markdown',

  // — The no-anchor hint (the body has nowhere to render in this template) ——————————————
  'templates.editor.noAnchor.title': 'O corpo não será incluído no documento',
  'templates.editor.noAnchor.body':
    'Os blocos deste modelo não incluem um marcador de corpo da narrativa (um bloco NarrativeBody), por isso o texto acima não é inserido no documento gerado. Acrescente esse bloco aos blocos do modelo para o incluir.',
  'templates.editor.noAnchor.add': 'Adicionar posição do corpo',
} as const;

/** The key set the template-editor body/preview copy resolves. */
export type TemplatesEditorCopyKey = keyof typeof templatesEditorPtPT;

export const templatesEditorEnglish = {
  'templates.editor.tabs.aria': 'Template editor sections',
  'templates.editor.tabs.content': 'Editor and preview',
  'templates.editor.tabs.properties': 'Properties',
  'templates.editor.tabs.versions': 'Version history',
  'templates.editor.versions.restoreBlockedDirty':
    'There are unsaved local changes. Save or discard them before restoring a version so no work is lost.',

  'templates.editor.saveName.label': 'Name this version (optional)',
  'templates.editor.saveName.hint':
    'Identify this save in the history. Up to 200 characters; leave blank to save without a name.',
  'templates.editor.saveName.placeholder': 'E.g. Review before the meeting',
  'templates.editor.saveName.tooLong': 'The name cannot be longer than 200 characters.',

  'templates.editor.blocks.intro':
    'Build the document from blocks. Open a block to edit its fields; the displayed order is the document order.',
  'templates.editor.blocks.item': 'Block {number}',
  'templates.editor.blocks.kind': 'Block type',
  'templates.editor.blocks.addKind': 'New block type',
  'templates.editor.blocks.add': 'Add block',
  'templates.editor.blocks.moveUp': 'Move block up',
  'templates.editor.blocks.moveDown': 'Move block down',
  'templates.editor.blocks.remove': 'Remove block',
  'templates.editor.blocks.changeKind.title': 'Change this block type?',
  'templates.editor.blocks.changeKind.intro':
    'Changing from {from} to {to} removes every current field in this block. The change is only applied after you confirm.',
  'templates.editor.blocks.changeKind.confirm': 'Change type',
  'templates.editor.blocks.changeKind.pending': 'Changing…',
  'templates.editor.blocks.empty': 'There are no blocks yet.',
  'templates.editor.blocks.addRow': 'Add row',
  'templates.editor.blocks.removeRow': 'Remove row',
  'templates.editor.blocks.raw.summary': 'Advanced JSON',
  'templates.editor.blocks.raw.hint':
    'Use this only when you need a field the structured editor does not expose yet. The JSON is validated before returning to the structured editor.',
  'templates.editor.blocks.raw.invalidJson': 'The block JSON is not valid.',
  'templates.editor.blocks.raw.notArray': 'The JSON must be a list of blocks.',
  'templates.editor.blocks.raw.empty': 'The template must contain at least one block.',
  'templates.editor.blocks.raw.unknownKind':
    'A block has an unknown type. Correct it in Advanced JSON.',
  'templates.editor.blocks.raw.invalidShape':
    'A block has missing or invalid fields. Correct it in Advanced JSON.',
  'templates.editor.blocks.marker.pageBreak': 'Starts the following content on a new page.',
  'templates.editor.blocks.marker.rule': 'Inserts a horizontal rule in the document.',
  'templates.editor.blocks.marker.narrativeBody':
    'Inserts the narrative body written in the editor and shown in the preview here.',

  'templates.editor.blocks.kind.heading': 'Heading',
  'templates.editor.blocks.kind.paragraph': 'Paragraph',
  'templates.editor.blocks.kind.keyValue': 'Properties table',
  'templates.editor.blocks.kind.voteTable': 'Vote table',
  'templates.editor.blocks.kind.signatureBlock': 'Signatures',
  'templates.editor.blocks.kind.pageBreak': 'Page break',
  'templates.editor.blocks.kind.rule': 'Horizontal rule',
  'templates.editor.blocks.kind.narrativeBody': 'Narrative body',

  'templates.editor.blocks.field.level': 'Heading level',
  'templates.editor.blocks.field.template': 'Template text',
  'templates.editor.blocks.field.items': 'Source list (optional)',
  'templates.editor.blocks.field.rows': 'Rows',
  'templates.editor.blocks.field.key': 'Label',
  'templates.editor.blocks.field.value': 'Value',
  'templates.editor.blocks.field.label': 'Vote row label',
  'templates.editor.blocks.field.voteField': 'Vote field',
  'templates.editor.blocks.field.unanimousTotal': 'Unanimous total (optional)',
  'templates.editor.blocks.field.source': 'Signatory list',
  'templates.editor.blocks.field.role': 'Capacity template',
  'templates.editor.blocks.field.name': 'Name template',

  'templates.editor.body.title': 'Template body',
  'templates.editor.body.hint':
    'Write the narrative body here, with formatting. Replaceable fields are kept exactly as you type them and are only filled in when a set of minutes is generated from this template.',
  'templates.editor.body.editorLabel': 'Template narrative body',
  'templates.editor.body.toolbar.aria': 'Narrative body formatting',
  'templates.editor.body.toolbar.paragraph': 'Paragraph',
  'templates.editor.body.toolbar.heading': 'Heading level {level}',
  'templates.editor.body.toolbar.bold': 'Bold',
  'templates.editor.body.toolbar.italic': 'Italic',
  'templates.editor.body.toolbar.rule': 'Horizontal rule',
  'templates.editor.body.toolbar.undo': 'Undo',
  'templates.editor.body.toolbar.redo': 'Redo',

  'templates.editor.structure.summary': 'Advanced document structure',
  'templates.editor.structure.hint':
    'Adjust structured blocks, tables, and placement markers only when the narrative body is not enough.',

  'templates.editor.preview.title': 'Template preview',
  'templates.editor.preview.hint':
    'Choose one format at a time. Markdown source is the exact stored text; the PDF view only appears when a real PDF is available.',
  'templates.editor.preview.empty': 'There is no body to preview yet.',
  'templates.editor.preview.tabs.aria': 'Preview format',
  'templates.editor.preview.tabs.pdf': 'PDF',
  'templates.editor.preview.tabs.markdown': 'Markdown',
  'templates.editor.preview.pdf.loading.title': 'Preparing the PDF preview',
  'templates.editor.preview.pdf.loading.body':
    'The real PDF is being generated. This area does not show an HTML imitation.',
  'templates.editor.preview.pdf.unavailable.title': 'PDF preview unavailable',
  'templates.editor.preview.pdf.unavailable.body':
    'The real PDF is not available in this session yet. An HTML approximation is not presented as the final document.',
  'templates.editor.preview.markdown.note':
    'This view shows the exact stored body_markdown source. It does not represent pagination or the final PDF appearance.',
  'templates.editor.preview.markdown.sourceLabel': 'body_markdown source',
  'templates.editor.preview.markdown.copy': 'Copy Markdown',
  'templates.editor.preview.markdown.copied': 'Markdown copied',
  'templates.editor.preview.markdown.copyFailed': 'Could not copy Markdown',

  'templates.editor.noAnchor.title': 'The body will not be included in the document',
  'templates.editor.noAnchor.body':
    'This template’s blocks do not include a narrative-body placement marker (a NarrativeBody block), so the text above is not inserted into the generated document. Add that block to the template’s blocks to include it.',
  'templates.editor.noAnchor.add': 'Add body placement',
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
