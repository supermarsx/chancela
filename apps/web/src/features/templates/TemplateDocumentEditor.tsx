/**
 * One lossless, document-oriented authoring flow for a template bundle.
 *
 * Shipped ATA templates carry their real prose in `spec.blocks`; `body_markdown` is frequently
 * empty. This component therefore renders the canonical block list first and mounts the existing
 * WYSIWYG exactly where the first NarrativeBody marker occurs. It never derives one authored half
 * from the other. The real PDF/Markdown preview follows the complete document flow once.
 */
import { useMemo } from 'react';
import type { TemplateSpec } from '../../api/types';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import { TemplateBlocksEditor, parseTemplateBlocksText } from './TemplateBlocksEditor';
import { TemplateBodyEditor, TemplateBodyPreview, placesNarrativeBody } from './TemplateBodyEditor';

export function TemplateDocumentEditor({
  spec,
  blocksText,
  onBlocksChange,
  bodyMarkdown,
  onBodyChange,
  onAddBodyPlacement,
  disabled,
  idPrefix,
}: {
  spec: TemplateSpec;
  blocksText: string;
  onBlocksChange: (next: string) => void;
  bodyMarkdown: string;
  onBodyChange: (next: string) => void;
  onAddBodyPlacement: () => void;
  disabled: boolean;
  idPrefix: string;
}) {
  const bt = useTemplatesEditorT();
  const parsedBlocks = useMemo(() => parseTemplateBlocksText(blocksText).blocks, [blocksText]);
  const hasRenderableBodyPlacement = parsedBlocks !== null && placesNarrativeBody(parsedBlocks);

  const narrativeEditor = () => (
    <TemplateBodyEditor
      spec={spec}
      value={bodyMarkdown}
      onChange={onBodyChange}
      onAddBodyPlacement={onAddBodyPlacement}
      disabled={disabled}
      idPrefix={`${idPrefix}-narrative`}
      showPreview={false}
    />
  );

  return (
    <section className="stack template-document-editor">
      <header className="stack--tight">
        <h3 className="panel__title">{bt('templates.editor.document.title')}</h3>
        <p className="field__hint">{bt('templates.editor.document.hint')}</p>
      </header>

      <TemplateBlocksEditor
        value={blocksText}
        onChange={onBlocksChange}
        idPrefix={`${idPrefix}-blocks`}
        presentation="document"
        renderNarrativeBody={narrativeEditor}
      />

      {/* Invalid Advanced JSON or a legacy block list without NarrativeBody must not make the
          authored body disappear. Keep it reachable and let its existing warning add the marker. */}
      {!hasRenderableBodyPlacement ? narrativeEditor() : null}

      <TemplateBodyPreview spec={spec} value={bodyMarkdown} idPrefix={`${idPrefix}-preview`} />
    </section>
  );
}
