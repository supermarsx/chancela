/**
 * One lossless, document-oriented authoring flow for a template bundle.
 *
 * Shipped ATA templates carry their real prose in `spec.blocks`; `body_markdown` is frequently
 * empty. This component therefore renders the canonical block list first and mounts the existing
 * WYSIWYG exactly where the first NarrativeBody marker occurs. It never derives one authored half
 * from the other. The editable paper is the fast semi-preview; one real server-rendered proof
 * remains below it.
 */
import { useMemo, type ReactNode } from 'react';
import type { TemplateSpec } from '../../api/types';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import { InlineWarning } from '../../ui';
import {
  TemplateBlocksEditor,
  parseTemplateBlocksText,
  type NarrativeBodyPlacement,
} from './TemplateBlocksEditor';
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
  const parsed = useMemo(() => parseTemplateBlocksText(blocksText), [blocksText]);
  const parsedBlocks = parsed.blocks;
  const previewSpec = useMemo(
    () => (parsedBlocks ? { ...spec, blocks: parsedBlocks } : null),
    [parsedBlocks, spec],
  );
  const hasRenderableBodyPlacement = parsedBlocks !== null && placesNarrativeBody(parsedBlocks);

  const narrativeEditor = ({ index, occurrence, primary }: NarrativeBodyPlacement): ReactNode => {
    const editor = (
      <TemplateBodyEditor
        spec={spec}
        value={bodyMarkdown}
        onChange={onBodyChange}
        onAddBodyPlacement={onAddBodyPlacement}
        disabled={primary ? disabled : true}
        idPrefix={`${idPrefix}-narrative-${index}`}
        showPreview={false}
        showHeading={primary}
      />
    );

    if (primary) return editor;
    return (
      <section
        className="template-narrative-mirror"
        aria-label={bt('templates.editor.document.narrativeMirror', {
          occurrence,
          number: index + 1,
        })}
        data-template-narrative-mirror={occurrence}
      >
        <header className="template-narrative-mirror__heading">
          <strong>{bt('templates.editor.blocks.kind.narrativeBody')}</strong>
          <span aria-hidden="true">×{occurrence}</span>
        </header>
        {editor}
      </section>
    );
  };

  return (
    <section className="stack template-document-editor">
      <header className="stack--tight">
        <h3 className="panel__title">{bt('templates.editor.document.title')}</h3>
        <p className="field__hint">{bt('templates.editor.document.hint')}</p>
      </header>

      <div className="template-document-editor__canvas">
        <TemplateBlocksEditor
          value={blocksText}
          onChange={onBlocksChange}
          idPrefix={`${idPrefix}-blocks`}
          presentation="document"
          renderNarrativeBody={narrativeEditor}
          disabled={disabled}
        />
      </div>

      {/* Invalid Advanced JSON or a legacy block list without NarrativeBody must not make the
          authored body disappear. Keep it reachable and let its existing warning add the marker. */}
      {!hasRenderableBodyPlacement ? (
        <div className="template-document-editor__recovery">
          {narrativeEditor({ index: -1, occurrence: 1, primary: true })}
        </div>
      ) : null}

      {/* The paper is the fast semi-preview; this is the one authoritative rendered proof. Keep it
          full width and secondary, with its mutually exclusive PDF/Markdown tabs intact. */}
      <div className="template-document-editor__proof">
        {previewSpec ? (
          <TemplateBodyPreview
            spec={previewSpec}
            value={bodyMarkdown}
            idPrefix={`${idPrefix}-preview`}
          />
        ) : (
          <InlineWarning tone="warn" title={bt('templates.editor.blocks.raw.invalidJson')}>
            <p>{bt('templates.editor.preview.pausedInvalidBlocks')}</p>
          </InlineWarning>
        )}
      </div>
    </section>
  );
}
