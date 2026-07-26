/**
 * TemplateBodyEditor — the template's primary narrative authoring surface.
 *
 * The ProseMirror editor owns only `body_markdown`; the surrounding document editor owns the
 * ordered `blocks[]` and mounts this surface at its `NarrativeBody` placement marker. A template
 * still needs that explicit marker to place this prose, so older templates without it get both an
 * honest warning and a direct recovery action.
 *
 * Preview is deliberately exclusive: either the real stateless PDF/A document or the complete
 * server-rendered Markdown document is mounted, both resolved from the same sample record.
 */
import { useEffect, useId, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';
import type { TemplateSpec } from '../../api/types';
import { useTemplateBodyPreview } from '../../api/hooks';
import { ApiError } from '../../api/client';
import {
  MarkdownBodyEditor,
  type MarkdownBodyToolbarLabels,
  type MarkdownDiagnostic,
} from '../acts/MarkdownBodyEditor';
import { useActBodyT, bodyDiagnosticKey } from '../../i18n/actBodyFallback';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import { Button, Icon, InlineWarning } from '../../ui';
import { TemplateMarkdownPreview } from './TemplateMarkdownPreview';
import { TemplatePdfPreview } from './TemplatePdfPreview';

/** The narrative-body byte ceiling — the server's cap for a template body seed (mirrors the ata). */
export const MAX_TEMPLATE_BODY_BYTES = 64 * 1024;

/** Does the structured document include the marker that places `body_markdown`? */
export function placesNarrativeBody(blocks: TemplateSpec['blocks']): boolean {
  return blocks.some((block) => block.kind === 'NarrativeBody');
}

type PreviewMode = 'pdf' | 'markdown';

export function TemplateBodyEditor({
  spec,
  value,
  onChange,
  onAddBodyPlacement,
  disabled,
  idPrefix = 'tpl',
  showPreview = true,
  showHeading = true,
}: {
  /** The current spec is read only to check whether it places the narrative body. */
  spec: TemplateSpec;
  /** The narrative-body markdown (`body_markdown`), the WYSIWYG's source of truth. */
  value: string;
  onChange: (next: string) => void;
  /** Adds a `NarrativeBody` marker without sending the operator hunting through raw JSON. */
  onAddBodyPlacement?: () => void;
  /** True while the body is not editable (loading, or a non-user template). */
  disabled: boolean;
  /** Prefix for the editor's DOM id, so two mounts never collide. */
  idPrefix?: string;
  /** The document editor mounts the shared preview once, after the complete ordered block flow. */
  showPreview?: boolean;
  /** Embedded read-only placement mirrors provide their own compact heading. */
  showHeading?: boolean;
}) {
  const bt = useTemplatesEditorT();
  const abt = useActBodyT();
  const previewValidation = useTemplateBodyPreview();
  const mutatePreview = previewValidation.mutate;
  const [diagnostic, setDiagnostic] = useState<MarkdownDiagnostic | null>(null);
  const hasAnchor = placesNarrativeBody(spec.blocks);

  // Keep the existing server-authoritative validation loop even though its old HTML rendering is
  // gone. A 422 still points at the exact rejected source offset in the visual editor.
  useEffect(() => {
    setDiagnostic(null);
    if (!value.trim() || disabled) return;
    const source = value;
    let active = true;
    const handle = window.setTimeout(() => {
      mutatePreview(
        { source },
        {
          onSuccess: () => {
            if (active) setDiagnostic(null);
          },
          onError: (err) => {
            if (!active) return;
            setDiagnostic(
              err instanceof ApiError && err.status === 422 && err.offset != null
                ? { construct: abt(bodyDiagnosticKey(err.code)), offset: err.offset }
                : null,
            );
          },
        },
      );
    }, 400);
    return () => {
      active = false;
      window.clearTimeout(handle);
    };
  }, [abt, disabled, mutatePreview, value]);

  const toolbarLabels: MarkdownBodyToolbarLabels = {
    ariaLabel: bt('templates.editor.body.toolbar.aria'),
    editor: bt('templates.editor.body.editorLabel'),
    paragraph: bt('templates.editor.body.toolbar.paragraph'),
    headings: [
      bt('templates.editor.body.toolbar.heading', { level: 1 }),
      bt('templates.editor.body.toolbar.heading', { level: 2 }),
      bt('templates.editor.body.toolbar.heading', { level: 3 }),
      bt('templates.editor.body.toolbar.heading', { level: 4 }),
      bt('templates.editor.body.toolbar.heading', { level: 5 }),
      bt('templates.editor.body.toolbar.heading', { level: 6 }),
    ],
    bold: bt('templates.editor.body.toolbar.bold'),
    italic: bt('templates.editor.body.toolbar.italic'),
    horizontalRule: bt('templates.editor.body.toolbar.rule'),
    undo: bt('templates.editor.body.toolbar.undo'),
    redo: bt('templates.editor.body.toolbar.redo'),
  };

  return (
    <section className="stack template-body-composer">
      <div className="stack--tight template-body-composer__editor">
        {showHeading ? (
          <>
            <h3 className="panel__title">{bt('templates.editor.body.title')}</h3>
            <p className="field__hint">{bt('templates.editor.body.hint')}</p>
          </>
        ) : null}

        {!hasAnchor ? (
          <InlineWarning tone="info" title={bt('templates.editor.noAnchor.title')}>
            <p>{bt('templates.editor.noAnchor.body')}</p>
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              disabled={disabled || !onAddBodyPlacement}
              onClick={onAddBodyPlacement}
            >
              {bt('templates.editor.noAnchor.add')}
            </Button>
          </InlineWarning>
        ) : null}

        <MarkdownBodyEditor
          id={`${idPrefix}-body`}
          ariaLabel={bt('templates.editor.body.editorLabel')}
          toolbarLabels={toolbarLabels}
          value={value}
          disabled={disabled}
          diagnostic={diagnostic}
          maxBytes={MAX_TEMPLATE_BODY_BYTES}
          onChange={onChange}
        />
      </div>

      {showPreview ? <TemplateBodyPreview spec={spec} value={value} idPrefix={idPrefix} /> : null}
    </section>
  );
}

/**
 * The one preview belonging to the complete document flow. Keeping it separate lets
 * `TemplateDocumentEditor` place the WYSIWYG at NarrativeBody while the preview remains below the
 * whole authored document instead of appearing as a second editor column or halfway through it.
 */
export function TemplateBodyPreview({
  spec,
  value,
  idPrefix = 'tpl',
}: {
  spec: TemplateSpec;
  value: string;
  idPrefix?: string;
}) {
  const bt = useTemplatesEditorT();
  const [previewMode, setPreviewMode] = useState<PreviewMode>('pdf');
  const previewId = useId();
  const request = { source: 'draft' as const, spec, body_markdown: value };
  const previewModes: PreviewMode[] = ['pdf', 'markdown'];

  function handlePreviewTabKeyDown(
    event: ReactKeyboardEvent<HTMLButtonElement>,
    mode: PreviewMode,
  ) {
    let nextIndex: number | null = null;
    const currentIndex = previewModes.indexOf(mode);
    if (event.key === 'ArrowRight') nextIndex = (currentIndex + 1) % previewModes.length;
    if (event.key === 'ArrowLeft')
      nextIndex = (currentIndex - 1 + previewModes.length) % previewModes.length;
    if (event.key === 'Home') nextIndex = 0;
    if (event.key === 'End') nextIndex = previewModes.length - 1;
    if (nextIndex === null) return;

    event.preventDefault();
    setPreviewMode(previewModes[nextIndex]);
    const tabs =
      event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    tabs?.[nextIndex]?.focus();
  }

  return (
    <section className="stack--tight template-preview" aria-labelledby={`${previewId}-title`}>
      <div className="template-preview__heading">
        <div>
          <h3 className="panel__title" id={`${previewId}-title`}>
            {bt('templates.editor.preview.title')}
          </h3>
        </div>
        <div
          className="template-preview__tabs"
          role="tablist"
          aria-label={bt('templates.editor.preview.tabs.aria')}
        >
          {previewModes.map((mode) => (
            <button
              key={mode}
              id={`${previewId}-${mode}-tab`}
              type="button"
              role="tab"
              className={previewMode === mode ? 'is-active' : undefined}
              aria-selected={previewMode === mode}
              aria-controls={`${previewId}-${mode}-panel`}
              tabIndex={previewMode === mode ? 0 : -1}
              onClick={() => setPreviewMode(mode)}
              onKeyDown={(event) => handlePreviewTabKeyDown(event, mode)}
            >
              {bt(
                mode === 'pdf'
                  ? 'templates.editor.preview.tabs.pdf'
                  : 'templates.editor.preview.tabs.markdown',
              )}
            </button>
          ))}
        </div>
      </div>

      {previewMode === 'pdf' ? (
        <div
          id={`${previewId}-pdf-panel`}
          className="template-preview__panel"
          role="tabpanel"
          aria-labelledby={`${previewId}-pdf-tab`}
        >
          <TemplatePdfPreview
            request={request}
            idPrefix={`${idPrefix}-pdf`}
            downloadFilename={`${spec.id || 'template'}-preview.pdf`}
          />
        </div>
      ) : (
        <div
          id={`${previewId}-markdown-panel`}
          className="template-preview__panel stack--tight"
          role="tabpanel"
          aria-labelledby={`${previewId}-markdown-tab`}
        >
          <TemplateMarkdownPreview request={request} idPrefix={`${idPrefix}-markdown`} />
        </div>
      )}
    </section>
  );
}
