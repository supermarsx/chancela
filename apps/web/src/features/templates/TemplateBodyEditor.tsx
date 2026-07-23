/**
 * TemplateBodyEditor — the template's narrative body as a WYSIWYG surface beside the complete
 * currently-authored template preview. Shared by create and edit so the two cannot drift.
 *
 * ## What this edits
 *
 * The NARRATIVE body only — the markdown seed that rides the `chancela.template-bundle` envelope as
 * `body_markdown` and is folded into the template's `default_body`. It is a pure consumer of the
 * ata's `MarkdownBodyEditor` (the t35/t74 ProseMirror surface whose schema IS the frozen block set,
 * so unsupported constructs are unrepresentable rather than rejected after the fact). The structured
 * `blocks[]` stays a separate structured editor — the WYSIWYG never touches it, because a
 * `BlockSpec[]` carries non-prose bindings markdown cannot represent.
 *
 * ## Preview is the server's, unresolved
 *
 * The preview pane renders the complete authored `TemplateBlockSpec[]` in order. At each
 * `NarrativeBody` marker it inserts ONLY the `Block[]` returned by the stateless
 * `POST /v1/templates/body/preview` compiler used by the seal path (debounced). Merge tags stay
 * literal because this stateless preview has no act context. A rejected body carries its server
 * diagnostic both into the editor and into the in-place preview error state.
 *
 * ## The no-anchor hint
 *
 * A body only reaches the generated document if the template's blocks carry a `NarrativeBody`
 * placement anchor (t35-e1). When they do not, the body is stored and round-tripped but never
 * rendered — so the author is told, next to the editor, rather than left to wonder why their prose
 * vanished from the output.
 */
import { useEffect, useState } from 'react';
import type { Block, TemplateSpec } from '../../api/types';
import { useTemplateBodyPreview } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { MarkdownBodyEditor, type MarkdownDiagnostic } from '../acts/MarkdownBodyEditor';
import { useActBodyT, bodyDiagnosticKey } from '../../i18n/actBodyFallback';
import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import { InlineWarning } from '../../ui';
import {
  TemplateAuthoredPreview,
  type TemplateNarrativePreviewState,
} from './TemplateAuthoredPreview';

/** The narrative-body byte ceiling — the server's cap for a template body seed (mirrors the ata). */
export const MAX_TEMPLATE_BODY_BYTES = 64 * 1024;

/**
 * Does the template place a narrative body? The `NarrativeBody` anchor (t35-e1) is a kind-tagged
 * fieldless block and is represented explicitly in the authored `TemplateBlockSpec` union.
 */
export function placesNarrativeBody(blocks: TemplateSpec['blocks']): boolean {
  return blocks.some((block) => block.kind === 'NarrativeBody');
}

export function TemplateBodyEditor({
  spec,
  value,
  onChange,
  disabled,
  idPrefix = 'tpl',
}: {
  /** The current spec — read only to check whether it places a narrative body. */
  spec: TemplateSpec;
  /** The narrative-body markdown (`body_markdown`), the WYSIWYG's source of truth. */
  value: string;
  onChange: (next: string) => void;
  /** True while the body is not editable (loading, or a non-user template). */
  disabled: boolean;
  /** Prefix for the editor's DOM id, so two mounts never collide. */
  idPrefix?: string;
}) {
  const bt = useTemplatesEditorT();
  const abt = useActBodyT();
  const preview = useTemplateBodyPreview();
  const mutatePreview = preview.mutate;
  const [compiled, setCompiled] = useState<{ source: string; blocks: Block[] } | null>(null);
  const [compileFailure, setCompileFailure] = useState<{
    source: string;
    diagnostic: string;
  } | null>(null);
  // Server-only verdict on the current source, when it refused to compile. The editor never
  // compiles content itself — this is populated from a `422` preview response and cleared on a clean
  // one, exactly as the ata body editor does (t35-e2).
  const [diagnostic, setDiagnostic] = useState<MarkdownDiagnostic | null>(null);

  const hasAnchor = placesNarrativeBody(spec.blocks);

  // Debounced stateless preview. The server compiles the SAME way it will at generation, so its
  // verdict — clean blocks or a rejected `{ code, offset }` — is what the document would carry; the
  // pane shows that rather than guessing. Suspended while the body is not editable.
  useEffect(() => {
    setDiagnostic(null);
    setCompileFailure(null);
    if (!value.trim()) {
      setCompiled(null);
      return;
    }
    if (disabled) {
      return;
    }
    const source = value;
    let active = true;
    const handle = window.setTimeout(() => {
      mutatePreview(
        { source },
        {
          onSuccess: (response) => {
            if (!active) return;
            setCompiled({ source, blocks: response.blocks });
            setCompileFailure(null);
            setDiagnostic(null);
          },
          onError: (err) => {
            if (!active) return;
            // A rejected body is a 422 with a byte offset; anything else (transport, 403) is not a
            // body rejection, so it leaves no spurious underline. The `construct` shown is a friendly
            // noun resolved from the server's machine `code`.
            if (err instanceof ApiError && err.status === 422 && err.offset != null) {
              setDiagnostic({ construct: abt(bodyDiagnosticKey(err.code)), offset: err.offset });
            } else {
              setDiagnostic(null);
            }
            setCompileFailure({
              source,
              diagnostic: err instanceof Error ? err.message : String(err),
            });
          },
        },
      );
    }, 400);
    return () => {
      active = false;
      window.clearTimeout(handle);
    };
  }, [abt, disabled, mutatePreview, value]);

  const narrative: TemplateNarrativePreviewState = !value.trim()
    ? { status: 'empty' }
    : compileFailure?.source === value
      ? { status: 'error', diagnostic: compileFailure.diagnostic }
      : compiled?.source === value
        ? { status: 'ready', blocks: compiled.blocks }
        : { status: 'loading' };

  return (
    <div className="stack--tight">
      <p className="field__hint">{bt('templates.editor.body.hint')}</p>

      {/* Stored and round-tripped, but it never reaches the document without a placement anchor —
          said here, next to the editor, so an author is not left wondering where the prose went. */}
      {!hasAnchor ? (
        <InlineWarning tone="info" title={bt('templates.editor.noAnchor.title')}>
          <p>{bt('templates.editor.noAnchor.body')}</p>
        </InlineWarning>
      ) : null}

      <div className="delib">
        <div className="delib__edit stack--tight">
          <MarkdownBodyEditor
            id={`${idPrefix}-body`}
            value={value}
            disabled={disabled}
            diagnostic={diagnostic}
            maxBytes={MAX_TEMPLATE_BODY_BYTES}
            onChange={onChange}
          />
        </div>
        <div className="delib__preview stack--tight">
          <p className="field__hint">{bt('templates.editor.preview.hint')}</p>
          <div className="preview template-editor__document-preview">
            <TemplateAuthoredPreview
              title={bt('templates.editor.preview.title')}
              templateId={spec.id}
              locale={spec.locale}
              blocks={spec.blocks}
              narrative={narrative}
            />
          </div>
        </div>
      </div>
    </div>
  );
}
