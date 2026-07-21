/**
 * Create/edit form for a user-authored template (wp23-e6).
 *
 * Builds a {@link TemplateSpec} — the canonical authored body — from structured inputs and
 * `JSON.stringify`s it for `POST`/`PUT /v1/templates`. Every scalar field (id, family, stage,
 * channels, signature policy, rule pack, locale) is a labelled control with a FieldHelp "?"
 * tooltip resolved through the `templates.editor.field.*` catalog. The `blocks[]` array is edited
 * as canonical JSON in a textarea (the sanctioned fallback) so the editor never fabricates prose
 * for the kind-tagged block sub-fields that have no i18n keys; the server still validates every
 * block (`no_blocks` / `bad_template` / `unknown_threshold`), and those verdicts map back inline.
 *
 * `law_references` are SERVER-DERIVED and therefore never authored here. A template is a reusable
 * skeleton — it carries no legal-validity guarantee (see `templates.editor.intro`).
 *
 * **Scope narrowed in t109.** In-place editing of an existing user template now happens on
 * {@link ../templates/TemplateEditPage}, a full-width page, because a `BlockSpec[]` body does not
 * fit a dialog. This form is reached for `create` and `fork` — where the operator is naming and
 * classifying a template rather than writing its body. `mode: 'edit'` is still implemented and
 * correct, but no caller currently uses it; `useTemplateEditor` routes edits to the page.
 *
 * The field set itself lives in {@link ./TemplateSpecFields} so the two surfaces cannot drift.
 */
import { useRef, useState, type FormEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import type { TemplateBlockSpec, TemplateSpec } from '../../api/types';
import { useCreateTemplate, useUpdateTemplate } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT, type MessageKey } from '../../i18n';
import { Button, Icon, InlineWarning, useToast } from '../../ui';
import { useFocusTrap } from '../../ui/useFocusTrap';
import { TemplateSpecFields } from './TemplateSpecFields';

/**
 * The server's `422`/`409` error codes that carry a localized `templates.error.<code>` message.
 * A code outside this set (or an unexpected transport error) falls back to the server message so
 * nothing is ever swallowed.
 */
export const TEMPLATE_ERROR_CODES: ReadonlySet<string> = new Set([
  'too_large',
  'malformed',
  'invalid_id',
  'no_blocks',
  'bad_template',
  'unknown_threshold',
  'unsupported_locale',
  'conflict',
  'id_mismatch',
]);

/** Map a server error code to its localized message, falling back to the raw server text. */
export function mappedTemplateError(
  t: (key: MessageKey) => string,
  code: string | undefined,
  fallback: string,
): string {
  return code && TEMPLATE_ERROR_CODES.has(code)
    ? t(`templates.error.${code}` as MessageKey)
    : fallback;
}

/** A default authored spec for a brand-new template (a single empty paragraph block). */
function blankSpec(): TemplateSpec {
  return {
    id: '',
    family: 'CommercialCompany',
    stage: 'Ata',
    channels: [],
    signature_policy: 'QualifiedPreferred',
    rule_pack_id: '',
    blocks: [{ kind: 'Paragraph', template: '' }],
    locale: 'pt-PT',
  };
}

/** The shared modal chrome (matches `ConfirmActionModal`'s portal + focus-trap idiom). */
function TemplateModal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const trapRef = useFocusTrap<HTMLDivElement>(true);
  const titleId = useRef(`tpl-${Math.random().toString(36).slice(2)}`).current;
  return createPortal(
    <div className="modal-backdrop" onClick={onClose}>
      <div
        ref={trapRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(event) => event.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {title}
          </h2>
        </header>
        {children}
      </div>
    </div>,
    document.body,
  );
}

export interface TemplateEditorFormProps {
  /**
   * `fork` is a create in disguise: it POSTs a brand-new template whose body was copied from
   * another one. It exists as its own mode because it is the ONLY way to change a built-in,
   * and the operator has to be told what that copy can and cannot do before typing into it.
   */
  mode: 'create' | 'edit' | 'fork';
  /** The current spec to edit (fetched from the export endpoint); omitted for create. */
  initialSpec?: TemplateSpec | null;
  /** For `fork`: the id the body was copied from, echoed so the copy's origin stays visible. */
  sourceId?: string;
  /** For `fork`: whether that source was a built-in, which is why editing it made a copy. */
  sourceIsBuiltin?: boolean;
  onClose: () => void;
}

export function TemplateEditorForm({
  mode,
  initialSpec,
  sourceId,
  sourceIsBuiltin = false,
  onClose,
}: TemplateEditorFormProps) {
  const t = useT();
  const toast = useToast();
  const createTemplate = useCreateTemplate();
  const updateTemplate = useUpdateTemplate();

  const [spec, setSpec] = useState<TemplateSpec>(() => initialSpec ?? blankSpec());
  const [blocksText, setBlocksText] = useState(() =>
    JSON.stringify((initialSpec ?? blankSpec()).blocks, null, 2),
  );
  const [formError, setFormError] = useState<string | null>(null);

  const busy = createTemplate.isPending || updateTemplate.isPending;
  const canSubmit =
    spec.id.trim().length > 0 &&
    spec.rule_pack_id.trim().length > 0 &&
    blocksText.trim().length > 0;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy || !canSubmit) return;
    setFormError(null);

    let blocks: TemplateBlockSpec[];
    try {
      const parsed = JSON.parse(blocksText) as unknown;
      if (!Array.isArray(parsed) || parsed.length === 0) {
        setFormError(t('templates.error.no_blocks'));
        return;
      }
      blocks = parsed as TemplateBlockSpec[];
    } catch {
      setFormError(t('templates.error.malformed'));
      return;
    }

    const payload: TemplateSpec = {
      id: spec.id.trim(),
      family: spec.family,
      stage: spec.stage,
      channels: spec.channels,
      signature_policy: spec.signature_policy,
      rule_pack_id: spec.rule_pack_id.trim(),
      blocks,
      locale: spec.locale,
    };
    const rawJson = JSON.stringify(payload);

    try {
      if (mode !== 'edit') {
        const created = await createTemplate.mutateAsync(rawJson);
        toast.success(t('templates.toast.created', { id: created.id }));
      } else {
        const updated = await updateTemplate.mutateAsync({ id: payload.id, rawJson });
        toast.success(t('templates.toast.updated', { id: updated.id }));
      }
      onClose();
    } catch (err) {
      setFormError(
        mappedTemplateError(
          t,
          err instanceof ApiError ? err.code : undefined,
          err instanceof Error ? err.message : String(err),
        ),
      );
      toast.error(err);
    }
  }

  const title =
    mode === 'fork'
      ? t('templates.editor.title.fork')
      : mode === 'create'
        ? t('templates.editor.title.create')
        : t('templates.editor.title.edit');

  return (
    <TemplateModal title={title} onClose={onClose}>
      <form className="modal__body stack--tight" onSubmit={submit}>
        <p className="modal__intro field__hint">{t('templates.editor.intro')}</p>

        {/* Said HERE, before a single field is filled in — not at the sealing step, where it
            would arrive after the work rather than before it. */}
        {mode === 'fork' ? (
          <>
            {sourceIsBuiltin ? (
              <InlineWarning tone="info" title={t('templates.fork.builtin.title')}>
                <p>{t('templates.fork.builtin.body')}</p>
              </InlineWarning>
            ) : null}
            <InlineWarning tone="warn" title={t('templates.fork.limit.title')}>
              <p>{t('templates.fork.limit.body')}</p>
            </InlineWarning>
            {sourceId ? (
              <p className="field__hint">{t('templates.fork.source', { id: sourceId })}</p>
            ) : null}
          </>
        ) : null}

        <TemplateSpecFields
          spec={spec}
          onSpecChange={setSpec}
          blocksText={blocksText}
          onBlocksTextChange={setBlocksText}
          idLocked={mode === 'edit'}
        />

        {formError ? (
          <InlineWarning tone="error" title={t('templates.import.invalid')}>
            <p>{formError}</p>
          </InlineWarning>
        ) : null}

        <div className="modal__foot">
          <Button type="button" variant="ghost" disabled={busy} onClick={onClose}>
            {t('templates.actions.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.Save />}
            disabled={busy || !canSubmit}
          >
            {t('templates.actions.save')}
          </Button>
        </div>
      </form>
    </TemplateModal>
  );
}
