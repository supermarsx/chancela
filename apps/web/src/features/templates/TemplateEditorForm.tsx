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
 */
import { useRef, useState, type FormEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import {
  LIFECYCLE_STAGES,
  LOCALES,
  MEETING_CHANNELS,
  type EntityFamily,
  type MeetingChannel,
  type SignaturePolicyHint,
  type TemplateBlockSpec,
  type TemplateSpec,
} from '../../api/types';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  localeLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import { useCreateTemplate, useUpdateTemplate } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT, type MessageKey } from '../../i18n';
import {
  Button,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  Select,
  TextArea,
  useToast,
} from '../../ui';
import { useFocusTrap } from '../../ui/useFocusTrap';

const ENTITY_FAMILIES: readonly EntityFamily[] = [
  'CommercialCompany',
  'Condominium',
  'Association',
  'Foundation',
  'Cooperative',
];

const SIGNATURE_POLICIES: readonly SignaturePolicyHint[] = [
  'QualifiedPreferred',
  'QualifiedOrHandwritten',
  'ManualAttested',
];

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
  mode: 'create' | 'edit';
  /** The current spec to edit (fetched from the export endpoint); omitted for create. */
  initialSpec?: TemplateSpec | null;
  onClose: () => void;
}

export function TemplateEditorForm({ mode, initialSpec, onClose }: TemplateEditorFormProps) {
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

  function toggleChannel(channel: MeetingChannel) {
    setSpec((current) => ({
      ...current,
      channels: current.channels.includes(channel)
        ? current.channels.filter((value) => value !== channel)
        : [...current.channels, channel],
    }));
  }

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
      if (mode === 'create') {
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
    mode === 'create' ? t('templates.editor.title.create') : t('templates.editor.title.edit');

  return (
    <TemplateModal title={title} onClose={onClose}>
      <form className="modal__body stack--tight" onSubmit={submit}>
        <p className="modal__intro field__hint">{t('templates.editor.intro')}</p>

        <Field
          label={t('templates.editor.field.id.label')}
          htmlFor="tpl-id"
          help={t('templates.editor.field.id.help')}
        >
          <Input
            id="tpl-id"
            value={spec.id}
            disabled={mode === 'edit'}
            placeholder={t('templates.editor.field.id.placeholder')}
            onChange={(event) => setSpec((current) => ({ ...current, id: event.target.value }))}
          />
        </Field>

        <Field
          label={t('templates.editor.field.family.label')}
          htmlFor="tpl-family"
          help={t('templates.editor.field.family.help')}
        >
          <Select
            id="tpl-family"
            value={spec.family}
            options={ENTITY_FAMILIES.map((value) => ({ value, label: entityFamilyLabels[value] }))}
            onChange={(event) =>
              setSpec((current) => ({ ...current, family: event.target.value as EntityFamily }))
            }
          />
        </Field>

        <Field
          label={t('templates.editor.field.stage.label')}
          htmlFor="tpl-stage"
          help={t('templates.editor.field.stage.help')}
        >
          <Select
            id="tpl-stage"
            value={spec.stage}
            options={LIFECYCLE_STAGES.map((value) => ({
              value,
              label: lifecycleStageLabels[value],
            }))}
            onChange={(event) =>
              setSpec((current) => ({
                ...current,
                stage: event.target.value as TemplateSpec['stage'],
              }))
            }
          />
        </Field>

        <Field
          label={t('templates.editor.field.channels.label')}
          help={t('templates.editor.field.channels.help')}
        >
          <div className="row-wrap">
            {MEETING_CHANNELS.map((channel) => (
              <label key={channel} className="checkline">
                <input
                  type="checkbox"
                  checked={spec.channels.includes(channel)}
                  onChange={() => toggleChannel(channel)}
                />
                {meetingChannelLabels[channel]}
              </label>
            ))}
          </div>
        </Field>

        <Field
          label={t('templates.editor.field.signaturePolicy.label')}
          htmlFor="tpl-signature"
          help={t('templates.editor.field.signaturePolicy.help')}
        >
          <Select
            id="tpl-signature"
            value={spec.signature_policy}
            options={SIGNATURE_POLICIES.map((value) => ({
              value,
              label: signaturePolicyLabels[value],
            }))}
            onChange={(event) =>
              setSpec((current) => ({
                ...current,
                signature_policy: event.target.value as SignaturePolicyHint,
              }))
            }
          />
        </Field>

        <Field
          label={t('templates.editor.field.rulePackId.label')}
          htmlFor="tpl-rule-pack"
          help={t('templates.editor.field.rulePackId.help')}
        >
          <Input
            id="tpl-rule-pack"
            value={spec.rule_pack_id}
            onChange={(event) =>
              setSpec((current) => ({ ...current, rule_pack_id: event.target.value }))
            }
          />
        </Field>

        <Field
          label={t('templates.editor.field.locale.label')}
          htmlFor="tpl-locale"
          help={t('templates.editor.field.locale.help')}
        >
          <Select
            id="tpl-locale"
            value={spec.locale}
            options={LOCALES.map((value) => ({ value, label: localeLabels[value] }))}
            onChange={(event) => setSpec((current) => ({ ...current, locale: event.target.value }))}
          />
        </Field>

        <div className="field">
          <span className="field__labelrow">
            <label className="field__label" htmlFor="tpl-blocks">
              {t('templates.editor.field.blocks.label')}
            </label>
            <FieldHelp text={t('templates.editor.field.blocks.help')} />
          </span>
          <TextArea
            id="tpl-blocks"
            className="mono"
            rows={12}
            value={blocksText}
            spellCheck={false}
            onChange={(event) => setBlocksText(event.target.value)}
          />
        </div>

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
