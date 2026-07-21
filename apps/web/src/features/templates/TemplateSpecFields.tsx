/**
 * The authored fields of a {@link TemplateSpec} — extracted so the modal (create/fork) and the
 * full-width edit page cannot drift apart (t109).
 *
 * This is markup and nothing else: no fetching, no submission, no ruling about which templates
 * may be edited. The caller owns the spec state and the write, because those differ between the
 * two surfaces — the modal POSTs a new template, the page PUTs an existing one whose id is fixed.
 *
 * `law_references` are SERVER-DERIVED and therefore never authored here.
 *
 * ## Why `blocks` is still a JSON textarea and not a WYSIWYG
 *
 * A template body is **not markdown**. It is `Vec<BlockSpec>` — kind-tagged blocks
 * (`Heading`, `Paragraph`, `KeyValue`, `VoteTable`, `SignatureBlock`, `PageBreak`, `Rule`,
 * `chancela-templates/src/lib.rs:179`) carrying minijinja in their text fields plus non-text
 * bindings a document has no prose form for: `items` loop paths, `vote_field`,
 * `unanimous_total`, `KvRowSpec` pairs. The app's ProseMirror WYSIWYG
 * (`features/acts/MarkdownBodyEditor`) edits a **markdown string** — the ata's narrative body —
 * and markdown cannot represent any of the above. Pointing it at a spec would require a lossy
 * markdown⇄BlockSpec mapping whose failure mode is silently dropping a `VoteTable` from a legal
 * instrument. Canonical JSON is the honest surface until a block-structured editor exists; the
 * server still validates every block (`no_blocks` / `bad_template` / `unknown_threshold`).
 */
import {
  LIFECYCLE_STAGES,
  LOCALES,
  MEETING_CHANNELS,
  type EntityFamily,
  type MeetingChannel,
  type SignaturePolicyHint,
  type TemplateSpec,
} from '../../api/types';
import {
  entityFamilyLabels,
  lifecycleStageLabels,
  localeLabels,
  meetingChannelLabels,
  signaturePolicyLabels,
} from '../../api/labels';
import { useT } from '../../i18n';
import { Field, FieldHelp, Input, Select, TextArea } from '../../ui';

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

export interface TemplateSpecFieldsProps {
  /** The scalar fields of the spec being authored. */
  spec: TemplateSpec;
  onSpecChange: (next: (current: TemplateSpec) => TemplateSpec) => void;
  /** The `blocks[]` array as canonical JSON text — kept as text so a half-typed edit survives. */
  blocksText: string;
  onBlocksTextChange: (next: string) => void;
  /** The id is immutable once a template exists: a new id is a different template. */
  idLocked: boolean;
  /** How tall the blocks textarea should be — the page gives it far more room than the modal. */
  blocksRows?: number;
  /** Prefix for the generated control ids, so two mounts never collide. */
  idPrefix?: string;
}

export function TemplateSpecFields({
  spec,
  onSpecChange,
  blocksText,
  onBlocksTextChange,
  idLocked,
  blocksRows = 12,
  idPrefix = 'tpl',
}: TemplateSpecFieldsProps) {
  const t = useT();

  function toggleChannel(channel: MeetingChannel) {
    onSpecChange((current) => ({
      ...current,
      channels: current.channels.includes(channel)
        ? current.channels.filter((value) => value !== channel)
        : [...current.channels, channel],
    }));
  }

  return (
    <>
      <Field
        label={t('templates.editor.field.id.label')}
        htmlFor={`${idPrefix}-id`}
        help={t('templates.editor.field.id.help')}
      >
        <Input
          id={`${idPrefix}-id`}
          value={spec.id}
          disabled={idLocked}
          placeholder={t('templates.editor.field.id.placeholder')}
          onChange={(event) => onSpecChange((current) => ({ ...current, id: event.target.value }))}
        />
      </Field>

      <Field
        label={t('templates.editor.field.family.label')}
        htmlFor={`${idPrefix}-family`}
        help={t('templates.editor.field.family.help')}
      >
        <Select
          id={`${idPrefix}-family`}
          value={spec.family}
          options={ENTITY_FAMILIES.map((value) => ({ value, label: entityFamilyLabels[value] }))}
          onChange={(event) =>
            onSpecChange((current) => ({ ...current, family: event.target.value as EntityFamily }))
          }
        />
      </Field>

      <Field
        label={t('templates.editor.field.stage.label')}
        htmlFor={`${idPrefix}-stage`}
        help={t('templates.editor.field.stage.help')}
      >
        <Select
          id={`${idPrefix}-stage`}
          value={spec.stage}
          options={LIFECYCLE_STAGES.map((value) => ({
            value,
            label: lifecycleStageLabels[value],
          }))}
          onChange={(event) =>
            onSpecChange((current) => ({
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
        htmlFor={`${idPrefix}-signature`}
        help={t('templates.editor.field.signaturePolicy.help')}
      >
        <Select
          id={`${idPrefix}-signature`}
          value={spec.signature_policy}
          options={SIGNATURE_POLICIES.map((value) => ({
            value,
            label: signaturePolicyLabels[value],
          }))}
          onChange={(event) =>
            onSpecChange((current) => ({
              ...current,
              signature_policy: event.target.value as SignaturePolicyHint,
            }))
          }
        />
      </Field>

      <Field
        label={t('templates.editor.field.rulePackId.label')}
        htmlFor={`${idPrefix}-rule-pack`}
        help={t('templates.editor.field.rulePackId.help')}
      >
        <Input
          id={`${idPrefix}-rule-pack`}
          value={spec.rule_pack_id}
          onChange={(event) =>
            onSpecChange((current) => ({ ...current, rule_pack_id: event.target.value }))
          }
        />
      </Field>

      <Field
        label={t('templates.editor.field.locale.label')}
        htmlFor={`${idPrefix}-locale`}
        help={t('templates.editor.field.locale.help')}
      >
        <Select
          id={`${idPrefix}-locale`}
          value={spec.locale}
          options={LOCALES.map((value) => ({ value, label: localeLabels[value] }))}
          onChange={(event) =>
            onSpecChange((current) => ({ ...current, locale: event.target.value }))
          }
        />
      </Field>

      <div className="field">
        <span className="field__labelrow">
          <label className="field__label" htmlFor={`${idPrefix}-blocks`}>
            {t('templates.editor.field.blocks.label')}
          </label>
          <FieldHelp text={t('templates.editor.field.blocks.help')} />
        </span>
        <TextArea
          id={`${idPrefix}-blocks`}
          className="mono"
          rows={blocksRows}
          value={blocksText}
          spellCheck={false}
          onChange={(event) => onBlocksTextChange(event.target.value)}
        />
      </div>
    </>
  );
}
