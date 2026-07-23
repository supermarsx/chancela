/**
 * The compact metadata properties of a {@link TemplateSpec} — extracted so the full-page
 * create/fork surface and the full-width edit page cannot drift apart.
 *
 * This is markup and nothing else: no fetching, no submission, no ruling about which templates
 * may be edited. The caller owns the spec state and the write, because those differ between the
 * two surfaces — the create page POSTs a new template, the edit page PUTs an existing one whose id
 * is fixed.
 *
 * `law_references` are SERVER-DERIVED and therefore never authored here. Blocks are edited by
 * `TemplateBlocksEditor`; keeping them out of this component is what lets the page put authoring
 * and preview together on the first tab while these properties occupy their own compact table tab.
 */
import {
  LIFECYCLE_STAGES,
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
import { Field, Input, Select } from '../../ui';

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

// Template authoring currently accepts only pt-PT. The wider LOCALES catalog belongs to user and
// document settings; offering those values here guarantees a 422 from the template write API.
const AUTHORABLE_TEMPLATE_LOCALES = ['pt-PT'] as const;

export interface TemplateSpecFieldsProps {
  /** The scalar fields of the spec being authored. */
  spec: TemplateSpec;
  onSpecChange: (next: (current: TemplateSpec) => TemplateSpec) => void;
  /** The id is immutable once a template exists: a new id is a different template. */
  idLocked: boolean;
  /** Prefix for the generated control ids, so two mounts never collide. */
  idPrefix?: string;
}

export function TemplateSpecFields({
  spec,
  onSpecChange,
  idLocked,
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
    <div className="form field-table">
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
          options={AUTHORABLE_TEMPLATE_LOCALES.map((value) => ({
            value,
            label: localeLabels[value],
          }))}
          onChange={(event) =>
            onSpecChange((current) => ({ ...current, locale: event.target.value }))
          }
        />
      </Field>
    </div>
  );
}
