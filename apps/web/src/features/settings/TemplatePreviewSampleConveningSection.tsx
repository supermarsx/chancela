import {
  DISPATCH_CHANNELS,
  type DispatchChannel,
  type SignatoryCapacity,
  type TemplatePreviewRecipient,
} from '../../api/types';
import { dispatchChannelLabels, optionsFrom, signatoryCapacityLabels } from '../../api/labels';
import { useTemplatePreviewSamplesT } from '../../i18n/templatePreviewSamplesFallback';
import { Card, Toggle } from '../../ui';
import {
  ALL_TEMPLATE_PREVIEW_CAPACITIES,
  NumberSetting,
  SampleCollectionTable,
  SelectSetting,
  TextSetting,
} from './templatePreviewSamplesEditorParts';
import type { TemplatePreviewSampleSectionProps } from './templatePreviewSampleSectionTypes';
import {
  isTemplatePreviewContactText,
  isTemplatePreviewIsoDate,
  isTemplatePreviewShortText,
} from './templatePreviewSamplesModel';

export function TemplatePreviewSampleConveningSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <Card title={tt('templatePreview.card.convening')}>
        <div className="form settings-rows">
          <TextSetting
            id="template-preview-convener"
            label={tt('templatePreview.field.convener')}
            value={value.convening.convener}
            disabled={!canEdit}
            onChange={(convener) => update('convening', { ...value.convening, convener })}
          />
          <SelectSetting<SignatoryCapacity>
            id="template-preview-convener-capacity"
            label={tt('templatePreview.field.convener_capacity')}
            value={value.convening.convener_capacity}
            options={optionsFrom(ALL_TEMPLATE_PREVIEW_CAPACITIES, signatoryCapacityLabels)}
            disabled={!canEdit}
            onChange={(convener_capacity) =>
              update('convening', { ...value.convening, convener_capacity })
            }
          />
          <TextSetting
            id="template-preview-dispatch-date"
            type="date"
            label={tt('templatePreview.field.dispatch_date')}
            value={value.convening.dispatch_date}
            disabled={!canEdit}
            onChange={(dispatch_date) => update('convening', { ...value.convening, dispatch_date })}
          />
          <NumberSetting
            id="template-preview-antecedence"
            label={tt('templatePreview.field.antecedence_days')}
            value={value.convening.antecedence_days}
            min={0}
            max={3_650}
            disabled={!canEdit}
            onChange={(antecedence_days) =>
              update('convening', { ...value.convening, antecedence_days })
            }
          />
          <SelectSetting<DispatchChannel>
            id="template-preview-dispatch-channel"
            label={tt('templatePreview.field.channel')}
            value={value.convening.channel}
            options={optionsFrom(DISPATCH_CHANNELS, dispatchChannelLabels)}
            disabled={!canEdit}
            onChange={(channel) => update('convening', { ...value.convening, channel })}
          />
          <TextSetting
            id="template-preview-second-call-date"
            type="date"
            label={tt('templatePreview.field.second_call_date')}
            value={value.convening.second_call.date}
            disabled={!canEdit}
            onChange={(date) =>
              update('convening', {
                ...value.convening,
                second_call: { ...value.convening.second_call, date },
              })
            }
          />
          <TextSetting
            id="template-preview-second-call-time"
            type="time"
            label={tt('templatePreview.field.second_call_time')}
            value={value.convening.second_call.time}
            disabled={!canEdit}
            onChange={(time) =>
              update('convening', {
                ...value.convening,
                second_call: { ...value.convening.second_call, time },
              })
            }
          />
          <Toggle
            label={tt('templatePreview.field.reduced_quorum')}
            checked={value.convening.second_call.reduced_quorum}
            disabled={!canEdit}
            onChange={(reduced_quorum) =>
              update('convening', {
                ...value.convening,
                second_call: { ...value.convening.second_call, reduced_quorum },
              })
            }
          />
        </div>
      </Card>
      <SampleCollectionTable<TemplatePreviewRecipient>
        title={tt('templatePreview.collection.recipients')}
        rows={value.convening.recipients}
        columns={[
          { label: tt('templatePreview.column.name'), render: (row) => row.name },
          {
            label: tt('templatePreview.column.details'),
            render: (row) => `${dispatchChannelLabels[row.channel]} · ${row.reference}`,
          },
        ]}
        createRow={() => ({
          name: '',
          contact: '',
          channel: 'Email',
          reference: '',
          dispatched_at: value.convening.dispatch_date,
        })}
        validateRow={(row) =>
          isTemplatePreviewShortText(row.name) &&
          isTemplatePreviewContactText(row.contact) &&
          isTemplatePreviewShortText(row.reference) &&
          isTemplatePreviewIsoDate(row.dispatched_at)
        }
        renderEditor={(row, setRow) => (
          <>
            <TextSetting
              id="template-preview-recipient-name"
              label={tt('templatePreview.column.name')}
              value={row.name}
              onChange={(name) => setRow({ ...row, name })}
            />
            <TextSetting
              id="template-preview-recipient-contact"
              label={tt('templatePreview.field.contact')}
              value={row.contact}
              maxLength={500}
              onChange={(contact) => setRow({ ...row, contact })}
            />
            <SelectSetting<DispatchChannel>
              id="template-preview-recipient-channel"
              label={tt('templatePreview.field.channel')}
              value={row.channel}
              options={optionsFrom(DISPATCH_CHANNELS, dispatchChannelLabels)}
              onChange={(channel) => setRow({ ...row, channel })}
            />
            <TextSetting
              id="template-preview-recipient-reference"
              label={tt('templatePreview.field.reference')}
              value={row.reference}
              onChange={(reference) => setRow({ ...row, reference })}
            />
            <TextSetting
              id="template-preview-recipient-dispatched"
              type="date"
              label={tt('templatePreview.field.dispatched_at')}
              value={row.dispatched_at}
              onChange={(dispatched_at) => setRow({ ...row, dispatched_at })}
            />
          </>
        )}
        disabled={!canEdit}
        onChange={(recipients) => update('convening', { ...value.convening, recipients })}
      />
      <Card title={tt('templatePreview.card.waiver')}>
        <div className="form settings-rows">
          <TextSetting
            id="template-preview-waiver-basis"
            label={tt('templatePreview.field.basis')}
            value={value.convening_waiver.basis}
            disabled={!canEdit}
            onChange={(basis) => update('convening_waiver', { ...value.convening_waiver, basis })}
          />
          <Toggle
            label={tt('templatePreview.field.all_agreed_to_meet')}
            checked={value.convening_waiver.all_agreed_to_meet}
            disabled={!canEdit}
            onChange={(all_agreed_to_meet) =>
              update('convening_waiver', {
                ...value.convening_waiver,
                all_agreed_to_meet,
              })
            }
          />
          <Toggle
            label={tt('templatePreview.field.all_agreed_to_agenda')}
            checked={value.convening_waiver.all_agreed_to_agenda}
            disabled={!canEdit}
            onChange={(all_agreed_to_agenda) =>
              update('convening_waiver', {
                ...value.convening_waiver,
                all_agreed_to_agenda,
              })
            }
          />
          <TextSetting
            id="template-preview-waiver-grounds"
            label={tt('templatePreview.field.grounds')}
            value={value.convening_waiver.grounds}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(grounds) =>
              update('convening_waiver', { ...value.convening_waiver, grounds })
            }
          />
          <TextSetting
            id="template-preview-waiver-evidence"
            label={tt('templatePreview.field.evidence_reference')}
            value={value.convening_waiver.evidence_reference}
            disabled={!canEdit}
            onChange={(evidence_reference) =>
              update('convening_waiver', { ...value.convening_waiver, evidence_reference })
            }
          />
        </div>
      </Card>
      <Card title={tt('templatePreview.card.representation')}>
        <div className="form settings-rows">
          <TextSetting
            id="template-preview-representation-scope"
            label={tt('templatePreview.field.scope')}
            value={value.representation.scope}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(scope) => update('representation', { ...value.representation, scope })}
          />
          <TextSetting
            id="template-preview-representation-instructions"
            label={tt('templatePreview.field.instructions')}
            value={value.representation.instructions}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(instructions) =>
              update('representation', { ...value.representation, instructions })
            }
          />
          <TextSetting
            id="template-preview-representation-evidence"
            label={tt('templatePreview.field.evidence_reference')}
            value={value.representation.evidence_reference}
            disabled={!canEdit}
            onChange={(evidence_reference) =>
              update('representation', { ...value.representation, evidence_reference })
            }
          />
          <TextSetting
            id="template-preview-representative-name"
            label={tt('templatePreview.field.representative_name')}
            value={value.representation.representative.name}
            disabled={!canEdit}
            onChange={(name) =>
              update('representation', {
                ...value.representation,
                representative: { ...value.representation.representative, name },
              })
            }
          />
          <TextSetting
            id="template-preview-representative-document"
            label={tt('templatePreview.field.representative_document')}
            value={value.representation.representative.document}
            disabled={!canEdit}
            onChange={(document) =>
              update('representation', {
                ...value.representation,
                representative: { ...value.representation.representative, document },
              })
            }
          />
          <TextSetting
            id="template-preview-represented-name"
            label={tt('templatePreview.field.represented_name')}
            value={value.representation.represented.name}
            disabled={!canEdit}
            onChange={(name) =>
              update('representation', {
                ...value.representation,
                represented: { ...value.representation.represented, name },
              })
            }
          />
          <TextSetting
            id="template-preview-represented-unit"
            label={tt('templatePreview.field.represented_unit')}
            value={value.representation.represented.unit}
            disabled={!canEdit}
            onChange={(unit) =>
              update('representation', {
                ...value.representation,
                represented: { ...value.representation.represented, unit },
              })
            }
          />
        </div>
      </Card>
      <Card title={tt('templatePreview.card.telematic')}>
        <div className="form settings-rows">
          {(['authenticity', 'recording', 'security'] as const).map((key) => (
            <TextSetting
              key={key}
              id={`template-preview-telematic-${key}`}
              label={tt(`templatePreview.field.${key}`)}
              value={value.telematic_evidence[key]}
              maxLength={2_000}
              multiline
              disabled={!canEdit}
              onChange={(next) =>
                update('telematic_evidence', {
                  ...value.telematic_evidence,
                  [key]: next,
                })
              }
            />
          ))}
        </div>
      </Card>
    </>
  );
}
