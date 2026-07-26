import { useTemplatePreviewSamplesT } from '../../i18n/templatePreviewSamplesFallback';
import { Card } from '../../ui';
import { FamilyProfilesTable, TextSetting } from './templatePreviewSamplesEditorParts';
import type { TemplatePreviewSampleSectionProps } from './templatePreviewSampleSectionTypes';

export function TemplatePreviewGeneralSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <Card title={tt('templatePreview.card.general')}>
      <div className="form settings-rows">
        <TextSetting
          id="template-preview-title"
          label={tt('templatePreview.field.title')}
          value={value.general.title}
          disabled={!canEdit}
          onChange={(title) => update('general', { ...value.general, title })}
        />
        <TextSetting
          id="template-preview-subject"
          label={tt('templatePreview.field.subject')}
          value={value.general.subject}
          disabled={!canEdit}
          onChange={(subject) => update('general', { ...value.general, subject })}
        />
        <TextSetting
          id="template-preview-created"
          type="date"
          label={tt('templatePreview.field.created_at')}
          value={value.general.created_at}
          disabled={!canEdit}
          onChange={(created_at) => update('general', { ...value.general, created_at })}
        />
      </div>
    </Card>
  );
}

export function TemplatePreviewEntitySection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <Card title={tt('templatePreview.card.entity')}>
        <div className="form settings-rows">
          <TextSetting
            id="template-preview-nipc"
            label={tt('templatePreview.field.nipc')}
            value={value.entity.nipc}
            maxLength={9}
            disabled={!canEdit}
            onChange={(nipc) => update('entity', { ...value.entity, nipc })}
          />
          <TextSetting
            id="template-preview-seat"
            label={tt('templatePreview.field.seat')}
            value={value.entity.seat}
            maxLength={500}
            disabled={!canEdit}
            onChange={(seat) => update('entity', { ...value.entity, seat })}
          />
          <TextSetting
            id="template-preview-address"
            label={tt('templatePreview.field.address')}
            value={value.entity.address}
            maxLength={500}
            disabled={!canEdit}
            onChange={(address) => update('entity', { ...value.entity, address })}
          />
          <TextSetting
            id="template-preview-share-capital"
            label={tt('templatePreview.field.share_capital')}
            value={value.entity.share_capital}
            disabled={!canEdit}
            onChange={(share_capital) => update('entity', { ...value.entity, share_capital })}
          />
          <TextSetting
            id="template-preview-capital"
            label={tt('templatePreview.field.capital')}
            value={value.entity.capital}
            disabled={!canEdit}
            onChange={(capital) => update('entity', { ...value.entity, capital })}
          />
        </div>
      </Card>
      <FamilyProfilesTable
        value={value.family_profiles}
        disabled={!canEdit}
        onChange={(family_profiles) => update('family_profiles', family_profiles)}
      />
    </>
  );
}
