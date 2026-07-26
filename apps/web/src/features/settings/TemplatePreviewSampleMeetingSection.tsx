import {
  MEETING_CHANNELS,
  type MeetingChannel,
  type TemplatePreviewAttendee,
} from '../../api/types';
import {
  attendeeQualityLabels,
  meetingChannelLabels,
  optionsFrom,
  presenceModeLabels,
} from '../../api/labels';
import { useTemplatePreviewSamplesT } from '../../i18n/templatePreviewSamplesFallback';
import { Card } from '../../ui';
import {
  AttendeeEditor,
  NumberSetting,
  SampleCollectionTable,
  SelectSetting,
  TextSetting,
  isTemplatePreviewAttendeeRow,
} from './templatePreviewSamplesEditorParts';
import {
  isTemplatePreviewShortText,
  TEMPLATE_PREVIEW_SECRETARIES_MAX,
} from './templatePreviewSamplesModel';
import type { TemplatePreviewSampleSectionProps } from './templatePreviewSampleSectionTypes';

export function TemplatePreviewSampleMeetingSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <Card title={tt('templatePreview.card.act')}>
        <div className="form settings-rows">
          <NumberSetting
            id="template-preview-act-number"
            label={tt('templatePreview.field.number')}
            value={value.act.number}
            min={1}
            max={999_999}
            disabled={!canEdit}
            onChange={(number) => update('act', { ...value.act, number })}
          />
          <TextSetting
            id="template-preview-act-title"
            label={tt('templatePreview.field.title')}
            value={value.act.title}
            disabled={!canEdit}
            onChange={(title) => update('act', { ...value.act, title })}
          />
          <TextSetting
            id="template-preview-act-date"
            type="date"
            label={tt('templatePreview.field.meeting_date')}
            value={value.act.meeting_date}
            disabled={!canEdit}
            onChange={(meeting_date) => update('act', { ...value.act, meeting_date })}
          />
          <TextSetting
            id="template-preview-act-time"
            type="time"
            label={tt('templatePreview.field.meeting_time')}
            value={value.act.meeting_time}
            disabled={!canEdit}
            onChange={(meeting_time) => update('act', { ...value.act, meeting_time })}
          />
          <TextSetting
            id="template-preview-act-place"
            label={tt('templatePreview.field.place')}
            value={value.act.place}
            maxLength={500}
            disabled={!canEdit}
            onChange={(place) => update('act', { ...value.act, place })}
          />
        </div>
      </Card>
      <Card title={tt('templatePreview.card.meeting')}>
        <div className="form settings-rows">
          <NumberSetting
            id="template-preview-ata-number"
            label={tt('templatePreview.field.ata_number')}
            value={value.meeting.ata_number}
            min={1}
            max={999_999}
            disabled={!canEdit}
            onChange={(ata_number) => update('meeting', { ...value.meeting, ata_number })}
          />
          <NumberSetting
            id="template-preview-agenda-number"
            label={tt('templatePreview.field.agenda_number')}
            value={value.meeting.agenda_number}
            min={1}
            max={999_999}
            disabled={!canEdit}
            onChange={(agenda_number) => update('meeting', { ...value.meeting, agenda_number })}
          />
          <TextSetting
            id="template-preview-meeting-date"
            type="date"
            label={tt('templatePreview.field.meeting_date')}
            value={value.meeting.meeting_date}
            disabled={!canEdit}
            onChange={(meeting_date) => update('meeting', { ...value.meeting, meeting_date })}
          />
          <TextSetting
            id="template-preview-meeting-time"
            type="time"
            label={tt('templatePreview.field.meeting_time')}
            value={value.meeting.meeting_time}
            disabled={!canEdit}
            onChange={(meeting_time) => update('meeting', { ...value.meeting, meeting_time })}
          />
          <TextSetting
            id="template-preview-meeting-place"
            label={tt('templatePreview.field.place')}
            value={value.meeting.place}
            maxLength={500}
            disabled={!canEdit}
            onChange={(place) => update('meeting', { ...value.meeting, place })}
          />
          <SelectSetting<MeetingChannel>
            id="template-preview-meeting-channel"
            label={tt('templatePreview.field.channel')}
            value={value.meeting.channel}
            options={optionsFrom(MEETING_CHANNELS, meetingChannelLabels)}
            disabled={!canEdit}
            onChange={(channel) => update('meeting', { ...value.meeting, channel })}
          />
          <NumberSetting
            id="template-preview-members-present"
            label={tt('templatePreview.field.members_present')}
            value={value.meeting.members_present}
            min={0}
            max={1_000_000}
            disabled={!canEdit}
            onChange={(members_present) => update('meeting', { ...value.meeting, members_present })}
          />
          <NumberSetting
            id="template-preview-members-represented"
            label={tt('templatePreview.field.members_represented')}
            value={value.meeting.members_represented}
            min={0}
            max={1_000_000}
            disabled={!canEdit}
            onChange={(members_represented) =>
              update('meeting', { ...value.meeting, members_represented })
            }
          />
          <TextSetting
            id="template-preview-attendance-reference"
            label={tt('templatePreview.field.attendance_reference')}
            value={value.meeting.attendance_reference}
            disabled={!canEdit}
            onChange={(attendance_reference) =>
              update('meeting', { ...value.meeting, attendance_reference })
            }
          />
          <TextSetting
            id="template-preview-president"
            label={tt('templatePreview.field.president')}
            value={value.meeting.mesa.president}
            disabled={!canEdit}
            onChange={(president) =>
              update('meeting', {
                ...value.meeting,
                mesa: { ...value.meeting.mesa, president },
              })
            }
          />
        </div>
      </Card>
      <SampleCollectionTable<string>
        title={tt('templatePreview.collection.secretaries')}
        rows={value.meeting.mesa.secretaries}
        columns={[
          {
            label: tt('templatePreview.field.secretary'),
            render: (secretary) => secretary,
          },
        ]}
        createRow={() => ''}
        validateRow={isTemplatePreviewShortText}
        renderEditor={(secretary, setSecretary) => (
          <TextSetting
            id="template-preview-secretary"
            label={tt('templatePreview.field.secretary')}
            value={secretary}
            onChange={setSecretary}
          />
        )}
        disabled={!canEdit}
        maxRows={TEMPLATE_PREVIEW_SECRETARIES_MAX}
        onChange={(secretaries) =>
          update('meeting', {
            ...value.meeting,
            mesa: { ...value.meeting.mesa, secretaries },
          })
        }
      />
      <SampleCollectionTable<TemplatePreviewAttendee>
        title={tt('templatePreview.collection.attendees')}
        rows={value.meeting.attendees}
        columns={[
          { label: tt('templatePreview.column.name'), render: (row) => row.name },
          {
            label: tt('templatePreview.column.details'),
            render: (row) =>
              `${attendeeQualityLabels[row.quality]} · ${presenceModeLabels[row.presence]}`,
          },
        ]}
        createRow={() => ({
          name: '',
          quality: 'Member',
          quality_note: '',
          weight: { capital: null, permilage: null },
          presence: 'InPerson',
          represented_by: null,
        })}
        validateRow={isTemplatePreviewAttendeeRow}
        renderEditor={(row, setRow) => <AttendeeEditor row={row} setRow={setRow} />}
        disabled={!canEdit}
        onChange={(attendees) => update('meeting', { ...value.meeting, attendees })}
      />
    </>
  );
}
