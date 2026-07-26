import type {
  TemplatePreviewAgendaItem,
  TemplatePreviewDeliberation,
  TemplatePreviewVote,
} from '../../api/types';
import { useTemplatePreviewSamplesT } from '../../i18n/templatePreviewSamplesFallback';
import { Card } from '../../ui';
import {
  NumberSetting,
  SampleCollectionTable,
  SelectSetting,
  StatementsEditor,
  TextSetting,
  isTemplatePreviewStatementRow,
} from './templatePreviewSamplesEditorParts';
import {
  isTemplatePreviewCount,
  isTemplatePreviewDocumentNumber,
  isTemplatePreviewProse,
  TEMPLATE_PREVIEW_STATEMENTS_MAX,
} from './templatePreviewSamplesModel';
import type { TemplatePreviewSampleSectionProps } from './templatePreviewSampleSectionTypes';

export function TemplatePreviewSampleAgendaSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <SampleCollectionTable<TemplatePreviewAgendaItem>
        title={tt('templatePreview.collection.agenda')}
        rows={value.agenda}
        columns={[
          { label: tt('templatePreview.field.number'), render: (row) => row.number },
          { label: tt('templatePreview.field.text'), render: (row) => row.text },
        ]}
        createRow={() => ({ number: value.agenda.length + 1, text: '' })}
        validateRow={(row) =>
          isTemplatePreviewDocumentNumber(row.number) && isTemplatePreviewProse(row.text)
        }
        renderEditor={(row, setRow) => (
          <>
            <NumberSetting
              id="template-preview-agenda-item-number"
              label={tt('templatePreview.field.number')}
              value={row.number}
              min={1}
              max={999_999}
              onChange={(number) => setRow({ ...row, number })}
            />
            <TextSetting
              id="template-preview-agenda-item-text"
              label={tt('templatePreview.field.text')}
              value={row.text}
              maxLength={2_000}
              multiline
              onChange={(text) => setRow({ ...row, text })}
            />
          </>
        )}
        disabled={!canEdit}
        onChange={(agenda) => update('agenda', agenda)}
      />
      <Card title={tt('templatePreview.card.deliberations')}>
        <div className="form settings-rows">
          <TextSetting
            id="template-preview-deliberations-summary"
            label={tt('templatePreview.field.summary')}
            value={value.deliberations.summary}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(summary) => update('deliberations', { ...value.deliberations, summary })}
          />
        </div>
      </Card>
      <SampleCollectionTable<TemplatePreviewDeliberation>
        title={tt('templatePreview.collection.deliberations')}
        rows={value.deliberations.items}
        columns={[
          {
            label: tt('templatePreview.field.agenda_number'),
            render: (row) => row.agenda_number,
          },
          { label: tt('templatePreview.field.text'), render: (row) => row.text },
          {
            label: tt('templatePreview.column.vote'),
            render: (row) =>
              row.vote === 'Unanimous'
                ? tt('templatePreview.vote.unanimous')
                : tt('templatePreview.vote.recorded'),
          },
        ]}
        createRow={() => ({
          agenda_number: value.deliberations.items.length + 1,
          text: '',
          vote: 'Unanimous',
          statements: [],
        })}
        validateRow={(row) =>
          isTemplatePreviewDocumentNumber(row.agenda_number) &&
          isTemplatePreviewProse(row.text) &&
          row.statements.length <= TEMPLATE_PREVIEW_STATEMENTS_MAX &&
          row.statements.every(isTemplatePreviewStatementRow) &&
          (row.vote === 'Unanimous' ||
            (isTemplatePreviewCount(row.vote.Recorded.em_favor) &&
              isTemplatePreviewCount(row.vote.Recorded.contra) &&
              isTemplatePreviewCount(row.vote.Recorded.abstencoes)))
        }
        renderEditor={(row, setRow) => {
          const recorded =
            row.vote === 'Unanimous'
              ? { em_favor: 0, contra: 0, abstencoes: 0 }
              : row.vote.Recorded;
          return (
            <>
              <NumberSetting
                id="template-preview-deliberation-agenda-number"
                label={tt('templatePreview.field.agenda_number')}
                value={row.agenda_number}
                min={1}
                max={999_999}
                onChange={(agenda_number) => setRow({ ...row, agenda_number })}
              />
              <TextSetting
                id="template-preview-deliberation-text"
                label={tt('templatePreview.field.text')}
                value={row.text}
                maxLength={2_000}
                multiline
                onChange={(text) => setRow({ ...row, text })}
              />
              <SelectSetting<'Unanimous' | 'Recorded'>
                id="template-preview-deliberation-vote"
                label={tt('templatePreview.field.vote')}
                value={row.vote === 'Unanimous' ? 'Unanimous' : 'Recorded'}
                options={[
                  { value: 'Unanimous', label: tt('templatePreview.vote.unanimous') },
                  { value: 'Recorded', label: tt('templatePreview.vote.recorded') },
                ]}
                onChange={(kind) =>
                  setRow({
                    ...row,
                    vote: kind === 'Unanimous' ? 'Unanimous' : { Recorded: recorded },
                  })
                }
              />
              {row.vote !== 'Unanimous' ? (
                <div className="template-preview-modal-grid">
                  {(['em_favor', 'contra', 'abstencoes'] as const).map((key) => (
                    <NumberSetting
                      key={key}
                      id={`template-preview-vote-${key}`}
                      label={tt(`templatePreview.field.${key}`)}
                      value={row.vote === 'Unanimous' ? 0 : row.vote.Recorded[key]}
                      min={0}
                      max={1_000_000}
                      onChange={(count) =>
                        setRow({
                          ...row,
                          vote: {
                            Recorded: {
                              ...(row.vote as Exclude<TemplatePreviewVote, 'Unanimous'>).Recorded,
                              [key]: count,
                            },
                          },
                        })
                      }
                    />
                  ))}
                </div>
              ) : null}
              <StatementsEditor
                value={row.statements}
                onChange={(statements) => setRow({ ...row, statements })}
              />
            </>
          );
        }}
        disabled={!canEdit}
        onChange={(items) => update('deliberations', { ...value.deliberations, items })}
      />
    </>
  );
}
