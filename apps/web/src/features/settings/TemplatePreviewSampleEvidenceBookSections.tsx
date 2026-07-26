import {
  type SignatoryCapacity,
  type TemplatePreviewAttachment,
  type TemplatePreviewReferencedDocument,
  type TemplatePreviewSignatory,
} from '../../api/types';
import { attendeeQualityLabels, optionsFrom, signatoryCapacityLabels } from '../../api/labels';
import {
  type TemplatePreviewSamplesCopyKey,
  useTemplatePreviewSamplesT,
} from '../../i18n/templatePreviewSamplesFallback';
import { Card, InlineWarning } from '../../ui';
import {
  ALL_TEMPLATE_PREVIEW_CAPACITIES,
  NumberSetting,
  SampleCollectionTable,
  SelectSetting,
  SignatoryEditor,
  TextSetting,
  isTemplatePreviewSignatoryRow,
} from './templatePreviewSamplesEditorParts';
import type { TemplatePreviewSampleSectionProps } from './templatePreviewSampleSectionTypes';
import { isTemplatePreviewDigest, isTemplatePreviewShortText } from './templatePreviewSamplesModel';

const NUMBERING_SCHEMES = ['BoundVolume', 'LooseLeaf'] as const;
const CLOSING_REASONS = ['BookFull', 'EntityDissolved', 'MigrationToSuccessor', 'Other'] as const;

export function TemplatePreviewSampleEvidenceSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <SampleCollectionTable<TemplatePreviewReferencedDocument>
        title={tt('templatePreview.collection.referencedDocuments')}
        rows={value.evidence.referenced_documents}
        columns={[
          { label: tt('templatePreview.field.label'), render: (row) => row.label },
          { label: tt('templatePreview.field.reference'), render: (row) => row.reference },
        ]}
        createRow={() => ({ label: '', reference: '' })}
        validateRow={(row) =>
          isTemplatePreviewShortText(row.label) && isTemplatePreviewShortText(row.reference)
        }
        renderEditor={(row, setRow) => (
          <>
            <TextSetting
              id="template-preview-document-label"
              label={tt('templatePreview.field.label')}
              value={row.label}
              onChange={(label) => setRow({ ...row, label })}
            />
            <TextSetting
              id="template-preview-document-reference"
              label={tt('templatePreview.field.reference')}
              value={row.reference}
              onChange={(reference) => setRow({ ...row, reference })}
            />
          </>
        )}
        disabled={!canEdit}
        onChange={(referenced_documents) =>
          update('evidence', { ...value.evidence, referenced_documents })
        }
      />
      <SampleCollectionTable<TemplatePreviewAttachment>
        title={tt('templatePreview.collection.attachments')}
        rows={value.evidence.attachments}
        columns={[
          { label: tt('templatePreview.field.kind'), render: (row) => row.kind },
          { label: tt('templatePreview.field.digest'), render: (row) => row.digest },
        ]}
        createRow={() => ({ kind: '', digest: '' })}
        validateRow={(row) =>
          isTemplatePreviewShortText(row.kind) && isTemplatePreviewDigest(row.digest)
        }
        renderEditor={(row, setRow) => (
          <>
            <TextSetting
              id="template-preview-attachment-kind"
              label={tt('templatePreview.field.kind')}
              value={row.kind}
              onChange={(kind) => setRow({ ...row, kind })}
            />
            <TextSetting
              id="template-preview-attachment-digest"
              label={tt('templatePreview.field.digest')}
              value={row.digest}
              maxLength={64}
              onChange={(digest) => setRow({ ...row, digest })}
            />
          </>
        )}
        disabled={!canEdit}
        onChange={(attachments) => update('evidence', { ...value.evidence, attachments })}
      />
      {(
        [
          ['signatories', 'templatePreview.collection.signatories'],
          ['required_signatories', 'templatePreview.collection.requiredSignatories'],
        ] as const
      ).map(([key, titleKey]) => (
        <SampleCollectionTable<TemplatePreviewSignatory>
          key={key}
          title={tt(titleKey)}
          rows={value.evidence[key]}
          columns={[
            { label: tt('templatePreview.column.name'), render: (row) => row.name },
            {
              label: tt('templatePreview.column.details'),
              render: (row) => `${signatoryCapacityLabels[row.capacity]} · ${row.role}`,
            },
          ]}
          createRow={() => ({ capacity: 'Chair', role: '', name: '' })}
          validateRow={isTemplatePreviewSignatoryRow}
          renderEditor={(row, setRow) => <SignatoryEditor row={row} setRow={setRow} />}
          disabled={!canEdit}
          onChange={(rows) => update('evidence', { ...value.evidence, [key]: rows })}
        />
      ))}
    </>
  );
}

export function TemplatePreviewSampleBookSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <Card title={tt('templatePreview.card.book')}>
        <div className="form settings-rows">
          {(['kind', 'reference', 'predecessor_reference'] as const).map((key) => (
            <TextSetting
              key={key}
              id={`template-preview-book-${key}`}
              label={tt(`templatePreview.field.${key}`)}
              value={value.book[key]}
              disabled={!canEdit}
              onChange={(next) => update('book', { ...value.book, [key]: next })}
            />
          ))}
        </div>
      </Card>
      <Card title={tt('templatePreview.card.bookInstruments')}>
        <div className="form settings-rows">
          <TextSetting
            id="template-preview-opening-date"
            type="date"
            label={tt('templatePreview.field.opening_date')}
            value={value.book_instruments.opening_date}
            disabled={!canEdit}
            onChange={(opening_date) =>
              update('book_instruments', { ...value.book_instruments, opening_date })
            }
          />
          <TextSetting
            id="template-preview-closing-date"
            type="date"
            label={tt('templatePreview.field.closing_date')}
            value={value.book_instruments.closing_date}
            disabled={!canEdit}
            onChange={(closing_date) =>
              update('book_instruments', { ...value.book_instruments, closing_date })
            }
          />
          <SelectSetting<(typeof NUMBERING_SCHEMES)[number]>
            id="template-preview-numbering-scheme"
            label={tt('templatePreview.field.numbering_scheme')}
            value={value.book_instruments.numbering_scheme}
            options={NUMBERING_SCHEMES.map((scheme) => ({
              value: scheme,
              label: tt(`templatePreview.numbering.${scheme}`),
            }))}
            disabled={!canEdit}
            onChange={(numbering_scheme) =>
              update('book_instruments', { ...value.book_instruments, numbering_scheme })
            }
          />
          <TextSetting
            id="template-preview-numbering-label"
            label={tt('templatePreview.field.numbering_label')}
            value={value.book_instruments.numbering_label}
            disabled={!canEdit}
            onChange={(numbering_label) =>
              update('book_instruments', { ...value.book_instruments, numbering_label })
            }
          />
          <TextSetting
            id="template-preview-purpose"
            label={tt('templatePreview.field.purpose')}
            value={value.book_instruments.purpose}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(purpose) =>
              update('book_instruments', { ...value.book_instruments, purpose })
            }
          />
          <NumberSetting
            id="template-preview-ata-count"
            label={tt('templatePreview.field.ata_count')}
            value={value.book_instruments.ata_count}
            min={0}
            max={1_000_000}
            disabled={!canEdit}
            onChange={(ata_count) =>
              update('book_instruments', { ...value.book_instruments, ata_count })
            }
          />
          <SelectSetting<(typeof CLOSING_REASONS)[number]>
            id="template-preview-closing-reason"
            label={tt('templatePreview.field.closing_reason')}
            value={value.book_instruments.closing_reason}
            options={CLOSING_REASONS.map((reason) => ({
              value: reason,
              label: tt(`templatePreview.reason.${reason}`),
            }))}
            disabled={!canEdit}
            onChange={(closing_reason) =>
              update('book_instruments', { ...value.book_instruments, closing_reason })
            }
          />
          <TextSetting
            id="template-preview-rectifies"
            label={tt('templatePreview.field.rectifies')}
            hint={tt('templatePreview.field.rectifies.hint')}
            value={value.book_instruments.rectifies}
            disabled={!canEdit}
            onChange={(rectifies) =>
              update('book_instruments', { ...value.book_instruments, rectifies })
            }
          />
          <NumberSetting
            id="template-preview-seal-event"
            label={tt('templatePreview.field.seal_event_seq')}
            value={value.book_instruments.seal_event_seq}
            min={0}
            max={1_000_000}
            disabled={!canEdit}
            onChange={(seal_event_seq) =>
              update('book_instruments', { ...value.book_instruments, seal_event_seq })
            }
          />
          <TextSetting
            id="template-preview-payload-digest"
            label={tt('templatePreview.field.payload_digest')}
            value={value.book_instruments.payload_digest}
            maxLength={64}
            disabled={!canEdit}
            onChange={(payload_digest) =>
              update('book_instruments', { ...value.book_instruments, payload_digest })
            }
          />
          <TextSetting
            id="template-preview-digest"
            label={tt('templatePreview.field.digest')}
            value={value.book_instruments.digest}
            maxLength={64}
            disabled={!canEdit}
            onChange={(digest) => update('book_instruments', { ...value.book_instruments, digest })}
          />
        </div>
      </Card>
    </>
  );
}

export function TemplatePreviewSampleFallbacksSection({
  value,
  canEdit,
  update,
}: TemplatePreviewSampleSectionProps) {
  const tt = useTemplatePreviewSamplesT();
  return (
    <>
      <Card title={tt('templatePreview.card.fallbacks')}>
        <div className="form settings-rows">
          <SelectSetting<SignatoryCapacity>
            id="template-preview-fallback-capacity"
            label={tt('templatePreview.field.capacity')}
            value={value.fallbacks.capacity}
            options={optionsFrom(ALL_TEMPLATE_PREVIEW_CAPACITIES, signatoryCapacityLabels)}
            disabled={!canEdit}
            onChange={(capacity) => update('fallbacks', { ...value.fallbacks, capacity })}
          />
          <TextSetting
            id="template-preview-fallback-contact"
            label={tt('templatePreview.field.contact')}
            value={value.fallbacks.contact}
            maxLength={500}
            disabled={!canEdit}
            onChange={(contact) => update('fallbacks', { ...value.fallbacks, contact })}
          />
          <TextSetting
            id="template-preview-fallback-dispatched"
            type="date"
            label={tt('templatePreview.field.dispatched_at')}
            value={value.fallbacks.dispatched_at}
            disabled={!canEdit}
            onChange={(dispatched_at) => update('fallbacks', { ...value.fallbacks, dispatched_at })}
          />
          {(['kind', 'label', 'name'] as const).map((key) => (
            <TextSetting
              key={key}
              id={`template-preview-fallback-${key}`}
              label={tt(
                key === 'name'
                  ? 'templatePreview.column.name'
                  : (`templatePreview.field.${key}` as TemplatePreviewSamplesCopyKey),
              )}
              value={value.fallbacks[key]}
              disabled={!canEdit}
              onChange={(next) => update('fallbacks', { ...value.fallbacks, [key]: next })}
            />
          ))}
          <NumberSetting
            id="template-preview-fallback-number"
            label={tt('templatePreview.field.number')}
            value={value.fallbacks.number}
            min={1}
            max={999_999}
            disabled={!canEdit}
            onChange={(number) => update('fallbacks', { ...value.fallbacks, number })}
          />
          <SelectSetting
            id="template-preview-fallback-quality"
            label={tt('templatePreview.field.quality')}
            value={value.fallbacks.quality}
            options={optionsFrom(ALL_TEMPLATE_PREVIEW_CAPACITIES, attendeeQualityLabels)}
            disabled={!canEdit}
            onChange={(quality) => update('fallbacks', { ...value.fallbacks, quality })}
          />
          {(['quality_note', 'reference', 'represented_by', 'role'] as const).map((key) => (
            <TextSetting
              key={key}
              id={`template-preview-fallback-${key}`}
              label={tt(`templatePreview.field.${key}`)}
              value={value.fallbacks[key]}
              disabled={!canEdit}
              onChange={(next) => update('fallbacks', { ...value.fallbacks, [key]: next })}
            />
          ))}
          <NumberSetting
            id="template-preview-fallback-statement-number"
            label={tt('templatePreview.field.agenda_number')}
            value={value.fallbacks.statement.agenda_number}
            min={1}
            max={999_999}
            disabled={!canEdit}
            onChange={(agenda_number) =>
              update('fallbacks', {
                ...value.fallbacks,
                statement: { ...value.fallbacks.statement, agenda_number },
              })
            }
          />
          <TextSetting
            id="template-preview-fallback-statement-member"
            label={tt('templatePreview.field.fallback_statement_member')}
            value={value.fallbacks.statement.member}
            disabled={!canEdit}
            onChange={(member) =>
              update('fallbacks', {
                ...value.fallbacks,
                statement: { ...value.fallbacks.statement, member },
              })
            }
          />
          <TextSetting
            id="template-preview-fallback-statement-text"
            label={tt('templatePreview.field.fallback_statement_text')}
            value={value.fallbacks.statement.text}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(text) =>
              update('fallbacks', {
                ...value.fallbacks,
                statement: { ...value.fallbacks.statement, text },
              })
            }
          />
          <TextSetting
            id="template-preview-fallback-text"
            label={tt('templatePreview.field.text')}
            value={value.fallbacks.text}
            maxLength={2_000}
            multiline
            disabled={!canEdit}
            onChange={(text) => update('fallbacks', { ...value.fallbacks, text })}
          />
          <TextSetting
            id="template-preview-fallback-capital"
            label={tt('templatePreview.field.capital_weight')}
            value={value.fallbacks.weight.capital}
            disabled={!canEdit}
            onChange={(capital) =>
              update('fallbacks', {
                ...value.fallbacks,
                weight: { ...value.fallbacks.weight, capital },
              })
            }
          />
          <NumberSetting
            id="template-preview-fallback-permilage"
            label={tt('templatePreview.field.permilage')}
            value={value.fallbacks.weight.permilage}
            min={0}
            max={1_000}
            disabled={!canEdit}
            onChange={(permilage) =>
              update('fallbacks', {
                ...value.fallbacks,
                weight: { ...value.fallbacks.weight, permilage },
              })
            }
          />
        </div>
      </Card>
      <InlineWarning tone="info" title={tt('templatePreview.law.title')}>
        {tt('templatePreview.law.body')}
      </InlineWarning>
    </>
  );
}
