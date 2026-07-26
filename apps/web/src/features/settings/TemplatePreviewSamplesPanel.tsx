import { useMemo, useState, type ReactNode } from 'react';
import type { TemplatePreviewSampleSettings } from '../../api/types';
import { useActiveLocale } from '../../i18n';
import {
  type TemplatePreviewSamplesCopyKey,
  useTemplatePreviewSamplesT,
} from '../../i18n/templatePreviewSamplesFallback';
import { Badge, Button, ConfirmActionModal, Icon, InlineWarning, SubNav } from '../../ui';
import {
  TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES,
  templatePreviewSamplesByteSize,
  validateTemplatePreviewSamples,
} from './templatePreviewSamplesModel';
import {
  TemplatePreviewEntitySection,
  TemplatePreviewGeneralSection,
} from './TemplatePreviewSampleGeneralSections';
import { TemplatePreviewSampleMeetingSection } from './TemplatePreviewSampleMeetingSection';
import { TemplatePreviewSampleAgendaSection } from './TemplatePreviewSampleAgendaSection';
import { TemplatePreviewSampleConveningSection } from './TemplatePreviewSampleConveningSection';
import {
  TemplatePreviewSampleBookSection,
  TemplatePreviewSampleEvidenceSection,
  TemplatePreviewSampleFallbacksSection,
} from './TemplatePreviewSampleEvidenceBookSections';
import './TemplatePreviewSamplesPanel.css';

type PreviewSamplesTab =
  'general' | 'entity' | 'meeting' | 'agenda' | 'convening' | 'evidence' | 'book' | 'fallbacks';

interface TemplatePreviewSamplesPanelProps {
  value: TemplatePreviewSampleSettings;
  canEdit: boolean;
  onChange: (value: TemplatePreviewSampleSettings) => void;
  onReset: () => void;
}

const VALIDATION_FIELD_KEYS: Record<string, TemplatePreviewSamplesCopyKey> = {
  'general.title': 'templatePreview.field.title',
  'general.subject': 'templatePreview.field.subject',
  'general.created_at': 'templatePreview.field.created_at',
  'entity.nipc': 'templatePreview.field.nipc',
  'entity.seat': 'templatePreview.field.seat',
  'entity.address': 'templatePreview.field.address',
  'entity.share_capital': 'templatePreview.field.share_capital',
  'entity.capital': 'templatePreview.field.capital',
  'family_profiles.name': 'templatePreview.column.name',
  'family_profiles.legal_form': 'templatePreview.field.legal_form',
  'book.kind': 'templatePreview.field.kind',
  'book.reference': 'templatePreview.field.reference',
  'book.predecessor_reference': 'templatePreview.field.predecessor_reference',
  'act.number': 'templatePreview.field.number',
  'act.title': 'templatePreview.field.title',
  'act.meeting_date': 'templatePreview.field.meeting_date',
  'act.meeting_time': 'templatePreview.field.meeting_time',
  'act.place': 'templatePreview.field.place',
  'meeting.ata_number': 'templatePreview.field.ata_number',
  'meeting.agenda_number': 'templatePreview.field.agenda_number',
  'meeting.meeting_date': 'templatePreview.field.meeting_date',
  'meeting.meeting_time': 'templatePreview.field.meeting_time',
  'meeting.place': 'templatePreview.field.place',
  'meeting.members_present': 'templatePreview.field.members_present',
  'meeting.members_represented': 'templatePreview.field.members_represented',
  'meeting.attendance_reference': 'templatePreview.field.attendance_reference',
  'meeting.mesa.president': 'templatePreview.field.president',
  'meeting.mesa.secretaries': 'templatePreview.collection.secretaries',
  'meeting.mesa.secretaries.value': 'templatePreview.field.secretary',
  'meeting.attendees': 'templatePreview.collection.attendees',
  'meeting.attendees.name': 'templatePreview.column.name',
  'meeting.attendees.quality_note': 'templatePreview.field.quality_note',
  'meeting.attendees.weight.capital': 'templatePreview.field.capital_weight',
  'meeting.attendees.weight.permilage': 'templatePreview.field.permilage',
  'meeting.attendees.represented_by': 'templatePreview.field.represented_by',
  agenda: 'templatePreview.collection.agenda',
  'agenda.number': 'templatePreview.field.number',
  'agenda.text': 'templatePreview.field.text',
  'deliberations.items': 'templatePreview.collection.deliberations',
  'deliberations.summary': 'templatePreview.field.summary',
  'deliberations.items.agenda_number': 'templatePreview.field.agenda_number',
  'deliberations.items.text': 'templatePreview.field.text',
  'deliberations.items.statements': 'templatePreview.collection.statements',
  'deliberations.items.statements.agenda_number': 'templatePreview.field.agenda_number',
  'deliberations.items.statements.member': 'templatePreview.field.member',
  'deliberations.items.statements.text': 'templatePreview.field.text',
  'deliberations.items.vote.em_favor': 'templatePreview.field.em_favor',
  'deliberations.items.vote.contra': 'templatePreview.field.contra',
  'deliberations.items.vote.abstencoes': 'templatePreview.field.abstencoes',
  'evidence.referenced_documents': 'templatePreview.collection.referencedDocuments',
  'evidence.referenced_documents.label': 'templatePreview.field.label',
  'evidence.referenced_documents.reference': 'templatePreview.field.reference',
  'evidence.attachments': 'templatePreview.collection.attachments',
  'evidence.attachments.kind': 'templatePreview.field.kind',
  'evidence.attachments.digest': 'templatePreview.field.digest',
  'evidence.signatories': 'templatePreview.collection.signatories',
  'evidence.required_signatories': 'templatePreview.collection.requiredSignatories',
  'evidence.signatories.role': 'templatePreview.field.role',
  'evidence.signatories.name': 'templatePreview.column.name',
  'convening.convener': 'templatePreview.field.convener',
  'convening.dispatch_date': 'templatePreview.field.dispatch_date',
  'convening.antecedence_days': 'templatePreview.field.antecedence_days',
  'convening.second_call.date': 'templatePreview.field.second_call_date',
  'convening.second_call.time': 'templatePreview.field.second_call_time',
  'convening.recipients': 'templatePreview.collection.recipients',
  'convening.recipients.name': 'templatePreview.column.name',
  'convening.recipients.contact': 'templatePreview.field.contact',
  'convening.recipients.reference': 'templatePreview.field.reference',
  'convening.recipients.dispatched_at': 'templatePreview.field.dispatched_at',
  'convening_waiver.basis': 'templatePreview.field.basis',
  'convening_waiver.grounds': 'templatePreview.field.grounds',
  'convening_waiver.evidence_reference': 'templatePreview.field.evidence_reference',
  'representation.scope': 'templatePreview.field.scope',
  'representation.instructions': 'templatePreview.field.instructions',
  'representation.evidence_reference': 'templatePreview.field.evidence_reference',
  'representation.representative.name': 'templatePreview.field.representative_name',
  'representation.representative.document': 'templatePreview.field.representative_document',
  'representation.represented.name': 'templatePreview.field.represented_name',
  'representation.represented.unit': 'templatePreview.field.represented_unit',
  'telematic_evidence.authenticity': 'templatePreview.field.authenticity',
  'telematic_evidence.recording': 'templatePreview.field.recording',
  'telematic_evidence.security': 'templatePreview.field.security',
  'book_instruments.opening_date': 'templatePreview.field.opening_date',
  'book_instruments.closing_date': 'templatePreview.field.closing_date',
  'book_instruments.numbering_label': 'templatePreview.field.numbering_label',
  'book_instruments.purpose': 'templatePreview.field.purpose',
  'book_instruments.ata_count': 'templatePreview.field.ata_count',
  'book_instruments.rectifies': 'templatePreview.field.rectifies',
  'book_instruments.seal_event_seq': 'templatePreview.field.seal_event_seq',
  'book_instruments.payload_digest': 'templatePreview.field.payload_digest',
  'book_instruments.digest': 'templatePreview.field.digest',
  'fallbacks.contact': 'templatePreview.field.contact',
  'fallbacks.dispatched_at': 'templatePreview.field.dispatched_at',
  'fallbacks.kind': 'templatePreview.field.kind',
  'fallbacks.label': 'templatePreview.field.label',
  'fallbacks.name': 'templatePreview.column.name',
  'fallbacks.number': 'templatePreview.field.number',
  'fallbacks.quality_note': 'templatePreview.field.quality_note',
  'fallbacks.reference': 'templatePreview.field.reference',
  'fallbacks.represented_by': 'templatePreview.field.represented_by',
  'fallbacks.role': 'templatePreview.field.role',
  'fallbacks.statement.agenda_number': 'templatePreview.field.agenda_number',
  'fallbacks.statement.member': 'templatePreview.field.fallback_statement_member',
  'fallbacks.statement.text': 'templatePreview.field.fallback_statement_text',
  'fallbacks.text': 'templatePreview.field.text',
  'fallbacks.weight.capital': 'templatePreview.field.capital_weight',
  'fallbacks.weight.permilage': 'templatePreview.field.permilage',
};

function formatNumber(value: number, locale: string): string {
  return new Intl.NumberFormat(locale).format(value);
}

export function TemplatePreviewSamplesPanel({
  value,
  canEdit,
  onChange,
  onReset,
}: TemplatePreviewSamplesPanelProps) {
  const tt = useTemplatePreviewSamplesT();
  const locale = useActiveLocale();
  const [tab, setTab] = useState<PreviewSamplesTab>('general');
  const [confirmReset, setConfirmReset] = useState(false);
  const bytes = useMemo(() => templatePreviewSamplesByteSize(value), [value]);
  const overBudget = bytes > TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES;
  const validationIssues = useMemo(
    () => validateTemplatePreviewSamples(value).filter((issue) => issue.kind !== 'size'),
    [value],
  );
  const update = <Key extends keyof TemplatePreviewSampleSettings>(
    key: Key,
    next: TemplatePreviewSampleSettings[Key],
  ) => onChange({ ...value, [key]: next });
  const sectionProps = { value, canEdit, update };

  const tabs = [
    { id: 'general', label: tt('templatePreview.tab.general'), icon: <Icon.FileText /> },
    { id: 'entity', label: tt('templatePreview.tab.entity'), icon: <Icon.Users /> },
    { id: 'meeting', label: tt('templatePreview.tab.meeting'), icon: <Icon.Calendar /> },
    { id: 'agenda', label: tt('templatePreview.tab.agenda'), icon: <Icon.Layers /> },
    { id: 'convening', label: tt('templatePreview.tab.convening'), icon: <Icon.Bell /> },
    { id: 'evidence', label: tt('templatePreview.tab.evidence'), icon: <Icon.Seal /> },
    { id: 'book', label: tt('templatePreview.tab.book'), icon: <Icon.BookClosed /> },
    { id: 'fallbacks', label: tt('templatePreview.tab.fallbacks'), icon: <Icon.Layers /> },
  ] satisfies { id: PreviewSamplesTab; label: string; icon: ReactNode }[];

  return (
    <div className="stack template-preview-samples">
      <div className="template-preview-samples__intro">
        <div>
          <p className="field__hint">{tt('templatePreview.intro')}</p>
          <Badge tone={overBudget ? 'error' : 'neutral'}>
            {tt('templatePreview.size', {
              used: formatNumber(bytes, locale),
              limit: formatNumber(TEMPLATE_PREVIEW_SAMPLE_MAX_BYTES, locale),
            })}
          </Badge>
        </div>
        <Button
          type="button"
          variant="secondary"
          disabled={!canEdit}
          onClick={() => setConfirmReset(true)}
        >
          {tt('templatePreview.action.reset')}
        </Button>
      </div>

      <InlineWarning tone="warn" title={tt('templatePreview.visibility.title')}>
        {tt('templatePreview.visibility.body')}
      </InlineWarning>
      {!canEdit ? (
        <InlineWarning tone="info">{tt('templatePreview.permission')}</InlineWarning>
      ) : null}
      {overBudget ? (
        <InlineWarning tone="error">{tt('templatePreview.sizeExceeded')}</InlineWarning>
      ) : null}
      {validationIssues.length > 0 ? (
        <InlineWarning tone="error" title={tt('templatePreview.validation.title')}>
          <p>{tt('templatePreview.validation.intro')}</p>
          <ul>
            {validationIssues.map((issue, index) => {
              const field = tt(VALIDATION_FIELD_KEYS[issue.path] ?? 'templatePreview.column.value');
              let message: string;
              if (issue.kind === 'collection') {
                message = tt('templatePreview.validation.collection', {
                  field,
                  count: issue.value,
                  min: issue.min,
                  max: issue.max,
                });
              } else if (issue.kind === 'number') {
                message = tt('templatePreview.validation.number', {
                  field,
                  min: issue.min,
                  max: issue.max,
                });
              } else if (issue.kind === 'required') {
                message = tt('templatePreview.validation.required', { field });
              } else if (issue.kind === 'length') {
                message = tt('templatePreview.validation.length', {
                  field,
                  count: issue.value,
                  max: issue.max,
                });
              } else if (issue.kind === 'format') {
                message = tt('templatePreview.validation.format', {
                  field,
                  format: tt(`templatePreview.validation.format.${issue.format}`),
                });
              } else if (issue.kind === 'characters') {
                message = tt('templatePreview.validation.characters', { field });
              } else {
                message = tt('templatePreview.validation.duplicate', {
                  field,
                  value: issue.value,
                });
              }
              return <li key={`${issue.kind}:${issue.path}:${index}`}>{message}</li>;
            })}
          </ul>
        </InlineWarning>
      ) : null}

      <div className="template-preview-samples__tabs">
        <SubNav
          items={tabs}
          active={tab}
          onSelect={setTab}
          ariaLabel={tt('templatePreview.tabs.aria')}
        />
      </div>

      <div className="route-transition stack" key={tab}>
        {tab === 'general' ? <TemplatePreviewGeneralSection {...sectionProps} /> : null}
        {tab === 'entity' ? <TemplatePreviewEntitySection {...sectionProps} /> : null}
        {tab === 'meeting' ? <TemplatePreviewSampleMeetingSection {...sectionProps} /> : null}
        {tab === 'agenda' ? <TemplatePreviewSampleAgendaSection {...sectionProps} /> : null}
        {tab === 'convening' ? <TemplatePreviewSampleConveningSection {...sectionProps} /> : null}
        {tab === 'evidence' ? <TemplatePreviewSampleEvidenceSection {...sectionProps} /> : null}
        {tab === 'book' ? <TemplatePreviewSampleBookSection {...sectionProps} /> : null}
        {tab === 'fallbacks' ? <TemplatePreviewSampleFallbacksSection {...sectionProps} /> : null}
      </div>

      <ConfirmActionModal
        open={confirmReset}
        onClose={() => setConfirmReset(false)}
        title={tt('templatePreview.reset.title')}
        intro={tt('templatePreview.reset.body')}
        confirmLabel={tt('templatePreview.reset.confirm')}
        pendingLabel={tt('templatePreview.reset.pending')}
        onConfirm={async () => {
          onReset();
          setConfirmReset(false);
        }}
      />
    </div>
  );
}
