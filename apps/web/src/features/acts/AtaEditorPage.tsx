/**
 * AtaEditorPage — the centerpiece editor (plan t5 §features/acts; restructured t31).
 *
 * It composes: meeting metadata (date/time/place + present/represented counts), the
 * mesa (bureau — presidente + secretários), the ordem de trabalhos (agenda), a free-text
 * deliberations editor with a read-only preview, a structured per-item deliberations
 * editor (text + VoteResult + member statements), act-scoped follow-up tooling, referenced
 * documents, signatories and attachments panels, a lifecycle stepper, a live CompliancePanel, and a SealAction that
 * stays disabled until `seal_allowed`. Once the act is Sealed/Archived it is read-only.
 *
 * The mesa presidente is the seal-unblocker: the CSC pack (csc-art63/v2) raises a blocking
 * `CSC-63/mesa-presidente` Error until it is filled, so the input below is what lets a
 * commercial-company ata reach «Conforme». The free-text `deliberations` field stays a
 * valid substance path alongside `deliberation_items` (plan R1/R3 — additive coexistence).
 * The SIG-03 manual-signature warning (UX-41) shows during signing because there is no
 * qualified-signature backend yet — sealing attests a manual signature.
 */
import { useEffect, useId, useState, type FormEvent } from 'react';
import { createPortal } from 'react-dom';
import { Link, useLocation, useParams } from 'react-router-dom';
import {
  useAct,
  useAdvanceAct,
  useArchiveAct,
  useBook,
  useCompliance,
  useEntity,
  useSealAct,
  useUpdateAct,
  useVerifyActHumanReview,
} from '../../api/hooks';
import {
  actStateLabels,
  attachmentKindLabels,
  dispatchChannelLabels,
  meetingChannelLabels,
  optionsFrom,
  severityLabels,
  signatoryCapacityLabels,
} from '../../api/labels';
import {
  ACT_STATES,
  ATTACHMENT_KINDS,
  DISPATCH_CHANNELS,
  MEETING_CHANNELS,
  SIGNATORY_CAPACITIES,
  type ActAgendaItem,
  type ActAttachment,
  type ActConvening,
  type ActConveningRecipient,
  type ActDeliberationItem,
  type ActDocumentReference,
  type ActManualSignatureOriginalReference,
  type ActMemberStatement,
  type ActMesa,
  type AiHumanVerificationStatus,
  type AiProvenanceView,
  type ActSecondCall,
  type ActSignatory,
  type ActState,
  type ActView,
  type ActVoteResult,
  type AttachmentKind,
  type ComplianceReport,
  type DispatchChannel,
  type HumanVerificationDecision,
  type MeetingChannel,
  type SignatoryCapacity,
  type WrittenResolutionEvidenceInput,
  type WrittenResolutionReviewReceiptInput,
  type WrittenResolutionReviewReceiptView,
  type WrittenResolutionReviewStatus,
} from '../../api/types';
import { formatAtaNumber } from '../../format';
import { useT } from '../../i18n';
import { formatAiProvenanceReviewPacket } from './aiProvenanceReviewPacket';
import {
  Badge,
  Button,
  Card,
  Digest,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  Skeleton,
  SkeletonText,
  TextArea,
  useToast,
} from '../../ui';
import { useFocusTrap } from '../../ui/useFocusTrap';
import { CompliancePanel } from './CompliancePanel';
import { FollowUpsPanel } from './FollowUpsPanel';
import { ataFieldHelp } from './fieldHelp';
import { ActDocumentPanel, type ActDocumentPanelTarget } from '../documents/ActDocumentPanel';
import { SigningPanel } from '../signing/SigningPanel';
import { GateButton, scopeBook, type CanScope } from '../session/permissions';

// Working (editable) copy of the mutable act fields. Scalars are held as strings for the
// inputs (empty ⇒ absent on save); the structured collections are held as their wire
// shapes so they PATCH back unchanged.
interface Draft {
  title: string;
  channel: MeetingChannel;
  meeting_date: string;
  meeting_time: string;
  place: string;
  attendance_reference: string;
  members_present: string;
  members_represented: string;
  mesa: ActMesa;
  agenda: ActAgendaItem[];
  referenced_documents: ActDocumentReference[];
  deliberations: string;
  deliberation_items: ActDeliberationItem[];
  telematic_evidence: string;
  convening: DraftConvening;
  attachments: ActAttachment[];
  signatories: ActSignatory[];
}

export function actDocumentPanelTargetFromLocation(
  search: string,
  hash: string,
): ActDocumentPanelTarget | undefined {
  const params = new URLSearchParams(search);
  const generatedDocumentId =
    params.get('generated_document_id')?.trim() || params.get('generatedDocument')?.trim() || null;
  const importedDocumentId =
    params.get('imported_document_id')?.trim() || params.get('importedDocument')?.trim() || null;
  const focusParam = params.get('focus')?.trim();
  const focus =
    focusParam === 'dispatch-evidence' || hash === '#generated-dispatch-evidence'
      ? 'dispatch-evidence'
      : focusParam === 'import-review' || hash === '#imported-documents'
        ? 'import-review'
        : null;

  if (!generatedDocumentId && !importedDocumentId && !focus) return undefined;
  return {
    ...(generatedDocumentId ? { generatedDocumentId } : {}),
    ...(importedDocumentId ? { importedDocumentId } : {}),
    ...(focus ? { focus } : {}),
  };
}

interface DraftConvening {
  convener: string;
  convener_capacity: SignatoryCapacity | '';
  dispatch_date: string;
  antecedence_days: string;
  channel: DispatchChannel | '';
  evidence_reference: string;
  recipients: ActConveningRecipient[];
  second_call: ActSecondCall | null;
}

function toDraftConvening(convening: ActConvening | undefined): DraftConvening {
  return {
    convener: convening?.convener ?? '',
    convener_capacity: convening?.convener_capacity ?? '',
    dispatch_date: convening?.dispatch_date ?? '',
    antecedence_days: convening?.antecedence_days == null ? '' : String(convening.antecedence_days),
    channel: convening?.channel ?? '',
    evidence_reference: convening?.evidence_reference ?? '',
    recipients: convening?.recipients ?? [],
    second_call: convening?.second_call ?? null,
  };
}

function toDraft(act: ActView): Draft {
  return {
    title: act.title,
    channel: act.channel,
    meeting_date: act.meeting_date ?? '',
    meeting_time: act.meeting_time ?? '',
    place: act.place ?? '',
    attendance_reference: act.attendance_reference ?? '',
    members_present: act.members_present == null ? '' : String(act.members_present),
    members_represented: act.members_represented == null ? '' : String(act.members_represented),
    mesa: { presidente: act.mesa.presidente, secretarios: act.mesa.secretarios },
    agenda: act.agenda,
    referenced_documents: act.referenced_documents,
    deliberations: act.deliberations,
    deliberation_items: act.deliberation_items,
    telematic_evidence: act.telematic_evidence ?? '',
    convening: toDraftConvening(act.convening),
    attachments: act.attachments,
    signatories: act.signatories,
  };
}

/** Trimmed-empty → null, so the API stores an absent optional rather than "". */
const orNull = (s: string): string | null => (s.trim() === '' ? null : s);

/** Parse an optional non-negative integer field; blank/invalid → null. */
function orNullNum(s: string): number | null {
  const trimmed = s.trim();
  if (trimmed === '') return null;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : null;
}

const WRITTEN_RESOLUTION_GUARDRAIL_ACKNOWLEDGEMENTS = [
  'local_metadata_only',
  'no_consent_quorum_identity_or_legal_proof',
  'no_external_validation_provider_authority_or_completion_claim',
] as const;

const WRITTEN_RESOLUTION_FALSE_CLAIM_FLAGS = {
  consent_proof_claimed: false,
  quorum_proof_claimed: false,
  identity_proof_claimed: false,
  legal_acceptance_claimed: false,
  legal_sufficiency_claimed: false,
  external_validation_claimed: false,
  automatic_approval_claimed: false,
  authority_certified_claimed: false,
} as const;

const CONVOCATION_NOTICE_ADVISORY_TITLE = 'Aviso local da convocatória estatutária';
const CONVOCATION_NOTICE_NO_CLAIMS =
  'Apenas metadados locais; não afirma suficiência jurídica, entrega externa válida nem conclusão do workflow.';

function writtenResolutionReviewStatusOptions(
  t: ReturnType<typeof useT>,
): { value: WrittenResolutionReviewStatus; label: string }[] {
  return [
    { value: 'reviewed', label: t('acts.writtenResolution.reviewStatusOption.reviewed') },
    {
      value: 'needs_follow_up',
      label: t('acts.writtenResolution.reviewStatusOption.needsFollowUp'),
    },
  ];
}

interface WrittenResolutionReceiptDraft {
  reviewer: string;
  reviewed_at: string;
  status: WrittenResolutionReviewStatus;
  evidence_label: string;
  evidence_locator: string;
  evidence_digest: string;
  note: string;
  guardrail_acknowledged: boolean;
}

function nowRfc3339(): string {
  return new Date().toISOString();
}

function newWrittenResolutionReceiptDraft(): WrittenResolutionReceiptDraft {
  return {
    reviewer: '',
    reviewed_at: nowRfc3339(),
    status: 'reviewed',
    evidence_label: '',
    evidence_locator: '',
    evidence_digest: '',
    note: '',
    guardrail_acknowledged: false,
  };
}

function receiptDraftReady(draft: WrittenResolutionReceiptDraft): boolean {
  return (
    draft.reviewer.trim() !== '' &&
    draft.reviewed_at.trim() !== '' &&
    draft.evidence_label.trim() !== '' &&
    (draft.evidence_locator.trim() !== '' || draft.evidence_digest.trim() !== '') &&
    draft.guardrail_acknowledged
  );
}

function existingWrittenResolutionReceiptToInput(
  receipt: WrittenResolutionReviewReceiptView,
): WrittenResolutionReviewReceiptInput {
  return {
    reviewer: receipt.reviewer,
    reviewed_at: receipt.reviewed_at,
    status: receipt.status,
    guardrail_acknowledgements: receipt.guardrail_acknowledgements,
    evidence: (receipt.evidence ?? []).map((evidence) => ({
      label: evidence.label,
      locator: evidence.locator,
      digest: evidence.digest,
    })),
    note: receipt.note,
    ...WRITTEN_RESOLUTION_FALSE_CLAIM_FLAGS,
  };
}

function receiptDraftToInput(
  draft: WrittenResolutionReceiptDraft,
): WrittenResolutionReviewReceiptInput {
  return {
    reviewer: draft.reviewer.trim(),
    reviewed_at: draft.reviewed_at.trim(),
    status: draft.status,
    guardrail_acknowledgements: [...WRITTEN_RESOLUTION_GUARDRAIL_ACKNOWLEDGEMENTS],
    evidence: [
      {
        label: draft.evidence_label.trim(),
        locator: orNull(draft.evidence_locator),
        digest: orNull(draft.evidence_digest),
      },
    ],
    note: orNull(draft.note),
    ...WRITTEN_RESOLUTION_FALSE_CLAIM_FLAGS,
  };
}

function writtenResolutionEvidencePatch(
  act: ActView,
  receiptDraft: WrittenResolutionReceiptDraft,
): WrittenResolutionEvidenceInput {
  const current = act.written_resolution_evidence;
  return {
    note: current?.note ?? null,
    checklist: (current?.checklist ?? []).map((item) => ({
      label: item.label,
      reference: item.reference,
      digest: item.digest,
      note: item.note,
    })),
    review_receipts: [
      ...(current?.review_receipts ?? []).map(existingWrittenResolutionReceiptToInput),
      receiptDraftToInput(receiptDraft),
    ],
  };
}

/** The next lifecycle target, capped at Signing (Sealed/Archived need the seal flow). */
function nextState(current: ActState): ActState | null {
  const idx = ACT_STATES.indexOf(current);
  const signingIdx = ACT_STATES.indexOf('Signing');
  if (idx < 0 || idx >= signingIdx) return null;
  return ACT_STATES[idx + 1];
}

/** Re-number an agenda list 1..n after an add/remove/reorder so numbers stay contiguous. */
function renumber(items: ActAgendaItem[]): ActAgendaItem[] {
  return items.map((item, i) => ({ ...item, number: i + 1 }));
}

function DeliberationsPreview({ text }: { text: string }) {
  const t = useT();
  const paragraphs = text.split(/\n{2,}/).filter((p) => p.trim().length > 0);
  if (paragraphs.length === 0) {
    return <p className="muted">{t('acts.noDeliberacoes')}</p>;
  }
  return (
    <div className="preview">
      {paragraphs.map((para, i) => (
        <p key={i}>
          {para.split('\n').map((line, j) => (
            <span key={j}>
              {line}
              {j < para.split('\n').length - 1 ? <br /> : null}
            </span>
          ))}
        </p>
      ))}
    </div>
  );
}

// --- Mesa (bureau) --------------------------------------------------------------

function MesaEditor({
  mesa,
  disabled,
  onChange,
}: {
  mesa: ActMesa;
  disabled: boolean;
  onChange: (next: ActMesa) => void;
}) {
  const t = useT();
  const secretarios = mesa.secretarios;
  return (
    <div className="form">
      <Field
        label={t('acts.mesa.presidente')}
        htmlFor="ed-presidente"
        hint={t('acts.mesa.hint')}
        help={ataFieldHelp.mesaPresidente}
      >
        <Input
          id="ed-presidente"
          value={mesa.presidente ?? ''}
          disabled={disabled}
          placeholder={t('acts.mesa.presidentePlaceholder')}
          onChange={(e) => onChange({ ...mesa, presidente: e.target.value })}
        />
      </Field>
      <Field label={t('acts.mesa.secretarios')} help={ataFieldHelp.mesaSecretarios}>
        <div className="stack--tight">
          {secretarios.map((name, i) => (
            <div className="rowline" key={i}>
              <Input
                aria-label={t('acts.mesa.secretarioAria')}
                placeholder={t('acts.namePlaceholder')}
                value={name}
                disabled={disabled}
                onChange={(e) =>
                  onChange({
                    ...mesa,
                    secretarios: secretarios.map((s, idx) => (idx === i ? e.target.value : s)),
                  })
                }
              />
              {!disabled ? (
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.Trash />}
                  onClick={() =>
                    onChange({ ...mesa, secretarios: secretarios.filter((_, idx) => idx !== i) })
                  }
                >
                  {t('common.remove')}
                </Button>
              ) : null}
            </div>
          ))}
          {!disabled ? (
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={() => onChange({ ...mesa, secretarios: [...secretarios, ''] })}
            >
              {t('acts.mesa.addSecretario')}
            </Button>
          ) : null}
          {secretarios.length === 0 && disabled ? (
            <p className="muted">{t('acts.mesa.noSecretarios')}</p>
          ) : null}
        </div>
      </Field>
    </div>
  );
}

// --- Agenda (ordem de trabalhos) ------------------------------------------------

function AgendaEditor({
  agenda,
  disabled,
  onChange,
}: {
  agenda: ActAgendaItem[];
  disabled: boolean;
  onChange: (next: ActAgendaItem[]) => void;
}) {
  const t = useT();
  const swap = (i: number, j: number) => {
    if (j < 0 || j >= agenda.length) return;
    const next = agenda.slice();
    [next[i], next[j]] = [next[j], next[i]];
    onChange(renumber(next));
  };
  return (
    <Field label={t('acts.agenda.itemAria')} help={ataFieldHelp.agendaItem}>
      <div className="stack--tight">
        {agenda.map((item, i) => (
          <div className="rowline" key={i}>
            <span className="agenda__num">{item.number}.</span>
            <Input
              aria-label={t('acts.agenda.itemAria')}
              placeholder={t('acts.agenda.placeholder')}
              value={item.text}
              disabled={disabled}
              onChange={(e) =>
                onChange(agenda.map((a, idx) => (idx === i ? { ...a, text: e.target.value } : a)))
              }
            />
            {!disabled ? (
              <>
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.ArrowUp />}
                  aria-label={t('acts.agenda.moveUp')}
                  disabled={i === 0}
                  onClick={() => swap(i, i - 1)}
                />
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.ArrowDown />}
                  aria-label={t('acts.agenda.moveDown')}
                  disabled={i === agenda.length - 1}
                  onClick={() => swap(i, i + 1)}
                />
                <Button
                  type="button"
                  variant="ghost"
                  icon={<Icon.Trash />}
                  onClick={() => onChange(renumber(agenda.filter((_, idx) => idx !== i)))}
                >
                  {t('common.remove')}
                </Button>
              </>
            ) : null}
          </div>
        ))}
        {!disabled ? (
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            onClick={() => onChange(renumber([...agenda, { number: agenda.length + 1, text: '' }]))}
          >
            {t('acts.agenda.add')}
          </Button>
        ) : null}
        {agenda.length === 0 && disabled ? <p className="muted">{t('acts.agenda.none')}</p> : null}
      </div>
    </Field>
  );
}

// --- Vote result ----------------------------------------------------------------

type VoteMode = 'none' | 'Unanimous' | 'Recorded';

function voteMode(vote: ActVoteResult | null): VoteMode {
  return vote === null ? 'none' : vote.type;
}

function VoteEditor({
  vote,
  disabled,
  onChange,
}: {
  vote: ActVoteResult | null;
  disabled: boolean;
  onChange: (next: ActVoteResult | null) => void;
}) {
  const t = useT();
  const mode = voteMode(vote);
  const recorded =
    vote && vote.type === 'Recorded' ? vote : { em_favor: 0, contra: 0, abstencoes: 0 };
  const setRecorded = (patch: Partial<Omit<ActVoteResult & { type: 'Recorded' }, 'type'>>) =>
    onChange({ type: 'Recorded', ...recorded, ...patch });
  const num = (v: string): number => {
    const n = Number(v);
    return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : 0;
  };

  const modeOptions = [
    { value: 'none', label: t('acts.vote.modeNone') },
    { value: 'Unanimous', label: t('acts.vote.modeUnanimous') },
    { value: 'Recorded', label: t('acts.vote.modeRecorded') },
  ];

  return (
    <div className="vote">
      <Field label={t('acts.vote.mode')} help={ataFieldHelp.voteMode}>
        <Select
          aria-label={t('acts.vote.mode')}
          value={mode}
          disabled={disabled}
          options={modeOptions}
          onChange={(e) => {
            const next = e.target.value as VoteMode;
            if (next === 'none') onChange(null);
            else if (next === 'Unanimous') onChange({ type: 'Unanimous' });
            else onChange({ type: 'Recorded', ...recorded });
          }}
        />
      </Field>
      {mode === 'Recorded' ? (
        <div className="rowline">
          <Field label={t('acts.vote.emFavor')} help={ataFieldHelp.voteCount}>
            <Input
              type="number"
              min={0}
              aria-label={t('acts.vote.emFavor')}
              value={recorded.em_favor}
              disabled={disabled}
              onChange={(e) => setRecorded({ em_favor: num(e.target.value) })}
            />
          </Field>
          <Field label={t('acts.vote.contra')} help={ataFieldHelp.voteCount}>
            <Input
              type="number"
              min={0}
              aria-label={t('acts.vote.contra')}
              value={recorded.contra}
              disabled={disabled}
              onChange={(e) => setRecorded({ contra: num(e.target.value) })}
            />
          </Field>
          <Field label={t('acts.vote.abstencoes')} help={ataFieldHelp.voteCount}>
            <Input
              type="number"
              min={0}
              aria-label={t('acts.vote.abstencoes')}
              value={recorded.abstencoes}
              disabled={disabled}
              onChange={(e) => setRecorded({ abstencoes: num(e.target.value) })}
            />
          </Field>
        </div>
      ) : null}
    </div>
  );
}

// --- Member statements (declarações) --------------------------------------------

function StatementsEditor({
  statements,
  disabled,
  onChange,
}: {
  statements: ActMemberStatement[];
  disabled: boolean;
  onChange: (next: ActMemberStatement[]) => void;
}) {
  const t = useT();
  const update = (i: number, patch: Partial<ActMemberStatement>) =>
    onChange(statements.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));
  return (
    <Field label={t('acts.statements')} help={ataFieldHelp.statements}>
      <div className="stack--tight">
        {statements.map((s, i) => (
          <div className="rowline" key={i}>
            <Input
              aria-label={t('acts.statements.memberAria')}
              placeholder={t('acts.statements.memberPlaceholder')}
              value={s.member}
              disabled={disabled}
              onChange={(e) => update(i, { member: e.target.value })}
            />
            <Input
              aria-label={t('acts.statements.textAria')}
              placeholder={t('acts.statements.textPlaceholder')}
              value={s.text}
              disabled={disabled}
              onChange={(e) => update(i, { text: e.target.value })}
            />
            {!disabled ? (
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Trash />}
                onClick={() => onChange(statements.filter((_, idx) => idx !== i))}
              >
                {t('common.remove')}
              </Button>
            ) : null}
          </div>
        ))}
        {!disabled ? (
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Plus />}
            onClick={() => onChange([...statements, { member: '', text: '' }])}
          >
            {t('acts.statements.add')}
          </Button>
        ) : null}
        {statements.length === 0 && disabled ? (
          <p className="muted">{t('acts.statements.none')}</p>
        ) : null}
      </div>
    </Field>
  );
}

// --- Structured deliberations ---------------------------------------------------

function DeliberationItemsEditor({
  items,
  agenda,
  disabled,
  onChange,
}: {
  items: ActDeliberationItem[];
  agenda: ActAgendaItem[];
  disabled: boolean;
  onChange: (next: ActDeliberationItem[]) => void;
}) {
  const t = useT();
  const update = (i: number, patch: Partial<ActDeliberationItem>) =>
    onChange(items.map((it, idx) => (idx === i ? { ...it, ...patch } : it)));
  const agendaOptions = [
    { value: '', label: t('acts.deliberationItems.agendaNone') },
    ...agenda.map((a) => ({ value: String(a.number), label: `${a.number}. ${a.text}`.trim() })),
  ];

  return (
    <div className="stack--tight">
      {items.map((item, i) => (
        <div className="delib-item" key={i}>
          <div className="delib-item__head">
            <span className="card__label">{t('acts.deliberationItems.item', { n: i + 1 })}</span>
            {!disabled ? (
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Trash />}
                onClick={() => onChange(items.filter((_, idx) => idx !== i))}
              >
                {t('common.remove')}
              </Button>
            ) : null}
          </div>
          <Field
            label={t('acts.deliberationItems.agendaLink')}
            help={ataFieldHelp.structuredAgenda}
          >
            <Select
              aria-label={t('acts.deliberationItems.agendaLink')}
              value={item.agenda_number == null ? '' : String(item.agenda_number)}
              disabled={disabled}
              options={agendaOptions}
              onChange={(e) =>
                update(i, { agenda_number: e.target.value === '' ? null : Number(e.target.value) })
              }
            />
          </Field>
          <Field label={t('acts.deliberationItems.textAria')} help={ataFieldHelp.structuredText}>
            <TextArea
              rows={3}
              aria-label={t('acts.deliberationItems.textAria')}
              placeholder={t('acts.deliberationItems.textPlaceholder')}
              value={item.text}
              disabled={disabled}
              onChange={(e) => update(i, { text: e.target.value })}
            />
          </Field>
          <VoteEditor
            vote={item.vote}
            disabled={disabled}
            onChange={(vote) => update(i, { vote })}
          />
          <StatementsEditor
            statements={item.statements}
            disabled={disabled}
            onChange={(statements) => update(i, { statements })}
          />
        </div>
      ))}
      {!disabled ? (
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() =>
            onChange([...items, { agenda_number: null, text: '', vote: null, statements: [] }])
          }
        >
          {t('acts.deliberationItems.add')}
        </Button>
      ) : null}
      {items.length === 0 && disabled ? (
        <p className="muted">{t('acts.deliberationItems.none')}</p>
      ) : null}
    </div>
  );
}

// --- Referenced documents -------------------------------------------------------

function ReferencedDocumentsEditor({
  documents,
  disabled,
  onChange,
}: {
  documents: ActDocumentReference[];
  disabled: boolean;
  onChange: (next: ActDocumentReference[]) => void;
}) {
  const t = useT();
  const update = (i: number, patch: Partial<ActDocumentReference>) =>
    onChange(documents.map((d, idx) => (idx === i ? { ...d, ...patch } : d)));
  return (
    <div className="stack--tight">
      {documents.map((doc, i) => (
        <div className="rowline" key={i}>
          <Field
            label={t('acts.referencedDocuments.labelAria')}
            help={ataFieldHelp.referencedDocumentLabel}
          >
            <Input
              aria-label={t('acts.referencedDocuments.labelAria')}
              placeholder={t('acts.referencedDocuments.labelPlaceholder')}
              value={doc.label}
              disabled={disabled}
              onChange={(e) => update(i, { label: e.target.value })}
            />
          </Field>
          <Field
            label={t('acts.referencedDocuments.refAria')}
            help={ataFieldHelp.referencedDocumentRef}
          >
            <Input
              aria-label={t('acts.referencedDocuments.refAria')}
              placeholder={t('acts.referencedDocuments.refPlaceholder')}
              value={doc.reference ?? ''}
              disabled={disabled}
              onChange={(e) => update(i, { reference: orNull(e.target.value) })}
            />
          </Field>
          {!disabled ? (
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Trash />}
              onClick={() => onChange(documents.filter((_, idx) => idx !== i))}
            >
              {t('common.remove')}
            </Button>
          ) : null}
        </div>
      ))}
      {!disabled ? (
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() => onChange([...documents, { label: '', reference: null }])}
        >
          {t('acts.referencedDocuments.add')}
        </Button>
      ) : null}
      {documents.length === 0 && disabled ? (
        <p className="muted">{t('acts.referencedDocuments.none')}</p>
      ) : null}
    </div>
  );
}

function SignatoriesEditor({
  signatories,
  disabled,
  onChange,
}: {
  signatories: ActSignatory[];
  disabled: boolean;
  onChange: (next: ActSignatory[]) => void;
}) {
  const t = useT();
  const update = (i: number, patch: Partial<ActSignatory>) =>
    onChange(signatories.map((s, idx) => (idx === i ? { ...s, ...patch } : s)));

  return (
    <div className="stack--tight">
      {signatories.map((s, i) => (
        <div className="rowline" key={i}>
          <Field label={t('acts.signatoryNameAria')} help={ataFieldHelp.signatoryName}>
            <Input
              aria-label={t('acts.signatoryNameAria')}
              placeholder={t('acts.namePlaceholder')}
              value={s.name}
              disabled={disabled}
              onChange={(e) => update(i, { name: e.target.value })}
            />
          </Field>
          <Field label={t('registry.email.label')}>
            <Input
              type="email"
              aria-label={t('registry.email.label')}
              placeholder={t('registry.email.placeholder')}
              value={s.email ?? ''}
              disabled={disabled}
              autoComplete="email"
              onChange={(e) => update(i, { email: orNull(e.target.value) })}
            />
          </Field>
          <Field label={t('acts.capacityAria')} help={ataFieldHelp.signatoryCapacity}>
            <Select
              aria-label={t('acts.capacityAria')}
              value={s.capacity}
              disabled={disabled}
              onChange={(e) => update(i, { capacity: e.target.value as SignatoryCapacity })}
              options={optionsFrom(SIGNATORY_CAPACITIES, signatoryCapacityLabels)}
            />
          </Field>
          {s.capacity === 'CondoOwner' ? (
            <Field label={t('acts.signatoryPermilageAria')} help={ataFieldHelp.signatoryPermilage}>
              <Input
                className="input--permilage"
                type="number"
                min={0}
                max={1000}
                aria-label={t('acts.signatoryPermilageAria')}
                placeholder={t('acts.signatoryPermilagePlaceholder')}
                value={s.permilage ?? ''}
                disabled={disabled}
                onChange={(e) =>
                  update(i, {
                    permilage: e.target.value === '' ? null : Math.trunc(Number(e.target.value)),
                  })
                }
              />
            </Field>
          ) : null}
          <span className="field__labelrow">
            <label className="check">
              <input
                type="checkbox"
                checked={s.signed}
                disabled={disabled}
                onChange={(e) => update(i, { signed: e.target.checked })}
              />{' '}
              {t('acts.signed')}
            </label>
            <FieldHelp text={ataFieldHelp.signatorySigned} />
          </span>
          {!disabled ? (
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Trash />}
              onClick={() => onChange(signatories.filter((_, idx) => idx !== i))}
            >
              {t('common.remove')}
            </Button>
          ) : null}
        </div>
      ))}
      {!disabled ? (
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() =>
            onChange([...signatories, { name: '', capacity: 'Member', signed: false }])
          }
        >
          {t('acts.addSignatory')}
        </Button>
      ) : null}
      {signatories.length === 0 && disabled ? (
        <p className="muted">{t('acts.noSignatories')}</p>
      ) : null}
    </div>
  );
}

function AttachmentsEditor({
  attachments,
  disabled,
  onChange,
}: {
  attachments: ActAttachment[];
  disabled: boolean;
  onChange: (next: ActAttachment[]) => void;
}) {
  const t = useT();
  const update = (i: number, patch: Partial<ActAttachment>) =>
    onChange(attachments.map((a, idx) => (idx === i ? { ...a, ...patch } : a)));

  return (
    <div className="stack--tight">
      {attachments.map((a, i) => (
        <div className="rowline" key={i}>
          <Field label={t('acts.attachmentDescAria')} help={ataFieldHelp.attachmentLabel}>
            <Input
              aria-label={t('acts.attachmentDescAria')}
              placeholder={t('acts.descPlaceholder')}
              value={a.label}
              disabled={disabled}
              onChange={(e) => update(i, { label: e.target.value })}
            />
          </Field>
          <Field label={t('acts.attachmentKindAria')} help={ataFieldHelp.attachmentKind}>
            <Select
              aria-label={t('acts.attachmentKindAria')}
              value={a.kind}
              disabled={disabled}
              onChange={(e) => update(i, { kind: e.target.value as AttachmentKind })}
              options={optionsFrom(ATTACHMENT_KINDS, attachmentKindLabels)}
            />
          </Field>
          {a.digest ? (
            <code className="mono" title={a.digest}>
              {a.digest.slice(0, 10)}…
            </code>
          ) : null}
          <span className="field__labelrow">
            <label className="check">
              <input
                type="checkbox"
                checked={a.beginning_of_proof ?? false}
                disabled={disabled}
                onChange={(e) => update(i, { beginning_of_proof: e.target.checked })}
              />{' '}
              {t('acts.attachment.beginningOfProof')}
            </label>
            <FieldHelp text={ataFieldHelp.beginningOfProof} />
          </span>
          {!disabled ? (
            <Button
              type="button"
              variant="ghost"
              icon={<Icon.Trash />}
              onClick={() => onChange(attachments.filter((_, idx) => idx !== i))}
            >
              {t('common.remove')}
            </Button>
          ) : null}
        </div>
      ))}
      {!disabled ? (
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() =>
            onChange([
              ...attachments,
              { label: '', kind: 'Exhibit', digest: null, beginning_of_proof: false },
            ])
          }
        >
          {t('acts.addAttachment')}
        </Button>
      ) : null}
      {attachments.length === 0 && disabled ? (
        <p className="muted">{t('acts.noAttachments')}</p>
      ) : null}
    </div>
  );
}

function writtenResolutionReviewStatusLabel(
  t: ReturnType<typeof useT>,
  status: WrittenResolutionReviewStatus,
): string {
  switch (status) {
    case 'reviewed':
      return t('acts.writtenResolution.status.reviewed');
    case 'needs_follow_up':
      return t('acts.writtenResolution.status.needsFollowUp');
    default:
      return (status as string)?.trim() || t('acts.writtenResolution.status.notRecorded');
  }
}

function WrittenResolutionReceiptEditor({
  act,
  receiptDraft,
  readOnly,
  pending,
  error,
  scope,
  onDraftChange,
  onSubmit,
}: {
  act: ActView;
  receiptDraft: WrittenResolutionReceiptDraft;
  readOnly: boolean;
  pending: boolean;
  error: unknown;
  scope: CanScope;
  onDraftChange: (next: WrittenResolutionReceiptDraft) => void;
  onSubmit: () => void;
}) {
  const t = useT();
  const receipts = act.written_resolution_evidence?.review_receipts ?? [];
  const ready = receiptDraftReady(receiptDraft) && !pending;
  const setReceipt = <K extends keyof WrittenResolutionReceiptDraft>(
    key: K,
    value: WrittenResolutionReceiptDraft[K],
  ) => onDraftChange({ ...receiptDraft, [key]: value });

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (ready) onSubmit();
  }

  return (
    <div className="stack--tight">
      <section className="stack--tight" aria-label={t('acts.writtenResolution.history.label')}>
        <div className="row-wrap">
          <span className="card__label">{t('acts.writtenResolution.history.label')}</span>
          <Badge tone={receipts.length > 0 ? 'ok' : 'warn'}>{receipts.length}</Badge>
        </div>
        {receipts.length > 0 ? (
          <ol className="stack--tight">
            {receipts.map((receipt, i) => (
              <li key={`${receipt.reviewed_at}-${receipt.reviewer}-${i}`} className="stack--tight">
                <div className="row-wrap">
                  <Badge tone={receipt.status === 'reviewed' ? 'ok' : 'warn'}>
                    {writtenResolutionReviewStatusLabel(t, receipt.status)}
                  </Badge>
                  <span className="mono">{receipt.reviewer}</span>
                  <time className="mono" dateTime={receipt.reviewed_at}>
                    {receipt.reviewed_at}
                  </time>
                </div>
                <dl className="deflist deflist--tight">
                  <div>
                    <dt>{t('acts.writtenResolution.receipt.reviewedEvidence')}</dt>
                    <dd>
                      {(receipt.evidence ?? []).length > 0
                        ? (receipt.evidence ?? [])
                            .map((evidence) =>
                              [
                                evidence.label,
                                evidence.locator ? `locator:${evidence.locator}` : null,
                                evidence.digest ? `digest:${evidence.digest}` : null,
                              ]
                                .filter(Boolean)
                                .join(' | '),
                            )
                            .join('; ')
                        : t('acts.writtenResolution.receipt.notRecorded')}
                    </dd>
                  </div>
                  <div>
                    <dt>{t('acts.writtenResolution.receipt.note')}</dt>
                    <dd>{receipt.note?.trim() || t('acts.writtenResolution.receipt.noNote')}</dd>
                  </div>
                  <div>
                    <dt>{t('acts.writtenResolution.receipt.boundaryFlags')}</dt>
                    <dd className="mono">
                      consent_proof_claimed=false; quorum_proof_claimed=false;
                      identity_proof_claimed=false; legal_acceptance_claimed=false;
                      legal_sufficiency_claimed=false; external_validation_claimed=false;
                      automatic_approval_claimed=false; authority_certified_claimed=false
                    </dd>
                  </div>
                </dl>
              </li>
            ))}
          </ol>
        ) : (
          <p className="muted">{t('acts.writtenResolution.history.empty')}</p>
        )}
      </section>

      {!readOnly ? (
        <form
          className="stack--tight"
          onSubmit={submit}
          aria-label={t('acts.writtenResolution.form.label')}
        >
          {error ? <ErrorNote error={error} /> : null}
          <div className="rowline">
            <Field label={t('acts.writtenResolution.field.reviewer')} htmlFor="wr-receipt-reviewer">
              <Input
                id="wr-receipt-reviewer"
                value={receiptDraft.reviewer}
                disabled={pending}
                onChange={(e) => setReceipt('reviewer', e.target.value)}
              />
            </Field>
            <Field
              label={t('acts.writtenResolution.field.reviewedAt')}
              htmlFor="wr-receipt-reviewed-at"
            >
              <Input
                id="wr-receipt-reviewed-at"
                value={receiptDraft.reviewed_at}
                disabled={pending}
                onChange={(e) => setReceipt('reviewed_at', e.target.value)}
              />
            </Field>
          </div>
          <Field label={t('acts.writtenResolution.field.reviewStatus')} htmlFor="wr-receipt-status">
            <Select
              id="wr-receipt-status"
              value={receiptDraft.status}
              disabled={pending}
              options={writtenResolutionReviewStatusOptions(t)}
              onChange={(e) =>
                setReceipt('status', e.target.value as WrittenResolutionReviewStatus)
              }
            />
          </Field>
          <div className="rowline">
            <Field
              label={t('acts.writtenResolution.field.evidenceLabel')}
              htmlFor="wr-receipt-evidence-label"
            >
              <Input
                id="wr-receipt-evidence-label"
                value={receiptDraft.evidence_label}
                disabled={pending}
                onChange={(e) => setReceipt('evidence_label', e.target.value)}
              />
            </Field>
            <Field
              label={t('acts.writtenResolution.field.evidenceReference')}
              htmlFor="wr-receipt-evidence-locator"
            >
              <Input
                id="wr-receipt-evidence-locator"
                value={receiptDraft.evidence_locator}
                disabled={pending}
                onChange={(e) => setReceipt('evidence_locator', e.target.value)}
              />
            </Field>
          </div>
          <Field
            label={t('acts.writtenResolution.field.evidenceDigest')}
            htmlFor="wr-receipt-evidence-digest"
          >
            <Input
              id="wr-receipt-evidence-digest"
              value={receiptDraft.evidence_digest}
              disabled={pending}
              onChange={(e) => setReceipt('evidence_digest', e.target.value)}
            />
          </Field>
          <Field label={t('acts.writtenResolution.field.receiptNotes')} htmlFor="wr-receipt-note">
            <TextArea
              id="wr-receipt-note"
              rows={3}
              value={receiptDraft.note}
              disabled={pending}
              onChange={(e) => setReceipt('note', e.target.value)}
            />
          </Field>
          <label className="checkline">
            <input
              type="checkbox"
              checked={receiptDraft.guardrail_acknowledged}
              disabled={pending}
              onChange={(e) => setReceipt('guardrail_acknowledged', e.target.checked)}
            />
            {t('acts.writtenResolution.guardrail')}
          </label>
          <p className="mono">
            consent_proof_claimed=false; quorum_proof_claimed=false; identity_proof_claimed=false;
            legal_sufficiency_claimed=false; external_validation_claimed=false;
            automatic_approval_claimed=false; authority_certified_claimed=false
          </p>
          <GateButton
            perm="act.edit"
            scope={scope}
            type="submit"
            variant="primary"
            icon={<Icon.Check />}
            disabled={!ready}
          >
            {pending
              ? t('acts.writtenResolution.submit.recording')
              : t('acts.writtenResolution.submit.record')}
          </GateButton>
        </form>
      ) : null}
    </div>
  );
}

function convocationNoticeEvidenceMissing(convening: DraftConvening): boolean {
  return (
    convening.dispatch_date.trim() === '' ||
    convening.channel === '' ||
    convening.antecedence_days.trim() === '' ||
    convening.evidence_reference.trim() === ''
  );
}

function ConvocationNoticeAdvisoryCue({
  meetingDate,
  convening,
}: {
  meetingDate: string;
  convening: DraftConvening;
}) {
  const missingMeetingDate = meetingDate.trim() === '';
  const missingEvidence = convocationNoticeEvidenceMissing(convening);
  if (!missingMeetingDate && !missingEvidence) return null;

  return (
    <InlineWarning tone="info" title={CONVOCATION_NOTICE_ADVISORY_TITLE}>
      <ul className="stack--tight">
        {missingMeetingDate ? (
          <li>Registe a data da reunião para calcular a data local de aviso.</li>
        ) : null}
        {missingEvidence ? (
          <li>
            Registe data/meio de expedição, antecedência efetiva e referência da prova conservada.
          </li>
        ) : null}
      </ul>
      <p className="muted">{CONVOCATION_NOTICE_NO_CLAIMS}</p>
    </InlineWarning>
  );
}

function ConveningEditor({
  convening,
  disabled,
  onChange,
}: {
  convening: DraftConvening;
  disabled: boolean;
  onChange: (next: DraftConvening) => void;
}) {
  const t = useT();
  const channelOptions = [
    { value: '', label: t('acts.convening.channelNone') },
    ...optionsFrom(DISPATCH_CHANNELS, dispatchChannelLabels),
  ];
  const setConvening = <K extends keyof DraftConvening>(key: K, value: DraftConvening[K]) =>
    onChange({ ...convening, [key]: value });

  return (
    <div className="form">
      <div className="rowline">
        <Field
          label={t('acts.convening.dispatchDate')}
          htmlFor="ed-convening-date"
          help={ataFieldHelp.conveningDispatchDate}
        >
          <Input
            id="ed-convening-date"
            type="date"
            value={convening.dispatch_date}
            disabled={disabled}
            onChange={(e) => setConvening('dispatch_date', e.target.value)}
          />
        </Field>
        <Field
          label={t('acts.convening.channel')}
          htmlFor="ed-convening-channel"
          help={ataFieldHelp.conveningChannel}
        >
          <Select
            id="ed-convening-channel"
            value={convening.channel}
            disabled={disabled}
            onChange={(e) => setConvening('channel', e.target.value as DispatchChannel | '')}
            options={channelOptions}
          />
        </Field>
      </div>
      <div className="rowline">
        <Field
          label={t('acts.convening.antecedenceDays')}
          htmlFor="ed-convening-days"
          help={ataFieldHelp.conveningAntecedenceDays}
        >
          <Input
            id="ed-convening-days"
            type="number"
            min={0}
            value={convening.antecedence_days}
            disabled={disabled}
            onChange={(e) => setConvening('antecedence_days', e.target.value)}
          />
        </Field>
        <Field
          label={t('acts.convening.evidenceReference')}
          htmlFor="ed-convening-evidence"
          help={ataFieldHelp.conveningEvidenceReference}
        >
          <Input
            id="ed-convening-evidence"
            value={convening.evidence_reference}
            disabled={disabled}
            placeholder={t('acts.convening.evidencePlaceholder')}
            onChange={(e) => setConvening('evidence_reference', e.target.value)}
          />
        </Field>
      </div>
    </div>
  );
}

function LifecycleStepper({
  current,
  aiHumanVerificationStatus,
  onAdvance,
  pending,
  scope,
}: {
  current: ActState;
  aiHumanVerificationStatus?: AiHumanVerificationStatus | null;
  onAdvance: (to: ActState) => void;
  pending: boolean;
  scope: CanScope;
}) {
  const t = useT();
  const currentIdx = ACT_STATES.indexOf(current);
  const next = nextState(current);
  const signingBlockedByAiReview =
    current === 'TextApproved' &&
    next === 'Signing' &&
    aiHumanVerificationStatus != null &&
    aiHumanVerificationStatus !== 'accepted_by_human';
  return (
    <div className="stack--tight">
      <ol className="stepper">
        {ACT_STATES.map((state, i) => (
          <li
            key={state}
            className={
              i < currentIdx ? 'step step--done' : i === currentIdx ? 'step step--current' : 'step'
            }
            aria-current={i === currentIdx ? 'step' : undefined}
          >
            {actStateLabels[state]}
          </li>
        ))}
      </ol>
      {next ? (
        <GateButton
          perm="act.advance"
          scope={scope}
          type="button"
          variant="primary"
          icon={<Icon.ArrowRight />}
          disabled={pending || signingBlockedByAiReview}
          onClick={() => onAdvance(next)}
        >
          {pending ? t('acts.advancing') : t('acts.advanceTo', { state: actStateLabels[next] })}
        </GateButton>
      ) : null}
      {signingBlockedByAiReview ? (
        <p className="field__hint">{t('acts.aiReview.signingBlocked')}</p>
      ) : null}
    </div>
  );
}

function aiHumanVerificationTone(status: AiHumanVerificationStatus): 'warn' | 'ok' | 'error' {
  if (status === 'accepted_by_human') return 'ok';
  if (status === 'rejected_by_human') return 'error';
  return 'warn';
}

function aiHumanVerificationLabel(
  status: AiHumanVerificationStatus,
):
  | 'acts.aiReview.status.accepted'
  | 'acts.aiReview.status.rejected'
  | 'acts.aiReview.status.pending' {
  switch (status) {
    case 'accepted_by_human':
      return 'acts.aiReview.status.accepted';
    case 'rejected_by_human':
      return 'acts.aiReview.status.rejected';
    case 'pending_human_verification':
      return 'acts.aiReview.status.pending';
  }
}

function aiRecordedSourceValue(value: unknown, missingLabel: string): string {
  if (typeof value !== 'string') return missingLabel;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : missingLabel;
}

function aiBooleanFlagLabel(value: unknown): 'true' | 'false' {
  return value === true ? 'true' : 'false';
}

function aiClaimFlagLabel(value: unknown): 'true/claimed' | 'false/no claim' {
  return value === true ? 'true/claimed' : 'false/no claim';
}

const AI_REVIEW_OFFLINE_BOUNDARY =
  'bounded local provenance panel; deterministic local; offline/static review guidance; no bridge/API/AI-provider/hidden-provider calls; no secrets';

const AI_REVIEW_FALSE_BOUNDARY_FLAGS = [
  'legal_validity: false',
  'source_certification: false',
  'provider: false',
  'trust: false',
  'external_validation: false',
  'signature_qualification: false',
] as const;

function aiSourceFieldMissing(
  source: Partial<NonNullable<AiProvenanceView['statement_sources']>[number]>,
): boolean {
  return (
    aiRecordedSourceValue(source.path, '') === '' ||
    aiRecordedSourceValue(source.source_type, '') === '' ||
    aiRecordedSourceValue(source.source_label, '') === '' ||
    aiRecordedSourceValue(source.human_verification_status, '') === ''
  );
}

function AiHumanReviewPanel({
  provenance,
  readOnly,
  note,
  pending,
  pendingDecision,
  error,
  scope,
  onNoteChange,
  onVerify,
}: {
  provenance: AiProvenanceView;
  readOnly: boolean;
  note: string;
  pending: boolean;
  pendingDecision: HumanVerificationDecision | null;
  error: unknown;
  scope: CanScope;
  onNoteChange: (note: string) => void;
  onVerify: (decision: HumanVerificationDecision) => void;
}) {
  const t = useT();
  const toast = useToast();
  const noteId = useId();
  const provenanceId = useId();
  const [copiedPacket, setCopiedPacket] = useState(false);
  const verification = provenance.human_verification;
  const statusLabel = t(aiHumanVerificationLabel(verification.status));
  const reviewedAt = verification.reviewed_at;
  const statementSources = provenance.statement_sources ?? [];
  const reviewPacketJson = formatAiProvenanceReviewPacket(provenance);
  const missingLabel = t('acts.aiReview.missing');
  const sourceTypeCounts = Array.from(
    statementSources.reduce<Map<string, number>>((counts, source) => {
      const sourceType = aiRecordedSourceValue(source.source_type, missingLabel);
      counts.set(sourceType, (counts.get(sourceType) ?? 0) + 1);
      return counts;
    }, new Map()),
  ).sort(([left], [right]) => left.localeCompare(right));
  const statusCounts = Array.from(
    statementSources.reduce<Map<string, number>>((counts, source) => {
      const status = aiRecordedSourceValue(source.human_verification_status, missingLabel);
      counts.set(status, (counts.get(status) ?? 0) + 1);
      return counts;
    }, new Map()),
  ).sort(([left], [right]) => left.localeCompare(right));
  const missingProvenanceRows = statementSources.filter(aiSourceFieldMissing).length;
  const pendingOrUnverifiedRows = statementSources.filter(
    (source) =>
      source.human_verified !== true || source.human_verification_status !== 'accepted_by_human',
  ).length;
  const claimFlaggedRows = statementSources.filter(
    (source) =>
      source.authoritative_source_claimed === true || source.legal_validity_claimed === true,
  ).length;

  async function copyReviewPacket() {
    try {
      await navigator.clipboard.writeText(reviewPacketJson);
      setCopiedPacket(true);
      window.setTimeout(() => setCopiedPacket(false), 1500);
      toast.success(t('acts.aiReview.packet.copied'));
    } catch {
      toast.error(t('acts.aiReview.packet.copyFailed'));
    }
  }

  return (
    <div className="stack--tight ai-review">
      <div className="row-wrap ai-review__status">
        <Badge tone={aiHumanVerificationTone(verification.status)}>{statusLabel}</Badge>
        <Button
          type="button"
          variant="ghost"
          icon={copiedPacket ? <Icon.Check /> : <Icon.Copy />}
          onClick={() => void copyReviewPacket()}
        >
          {copiedPacket ? t('acts.aiReview.packet.copiedButton') : t('acts.aiReview.packet.copy')}
        </Button>
      </div>
      <p className="muted">{t('acts.aiReview.body')}</p>

      <dl className="deflist deflist--tight ai-review__meta">
        <div>
          <dt>{t('acts.aiReview.source')}</dt>
          <dd className="mono">{provenance.source}</dd>
        </div>
        <div>
          <dt>{t('acts.aiReview.tool')}</dt>
          <dd>
            {provenance.tool ? (
              <span className="mono">{provenance.tool}</span>
            ) : (
              t('acts.aiReview.missing')
            )}
          </dd>
        </div>
        {provenance.statement_source ? (
          <div>
            <dt>{t('acts.aiReview.statementSource')}</dt>
            <dd className="mono">{provenance.statement_source}</dd>
          </div>
        ) : null}
        {verification.actor ? (
          <div>
            <dt>{t('acts.aiReview.actor')}</dt>
            <dd className="mono">{verification.actor}</dd>
          </div>
        ) : null}
        {reviewedAt ? (
          <div>
            <dt>{t('acts.aiReview.reviewedAt')}</dt>
            <dd>
              <time className="mono" dateTime={reviewedAt}>
                {reviewedAt}
              </time>
            </dd>
          </div>
        ) : null}
        {verification.note ? (
          <div>
            <dt>{t('acts.aiReview.recordedNote')}</dt>
            <dd>{verification.note}</dd>
          </div>
        ) : null}
      </dl>

      <section className="stack--tight" aria-labelledby={provenanceId}>
        <h3 id={provenanceId}>{t('acts.aiReview.provenance.title')}</h3>
        <dl className="deflist deflist--tight" aria-label={t('acts.aiReview.localSummary')}>
          <div>
            <dt>{t('acts.aiReview.localSummary.total')}</dt>
            <dd>{statementSources.length}</dd>
          </div>
          <div>
            <dt>{t('acts.aiReview.localSummary.pending')}</dt>
            <dd>{pendingOrUnverifiedRows}</dd>
          </div>
          <div>
            <dt>{t('acts.aiReview.localSummary.missing')}</dt>
            <dd>{missingProvenanceRows}</dd>
          </div>
          <div>
            <dt>{t('acts.aiReview.localSummary.claimFlags')}</dt>
            <dd>{claimFlaggedRows}</dd>
          </div>
        </dl>
        <InlineWarning tone="info" title={t('acts.aiReview.noClaim.title')}>
          <ul>
            <li>{t('acts.aiReview.noClaim.provider')}</li>
            <li>{t('acts.aiReview.noClaim.source')}</li>
            <li>{t('acts.aiReview.noClaim.legal')}</li>
            <li>{t('acts.aiReview.noClaim.workflow')}</li>
          </ul>
          <p className="mono">{AI_REVIEW_OFFLINE_BOUNDARY}</p>
          <p className="mono">{AI_REVIEW_FALSE_BOUNDARY_FLAGS.join(' · ')}</p>
        </InlineWarning>
        {statementSources.length > 0 ? (
          <>
            <dl
              className="deflist deflist--tight"
              aria-label={t('acts.aiReview.provenance.summary')}
            >
              {sourceTypeCounts.map(([sourceType, count]) => (
                <div key={sourceType}>
                  <dt className="mono">{sourceType}</dt>
                  <dd>{count}</dd>
                </div>
              ))}
            </dl>
            <dl
              className="deflist deflist--tight"
              aria-label={t('acts.aiReview.provenance.statusSummary')}
            >
              {statusCounts.map(([status, count]) => (
                <div key={status}>
                  <dt className="mono">{status}</dt>
                  <dd>{count}</dd>
                </div>
              ))}
            </dl>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('acts.aiReview.provenance.path')}</th>
                    <th>{t('acts.aiReview.provenance.type')}</th>
                    <th>{t('acts.aiReview.provenance.label')}</th>
                    <th>{t('acts.aiReview.provenance.status')}</th>
                    <th>{t('acts.aiReview.provenance.flags')}</th>
                  </tr>
                </thead>
                <tbody>
                  {statementSources.map((source, index) => {
                    const path = aiRecordedSourceValue(source.path, missingLabel);
                    const sourceType = aiRecordedSourceValue(source.source_type, missingLabel);
                    const sourceLabel = aiRecordedSourceValue(source.source_label, missingLabel);
                    const humanVerificationStatus = aiRecordedSourceValue(
                      source.human_verification_status,
                      missingLabel,
                    );
                    return (
                      <tr key={`${path}:${sourceType}:${sourceLabel}:${index}`}>
                        <td>
                          <span className="mono">{path}</span>
                        </td>
                        <td>
                          <span className="mono">{sourceType}</span>
                        </td>
                        <td>
                          <span className="mono">{sourceLabel}</span>
                        </td>
                        <td>
                          <span className="mono">{humanVerificationStatus}</span>
                        </td>
                        <td>
                          <div className="stack--tight">
                            <span className="mono">
                              {`human_verified=${aiBooleanFlagLabel(source.human_verified)}`}
                            </span>
                            <span className="mono">
                              {`authoritative_source_claimed=${aiClaimFlagLabel(
                                source.authoritative_source_claimed,
                              )}`}
                            </span>
                            <span className="mono">
                              {`legal_validity_claimed=${aiClaimFlagLabel(
                                source.legal_validity_claimed,
                              )}`}
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        ) : (
          <p className="muted">{t('acts.aiReview.provenance.empty')}</p>
        )}
      </section>

      {error ? <ErrorNote error={error} /> : null}

      {!readOnly ? (
        <>
          <Field label={t('acts.aiReview.note')} htmlFor={noteId}>
            <TextArea
              id={noteId}
              rows={3}
              value={note}
              disabled={pending}
              placeholder={t('acts.aiReview.notePlaceholder')}
              onChange={(e) => onNoteChange(e.target.value)}
            />
          </Field>
          <div className="row-wrap ai-review__actions">
            <GateButton
              perm="act.advance"
              scope={scope}
              type="button"
              variant="secondary"
              icon={<Icon.Check />}
              disabled={pending}
              onClick={() => onVerify('accept')}
            >
              {pending && pendingDecision === 'accept'
                ? t('acts.aiReview.recording')
                : t('acts.aiReview.accept')}
            </GateButton>
            <GateButton
              perm="act.advance"
              scope={scope}
              type="button"
              variant="ghost"
              icon={<Icon.Close />}
              disabled={pending}
              onClick={() => onVerify('reject')}
            >
              {pending && pendingDecision === 'reject'
                ? t('acts.aiReview.recording')
                : t('acts.aiReview.reject')}
            </GateButton>
          </div>
        </>
      ) : null}
    </div>
  );
}

/** The PATCH body assembled from the working draft (all §2.4 fields, additive). */
function draftToPatch(draft: Draft) {
  const convening: ActConvening | null =
    draft.convening.dispatch_date.trim() === '' &&
    draft.convening.antecedence_days.trim() === '' &&
    draft.convening.channel === '' &&
    draft.convening.evidence_reference.trim() === '' &&
    draft.convening.convener.trim() === '' &&
    draft.convening.convener_capacity === '' &&
    draft.convening.recipients.length === 0 &&
    draft.convening.second_call == null
      ? null
      : {
          convener: orNull(draft.convening.convener),
          convener_capacity:
            draft.convening.convener_capacity === '' ? null : draft.convening.convener_capacity,
          dispatch_date: orNull(draft.convening.dispatch_date),
          antecedence_days: orNullNum(draft.convening.antecedence_days),
          channel: draft.convening.channel === '' ? null : draft.convening.channel,
          evidence_reference: orNull(draft.convening.evidence_reference),
          recipients: draft.convening.recipients,
          second_call: draft.convening.second_call,
        };

  return {
    title: draft.title,
    channel: draft.channel,
    meeting_date: orNull(draft.meeting_date),
    meeting_time: orNull(draft.meeting_time),
    place: orNull(draft.place),
    attendance_reference: orNull(draft.attendance_reference),
    members_present: orNullNum(draft.members_present),
    members_represented: orNullNum(draft.members_represented),
    mesa: { presidente: orNull(draft.mesa.presidente ?? ''), secretarios: draft.mesa.secretarios },
    agenda: draft.agenda,
    referenced_documents: draft.referenced_documents,
    deliberations: draft.deliberations,
    deliberation_items: draft.deliberation_items,
    telematic_evidence: orNull(draft.telematic_evidence),
    convening,
    attachments: draft.attachments,
    signatories: draft.signatories,
  };
}

interface SealWarningItem {
  code: string;
  message: string;
}

function sealWarningItems(report: ComplianceReport | undefined): SealWarningItem[] {
  if (!report) return [];
  const issueWarnings = report.issues
    .filter((issue) => issue.severity === 'Warning')
    .map((issue) => ({ code: issue.rule_id, message: issue.message }));
  const advisoryWarnings = (report.convening_advisories ?? []).map((advisory) => ({
    code: advisory.code,
    message: advisory.message,
  }));
  return [...issueWarnings, ...advisoryWarnings];
}

function complianceWarningCount(report: ComplianceReport | undefined): number {
  if (!report) return 0;
  return report.warnings + (report.convening_advisories?.length ?? 0);
}

interface ManualSignatureOriginalReferenceDraft {
  storage_reference: string;
  custodian: string;
  note: string;
}

const MANUAL_SIGNATURE_ORIGINAL_REFERENCE_LIMIT = 512;
const MANUAL_SIGNATURE_ORIGINAL_CUSTODIAN_LIMIT = 256;
const MANUAL_SIGNATURE_ORIGINAL_NOTE_LIMIT = 2000;
const MANUAL_SIGNATURE_ORIGINAL_REFERENCE_CONTROL_CHARS = /\p{Cc}/u;

function emptyManualSignatureOriginalReferenceDraft(): ManualSignatureOriginalReferenceDraft {
  return { storage_reference: '', custodian: '', note: '' };
}

function manualSignatureOriginalReferenceReady(
  draft: ManualSignatureOriginalReferenceDraft,
): boolean {
  const storageReference = draft.storage_reference.trim();
  return (
    storageReference.length > 0 &&
    storageReference.length <= MANUAL_SIGNATURE_ORIGINAL_REFERENCE_LIMIT &&
    !MANUAL_SIGNATURE_ORIGINAL_REFERENCE_CONTROL_CHARS.test(draft.storage_reference) &&
    draft.custodian.trim().length <= MANUAL_SIGNATURE_ORIGINAL_CUSTODIAN_LIMIT &&
    draft.note.trim().length <= MANUAL_SIGNATURE_ORIGINAL_NOTE_LIMIT
  );
}

function manualSignatureOriginalReferenceStorageError(
  value: string,
  t: ReturnType<typeof useT>,
): string | undefined {
  const storageReference = value.trim();
  if (storageReference.length > MANUAL_SIGNATURE_ORIGINAL_REFERENCE_LIMIT) {
    return t('acts.manualSignature.originalReference.tooLong');
  }
  if (MANUAL_SIGNATURE_ORIGINAL_REFERENCE_CONTROL_CHARS.test(value)) {
    return t('acts.manualSignature.originalReference.controlCharacters');
  }
  return undefined;
}

function manualSignatureOriginalReferenceFromDraft(
  draft: ManualSignatureOriginalReferenceDraft,
): ActManualSignatureOriginalReference {
  const custodian = draft.custodian.trim();
  const note = draft.note.trim();
  return {
    storage_reference: draft.storage_reference.trim(),
    ...(custodian ? { custodian } : {}),
    ...(note ? { note } : {}),
  };
}

function SealWarningAcknowledgementModal({
  open,
  warnings,
  warningCount,
  checked,
  reference,
  pending,
  onCheckedChange,
  onReferenceChange,
  onClose,
  onConfirm,
}: {
  open: boolean;
  warnings: SealWarningItem[];
  warningCount: number;
  checked: boolean;
  reference: ManualSignatureOriginalReferenceDraft;
  pending: boolean;
  onCheckedChange: (checked: boolean) => void;
  onReferenceChange: (reference: ManualSignatureOriginalReferenceDraft) => void;
  onClose: () => void;
  onConfirm: () => void;
}) {
  const t = useT();
  const titleId = useId();
  const storageReferenceId = useId();
  const custodianId = useId();
  const noteId = useId();
  // Trap Tab focus inside the dialog and restore focus to the opener on close. Called before the
  // `if (!open) return null` early return (rules of hooks). This modal has no autofocus of its
  // own, so the hook's initial-focus branch also supplies it (onto the first focusable control).
  const trapRef = useFocusTrap<HTMLDivElement>(open);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !pending) onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, pending, onClose]);

  if (!open) return null;

  const referenceReady = manualSignatureOriginalReferenceReady(reference);
  const storageReferenceError = manualSignatureOriginalReferenceStorageError(
    reference.storage_reference,
    t,
  );
  const ready = checked && referenceReady && !pending;
  const warningLabel =
    warningCount === 1
      ? t('compliance.warnings.one', { count: warningCount })
      : t('compliance.warnings.other', { count: warningCount });

  function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (ready) onConfirm();
  }

  return createPortal(
    <div
      className="modal-backdrop"
      onClick={() => {
        if (!pending) onClose();
      }}
    >
      <div
        ref={trapRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {t('acts.sealing.warningAck.title')}
          </h2>
        </header>
        <form className="modal__body" onSubmit={submit}>
          <div className="modal__intro">
            <p>{t('acts.sealing.warningAck.body')}</p>
            {warningCount > 0 ? <p className="muted">{warningLabel}</p> : null}
          </div>

          {warnings.length > 0 ? (
            <ul className="issues">
              {warnings.map((warning, i) => (
                <li key={`${warning.code}-${i}`} className="issue issue--warning">
                  <div className="issue__head">
                    <Badge tone="warn">{severityLabels.Warning}</Badge>
                    <code className="mono">{warning.code}</code>
                  </div>
                  <p className="issue__message">{warning.message}</p>
                </li>
              ))}
            </ul>
          ) : null}

          <Field
            label={t('acts.manualSignature.originalReference.label')}
            htmlFor={storageReferenceId}
            hint={t('acts.manualSignature.originalReference.hint')}
            error={storageReferenceError}
          >
            <Input
              id={storageReferenceId}
              value={reference.storage_reference}
              maxLength={MANUAL_SIGNATURE_ORIGINAL_REFERENCE_LIMIT}
              disabled={pending}
              onChange={(e) =>
                onReferenceChange({ ...reference, storage_reference: e.target.value })
              }
            />
          </Field>

          <Field
            label={t('acts.manualSignature.custodian.label')}
            htmlFor={custodianId}
            hint={t('acts.manualSignature.custodian.hint')}
          >
            <Input
              id={custodianId}
              value={reference.custodian}
              maxLength={MANUAL_SIGNATURE_ORIGINAL_CUSTODIAN_LIMIT}
              disabled={pending}
              onChange={(e) => onReferenceChange({ ...reference, custodian: e.target.value })}
            />
          </Field>

          <Field
            label={t('acts.manualSignature.note.label')}
            htmlFor={noteId}
            hint={t('acts.manualSignature.note.hint')}
          >
            <TextArea
              id={noteId}
              value={reference.note}
              maxLength={MANUAL_SIGNATURE_ORIGINAL_NOTE_LIMIT}
              disabled={pending}
              rows={3}
              onChange={(e) => onReferenceChange({ ...reference, note: e.target.value })}
            />
          </Field>

          <label className="checkline">
            <input
              type="checkbox"
              checked={checked}
              disabled={pending}
              onChange={(e) => onCheckedChange(e.target.checked)}
            />
            {t(
              warningCount > 0
                ? 'acts.sealing.warningAck.checkboxWithWarnings'
                : 'acts.sealing.warningAck.checkbox',
            )}
          </label>

          <div className="modal__foot">
            <Button type="button" variant="ghost" disabled={pending} onClick={onClose}>
              {t('common.cancel')}
            </Button>
            <Button type="submit" variant="primary" icon={<Icon.Seal />} disabled={!ready}>
              {pending ? t('acts.sealing.sealing') : t('acts.sealing.warningAck.confirm')}
            </Button>
          </div>
        </form>
      </div>
    </div>,
    document.body,
  );
}

export function AtaEditorPage() {
  const t = useT();
  const toast = useToast();
  const { id = '' } = useParams();
  const location = useLocation();
  const documentPanelTarget = actDocumentPanelTargetFromLocation(location.search, location.hash);
  const act = useAct(id);
  const book = useBook(act.data?.book_id ?? '');
  const entity = useEntity(book.data?.entity_id ?? '');
  const compliance = useCompliance(id);
  const update = useUpdateAct(id);
  const advance = useAdvanceAct(id);
  const humanReview = useVerifyActHumanReview(id);
  const seal = useSealAct(id);
  const archive = useArchiveAct(id);

  const [draft, setDraft] = useState<Draft | null>(null);
  const [humanReviewNote, setHumanReviewNote] = useState('');
  const [humanReviewDecision, setHumanReviewDecision] = useState<HumanVerificationDecision | null>(
    null,
  );
  const [writtenResolutionReceipt, setWrittenResolutionReceipt] =
    useState<WrittenResolutionReceiptDraft>(() => newWrittenResolutionReceiptDraft());
  const [sealWarningsOpen, setSealWarningsOpen] = useState(false);
  const [sealWarningsAcknowledged, setSealWarningsAcknowledged] = useState(false);
  const [manualSignatureOriginalReference, setManualSignatureOriginalReference] =
    useState<ManualSignatureOriginalReferenceDraft>(() =>
      emptyManualSignatureOriginalReferenceDraft(),
    );

  // Seed the working copy once per act identity; refetches of the same act (after an
  // advance/seal) update the read-only header via the cache without clobbering edits.
  useEffect(() => {
    if (act.data) {
      setDraft(toDraft(act.data));
      setWrittenResolutionReceipt(newWrittenResolutionReceiptDraft());
      setManualSignatureOriginalReference(emptyManualSignatureOriginalReferenceDraft());
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [act.data?.id]);

  if (act.isLoading || !draft) {
    return (
      <div className="stack">
        <PageHeader crumbs={t('acts.crumb')} title={<Skeleton width="20rem" height="1.6rem" />} />
        <Card title={t('acts.reuniao')}>
          <div className="form">
            <Skeleton height="2.4rem" />
            <Skeleton height="2.4rem" />
            <Skeleton height="2.4rem" />
          </div>
        </Card>
      </div>
    );
  }
  if (act.error) return <ErrorNote error={act.error} />;
  if (!act.data) return null;

  const a = act.data;
  const readOnly = a.state === 'Sealed' || a.state === 'Archived';
  // Every act lifecycle mutation is gated at the act's BOOK scope (the server resolves the
  // same scope from the act's book_id, t64-E3).
  const bookScope = scopeBook(a.book_id);
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft((d) => (d ? { ...d, [key]: value } : d));

  // R7: every lifecycle mutation keeps its inline ErrorNote; the toast is additive.
  function onSave() {
    if (!draft) return;
    update.mutate(draftToPatch(draft), {
      onSuccess: () => toast.success(t('toast.ata.saved')),
      onError: (e) => toast.error(e),
    });
  }

  function onSubmitWrittenResolutionReceipt() {
    if (!receiptDraftReady(writtenResolutionReceipt)) return;
    update.mutate(
      { written_resolution_evidence: writtenResolutionEvidencePatch(a, writtenResolutionReceipt) },
      {
        onSuccess: () => {
          setWrittenResolutionReceipt(newWrittenResolutionReceiptDraft());
          toast.success(t('toast.ata.saved'));
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function onAdvance(to: ActState) {
    advance.mutate(to, {
      onSuccess: () => toast.success(t('toast.ata.advanced')),
      onError: (e) => toast.error(e),
    });
  }

  function onHumanReview(decision: HumanVerificationDecision) {
    const note = humanReviewNote.trim();
    setHumanReviewDecision(decision);
    humanReview.mutate(
      { decision, note: note === '' ? undefined : note },
      {
        onSuccess: () => {
          setHumanReviewNote('');
          toast.success(
            decision === 'accept'
              ? t('toast.ata.aiReviewAccepted')
              : t('toast.ata.aiReviewRejected'),
          );
        },
        onError: (e) => toast.error(e),
        onSettled: () => setHumanReviewDecision(null),
      },
    );
  }

  function submitSeal(acknowledgeWarnings: boolean) {
    if (!manualSignatureOriginalReferenceReady(manualSignatureOriginalReference)) return;
    seal.mutate(
      {
        ...(acknowledgeWarnings ? { acknowledge_warnings: true } : {}),
        manual_signature_original_reference: manualSignatureOriginalReferenceFromDraft(
          manualSignatureOriginalReference,
        ),
      },
      {
        onSuccess: () => {
          setSealWarningsOpen(false);
          setSealWarningsAcknowledged(false);
          setManualSignatureOriginalReference(emptyManualSignatureOriginalReferenceDraft());
          toast.success(t('toast.ata.sealed'));
        },
        onError: (e) => {
          setSealWarningsOpen(false);
          toast.error(e);
        },
      },
    );
  }

  function onSeal() {
    setSealWarningsAcknowledged(false);
    setManualSignatureOriginalReference(emptyManualSignatureOriginalReferenceDraft());
    setSealWarningsOpen(true);
  }

  function onArchive() {
    archive.mutate(undefined, {
      onSuccess: () => toast.success(t('toast.ata.archived')),
      onError: (e) => toast.error(e),
    });
  }

  const sealAllowed = compliance.data?.seal_allowed ?? false;
  const canSeal = a.state === 'Signing' && sealAllowed;
  const aiHumanVerificationStatus = a.ai_provenance?.human_verification.status ?? null;
  const warningCount = complianceWarningCount(compliance.data);
  const hasComplianceWarnings = warningCount > 0;
  const warningItems = sealWarningItems(compliance.data);
  const showWrittenResolutionReceipts =
    a.channel === 'WrittenResolution' || a.written_resolution_evidence != null;
  const manualOriginalReference = a.seal_metadata?.manual_signature_original_reference ?? null;

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            {book.data ? (
              <>
                <Link to={`/livros/${book.data.id}`}>{t('acts.book')}</Link> ·{' '}
              </>
            ) : null}
            {t('acts.crumb')}
          </>
        }
        title={
          <span className="ata-title">
            {a.title || t('acts.untitled')}{' '}
            <Badge tone={readOnly ? 'accent' : 'neutral'}>{actStateLabels[a.state]}</Badge>
            {a.ata_number ? (
              <span className="ata-number" data-testid="ata-number">
                {formatAtaNumber(
                  a.ata_number,
                  new Date(a.meeting_date ?? Date.now()).getFullYear(),
                )}
              </span>
            ) : null}
          </span>
        }
      />

      {readOnly ? (
        <InlineWarning tone="info" title={t('acts.sealed.title')}>
          {t('acts.sealed.bodyPrefix')}{' '}
          {a.payload_digest ? <Digest value={a.payload_digest} /> : <span className="mono">—</span>}
          .
          {manualOriginalReference ? (
            <dl className="deflist deflist--tight">
              <div>
                <dt>{t('acts.manualSignature.originalReference.displayLabel')}</dt>
                <dd>{manualOriginalReference.storage_reference}</dd>
              </div>
              {manualOriginalReference.custodian ? (
                <div>
                  <dt>{t('acts.manualSignature.custodian.displayLabel')}</dt>
                  <dd>{manualOriginalReference.custodian}</dd>
                </div>
              ) : null}
              {manualOriginalReference.note ? (
                <div>
                  <dt>{t('acts.manualSignature.note.displayLabel')}</dt>
                  <dd>{manualOriginalReference.note}</dd>
                </div>
              ) : null}
            </dl>
          ) : null}
        </InlineWarning>
      ) : null}

      <div className="split">
        <div className="split__main stack">
          <Card
            title={t('acts.reuniao')}
            actions={
              !readOnly ? (
                <GateButton
                  perm="act.edit"
                  scope={bookScope}
                  type="button"
                  variant="primary"
                  icon={<Icon.Save />}
                  disabled={update.isPending}
                  onClick={onSave}
                >
                  {update.isPending ? t('acts.saving') : t('common.save')}
                </GateButton>
              ) : null
            }
          >
            {update.error ? <ErrorNote error={update.error} /> : null}
            <div className="form">
              <Field label={t('acts.title')} htmlFor="ed-title" help={ataFieldHelp.title}>
                <Input
                  id="ed-title"
                  value={draft.title}
                  disabled={readOnly}
                  onChange={(e) => set('title', e.target.value)}
                />
              </Field>
              <Field label={t('acts.channel')} htmlFor="ed-channel" help={ataFieldHelp.channel}>
                <Select
                  id="ed-channel"
                  value={draft.channel}
                  disabled={readOnly}
                  onChange={(e) => set('channel', e.target.value as MeetingChannel)}
                  options={optionsFrom(MEETING_CHANNELS, meetingChannelLabels)}
                />
              </Field>
              <div className="rowline">
                <Field
                  label={t('acts.meetingDate')}
                  htmlFor="ed-date"
                  help={ataFieldHelp.meetingDate}
                >
                  <Input
                    id="ed-date"
                    type="date"
                    value={draft.meeting_date}
                    disabled={readOnly}
                    onChange={(e) => set('meeting_date', e.target.value)}
                  />
                </Field>
                <Field
                  label={t('acts.meetingTime')}
                  htmlFor="ed-time"
                  help={ataFieldHelp.meetingTime}
                >
                  <Input
                    id="ed-time"
                    type="time"
                    value={draft.meeting_time}
                    disabled={readOnly}
                    onChange={(e) => set('meeting_time', e.target.value)}
                  />
                </Field>
              </div>
              <Field label={t('acts.local')} htmlFor="ed-place" help={ataFieldHelp.place}>
                <Input
                  id="ed-place"
                  value={draft.place}
                  disabled={readOnly}
                  onChange={(e) => set('place', e.target.value)}
                />
              </Field>
              <Field
                label={t('acts.attendanceRef')}
                htmlFor="ed-attendance"
                help={ataFieldHelp.attendanceReference}
              >
                <Input
                  id="ed-attendance"
                  value={draft.attendance_reference}
                  disabled={readOnly}
                  onChange={(e) => set('attendance_reference', e.target.value)}
                />
              </Field>
              <div className="rowline">
                <Field
                  label={t('acts.membersPresent')}
                  htmlFor="ed-present"
                  help={ataFieldHelp.membersPresent}
                >
                  <Input
                    id="ed-present"
                    type="number"
                    min={0}
                    value={draft.members_present}
                    disabled={readOnly}
                    onChange={(e) => set('members_present', e.target.value)}
                  />
                </Field>
                <Field
                  label={t('acts.membersRepresented')}
                  htmlFor="ed-represented"
                  help={ataFieldHelp.membersRepresented}
                >
                  <Input
                    id="ed-represented"
                    type="number"
                    min={0}
                    value={draft.members_represented}
                    disabled={readOnly}
                    onChange={(e) => set('members_represented', e.target.value)}
                  />
                </Field>
              </div>
              {draft.channel === 'Telematic' || draft.channel === 'Hybrid' ? (
                <Field
                  label={t('acts.telematicEvidence')}
                  htmlFor="ed-telematic"
                  hint={t('acts.telematicEvidenceHint')}
                  help={ataFieldHelp.telematicEvidence}
                >
                  <Input
                    id="ed-telematic"
                    value={draft.telematic_evidence}
                    disabled={readOnly}
                    onChange={(e) => set('telematic_evidence', e.target.value)}
                  />
                </Field>
              ) : null}
            </div>
          </Card>

          <Card title={t('acts.convening')}>
            <p className="field__hint">{t('acts.convening.hint')}</p>
            <ConvocationNoticeAdvisoryCue
              meetingDate={draft.meeting_date}
              convening={draft.convening}
            />
            <ConveningEditor
              convening={draft.convening}
              disabled={readOnly}
              onChange={(next) => set('convening', next)}
            />
          </Card>

          <Card title={t('acts.mesa')}>
            <MesaEditor
              mesa={draft.mesa}
              disabled={readOnly}
              onChange={(next) => set('mesa', next)}
            />
          </Card>

          <Card title={t('acts.agenda')}>
            <AgendaEditor
              agenda={draft.agenda}
              disabled={readOnly}
              onChange={(next) => set('agenda', next)}
            />
          </Card>

          <Card title={t('acts.deliberacoes')}>
            <div className="delib">
              <div className="delib__edit">
                <Field
                  label={t('acts.text')}
                  htmlFor="ed-delib"
                  hint={t('acts.textHint')}
                  help={ataFieldHelp.deliberationsText}
                >
                  <TextArea
                    id="ed-delib"
                    rows={12}
                    value={draft.deliberations}
                    disabled={readOnly}
                    onChange={(e) => set('deliberations', e.target.value)}
                  />
                </Field>
              </div>
              <div className="delib__preview">
                <p className="card__label">{t('acts.preview')}</p>
                <DeliberationsPreview text={draft.deliberations} />
              </div>
            </div>
          </Card>

          <Card title={t('acts.deliberationItems')}>
            <p className="field__hint">{t('acts.deliberationItems.hint')}</p>
            <DeliberationItemsEditor
              items={draft.deliberation_items}
              agenda={draft.agenda}
              disabled={readOnly}
              onChange={(next) => set('deliberation_items', next)}
            />
          </Card>

          <FollowUpsPanel act={a} />

          <Card title={t('acts.referencedDocuments')}>
            <p className="field__hint">{t('acts.referencedDocuments.hint')}</p>
            <ReferencedDocumentsEditor
              documents={draft.referenced_documents}
              disabled={readOnly}
              onChange={(next) => set('referenced_documents', next)}
            />
          </Card>

          {showWrittenResolutionReceipts ? (
            <Card title={t('acts.writtenResolution.card.title')}>
              <WrittenResolutionReceiptEditor
                act={a}
                receiptDraft={writtenResolutionReceipt}
                readOnly={readOnly}
                pending={update.isPending}
                error={update.error}
                scope={bookScope}
                onDraftChange={setWrittenResolutionReceipt}
                onSubmit={onSubmitWrittenResolutionReceipt}
              />
            </Card>
          ) : null}

          <Card title={t('acts.signatories')}>
            <SignatoriesEditor
              signatories={draft.signatories}
              disabled={readOnly}
              onChange={(next) => set('signatories', next)}
            />
          </Card>

          <Card title={t('acts.attachments')}>
            <AttachmentsEditor
              attachments={draft.attachments}
              disabled={readOnly}
              onChange={(next) => set('attachments', next)}
            />
          </Card>

          <ActDocumentPanel
            act={a}
            entityName={entity.data?.name}
            family={entity.data?.family}
            target={documentPanelTarget}
          />

          {/* Qualified CMD signing — mounts only once the act is sealed (SigningPanel self-gates). */}
          <SigningPanel act={a} entityName={entity.data?.name} />
        </div>

        <div className="split__aside stack">
          <Card title={t('acts.lifecycle')}>
            {advance.error ? <ErrorNote error={advance.error} /> : null}
            <LifecycleStepper
              current={a.state}
              aiHumanVerificationStatus={aiHumanVerificationStatus}
              pending={advance.isPending}
              onAdvance={onAdvance}
              scope={bookScope}
            />
          </Card>

          {a.ai_provenance ? (
            <Card title={t('acts.aiReview.title')}>
              <AiHumanReviewPanel
                provenance={a.ai_provenance}
                readOnly={readOnly}
                note={humanReviewNote}
                pending={humanReview.isPending}
                pendingDecision={humanReviewDecision}
                error={humanReview.error}
                scope={bookScope}
                onNoteChange={setHumanReviewNote}
                onVerify={onHumanReview}
              />
            </Card>
          ) : null}

          <Card title={t('acts.compliance')}>
            {compliance.isLoading ? (
              <SkeletonText lines={3} />
            ) : compliance.error ? (
              <ErrorNote error={compliance.error} />
            ) : compliance.data ? (
              <CompliancePanel report={compliance.data} />
            ) : null}
          </Card>

          <Card title={t('acts.sealing.title')}>
            <div className="stack--tight">
              {a.state === 'Signing' ? (
                <InlineWarning tone="warn" title={t('acts.manualSignature.title')}>
                  {t('acts.manualSignature.body')}
                </InlineWarning>
              ) : null}
              {seal.error ? <ErrorNote error={seal.error} /> : null}
              {!readOnly ? (
                <>
                  <p className="muted">
                    {a.state !== 'Signing'
                      ? t('acts.sealing.unavailableState')
                      : sealAllowed && hasComplianceWarnings
                        ? t('acts.sealing.readyWithWarnings')
                        : sealAllowed
                          ? t('acts.sealing.ready')
                          : t('acts.sealing.fixErrors')}
                  </p>
                  <GateButton
                    perm="signing.perform"
                    scope={bookScope}
                    type="button"
                    variant="primary"
                    icon={<Icon.Seal />}
                    disabled={!canSeal || seal.isPending}
                    onClick={onSeal}
                  >
                    {seal.isPending ? t('acts.sealing.sealing') : t('acts.sealing.seal')}
                  </GateButton>
                </>
              ) : a.state === 'Sealed' ? (
                <>
                  <p className="muted">{t('acts.sealed.archiveHint')}</p>
                  <GateButton
                    perm="act.archive"
                    scope={bookScope}
                    type="button"
                    variant="secondary"
                    icon={<Icon.Archive />}
                    disabled={archive.isPending}
                    onClick={onArchive}
                  >
                    {archive.isPending ? t('acts.archiving') : t('acts.archive')}
                  </GateButton>
                  {archive.error ? <ErrorNote error={archive.error} /> : null}
                </>
              ) : (
                <p className="muted">{t('acts.archived')}</p>
              )}
            </div>
          </Card>
        </div>
      </div>
      <SealWarningAcknowledgementModal
        open={sealWarningsOpen}
        warnings={warningItems}
        warningCount={warningCount}
        checked={sealWarningsAcknowledged}
        reference={manualSignatureOriginalReference}
        pending={seal.isPending}
        onCheckedChange={setSealWarningsAcknowledged}
        onReferenceChange={setManualSignatureOriginalReference}
        onClose={() => {
          if (!seal.isPending) setSealWarningsOpen(false);
        }}
        onConfirm={() => submitSeal(hasComplianceWarnings)}
      />
    </div>
  );
}
