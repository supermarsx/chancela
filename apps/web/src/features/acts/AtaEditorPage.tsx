/**
 * AtaEditorPage — the centerpiece editor (plan t5 §features/acts; restructured t31).
 *
 * It composes: meeting metadata (date/time/place + present/represented counts), the
 * mesa (bureau — presidente + secretários), the ordem de trabalhos (agenda), a free-text
 * deliberations editor with a read-only preview, a structured per-item deliberations
 * editor (text + VoteResult + member statements), act-scoped follow-up tooling, referenced
 * documents, signatories and attachments panels, a lifecycle stepper, a live CompliancePanel, and a SealAction that
 * stays disabled until `seal_allowed`. Entering `Signing` freezes the canonical snapshot, so the
 * editor becomes read-only before any electronic or explicit manual-original signing evidence.
 *
 * The mesa presidente is the seal-unblocker: the CSC pack (csc-art63/v2) raises a blocking
 * `CSC-63/mesa-presidente` Error until it is filled, so the input below is what lets a
 * commercial-company ata reach «Conforme». The free-text `deliberations` field stays a
 * valid substance path alongside `deliberation_items` (plan R1/R3 — additive coexistence).
 * The SIG-03 manual-original path remains an explicit alternative when no accepted signed PDF is
 * present; it never claims to validate the manual signature or certify the archive.
 */
import { useEffect, useId, useRef, useState, type FormEvent } from 'react';
import { createPortal } from 'react-dom';
import { Link, useLocation, useParams } from 'react-router-dom';
import {
  useAct,
  useActSignature,
  useAdvanceAct,
  useArchiveAct,
  useBook,
  useCompliance,
  useDispatchActConvening,
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
  attendeeQualityLabels,
  optionsFrom,
  presenceModeLabels,
  severityLabels,
  signatoryCapacityLabels,
} from '../../api/labels';
import {
  ACT_STATES,
  ATTACHMENT_KINDS,
  ATTENDEE_ONLY_CAPACITIES,
  DISPATCH_CHANNELS,
  MEETING_CHANNELS,
  PRESENCE_MODES,
  SIGNATORY_CAPACITIES,
  type ActAgendaItem,
  type ActAttachment,
  type ActAttendanceWeight,
  type ActAttendee,
  type ActConvening,
  type ActConveningRecipient,
  type ActConveningWaiver,
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
  type DispatchActConveningBody,
  type DispatchChannel,
  type EntityFamily,
  type HumanVerificationDecision,
  type MeetingChannel,
  type NoConveningBasis,
  type PresenceMode,
  type SignatoryCapacity,
  type WrittenResolutionEvidenceInput,
  type WrittenResolutionReviewReceiptInput,
  type WrittenResolutionReviewReceiptView,
  type WrittenResolutionReviewStatus,
} from '../../api/types';
import { formatAtaNumber } from '../../format';
import { useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import { useT } from '../../i18n';
import { formatAiProvenanceReviewPacket } from './aiProvenanceReviewPacket';
import {
  buildWorkflowProvenanceReviewEvidence,
  formatWorkflowProvenanceReviewCopyPayload,
} from './workflowProvenanceReviewPacket';
import {
  Badge,
  Button,
  Card,
  DateTime,
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
  Stepper,
  type StepperStep,
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
import { ACT_CONVENING_GUIDANCE_HASH, ACT_CONVENING_GUIDANCE_ID } from './anchors';

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
  attendees: ActAttendee[];
  mesa: ActMesa;
  agenda: ActAgendaItem[];
  referenced_documents: ActDocumentReference[];
  deliberations: string;
  deliberation_items: ActDeliberationItem[];
  telematic_evidence: string;
  convening: DraftConvening;
  convening_waiver: DraftConveningWaiver;
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

/**
 * The no-convocatória record as edited. `enabled` is the editor's own state — the wire shape has
 * no such flag, an absent `convening_waiver` *is* "there was a convocatória" — so that switching
 * the toggle off and on again does not silently discard what was already typed.
 */
interface DraftConveningWaiver {
  enabled: boolean;
  basis: NoConveningBasis;
  grounds: string;
  all_agreed_to_meet: boolean;
  all_agreed_to_agenda: boolean;
  evidence_reference: string;
}

function toDraftConveningWaiver(waiver: ActConveningWaiver | undefined): DraftConveningWaiver {
  return {
    enabled: waiver != null,
    basis: waiver?.basis ?? 'AssembleiaUniversal',
    grounds: waiver?.grounds ?? '',
    all_agreed_to_meet: waiver?.all_agreed_to_meet ?? false,
    all_agreed_to_agenda: waiver?.all_agreed_to_agenda ?? false,
    evidence_reference: waiver?.evidence_reference ?? '',
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
    attendees: act.attendees ?? [],
    mesa: { presidente: act.mesa.presidente, secretarios: act.mesa.secretarios },
    agenda: act.agenda,
    referenced_documents: act.referenced_documents,
    deliberations: act.deliberations,
    deliberation_items: act.deliberation_items,
    telematic_evidence: act.telematic_evidence ?? '',
    convening: toDraftConvening(act.convening),
    convening_waiver: toDraftConveningWaiver(act.convening_waiver),
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

const emptyConveningRecipient = (): ActConveningRecipient => ({
  name: '',
  contact: null,
  channel: null,
  reference: null,
  dispatched_at: null,
});

function normalizedConveningRecipients(
  recipients: ActConveningRecipient[],
): ActConveningRecipient[] {
  return recipients
    .map((recipient) => ({
      name: recipient.name.trim(),
      contact: orNull(recipient.contact ?? ''),
      channel: recipient.channel,
      reference: orNull(recipient.reference ?? ''),
      dispatched_at: orNull(recipient.dispatched_at ?? ''),
    }))
    .filter((recipient) => recipient.name !== '');
}

/**
 * Drop the blank rows an operator left behind and keep the represented/proxy invariant the API
 * enforces (`represented_by` set **iff** the presence is `Represented`). A `Represented` row with
 * no proxy still goes out as-is — the editor warns about it inline rather than inventing a name.
 */
function normalizedAttendees(attendees: ActAttendee[]): ActAttendee[] {
  return attendees
    .map((attendee) => ({
      name: attendee.name.trim(),
      quality: attendee.quality,
      // The free-text qualidade is accepted only alongside `Other` (the API 422s otherwise).
      quality_note: attendee.quality === 'Other' ? orNull(attendee.quality_note ?? '') : null,
      presence: attendee.presence,
      represented_by:
        attendee.presence === 'Represented' ? orNull(attendee.represented_by ?? '') : null,
      weight: attendee.weight,
    }))
    .filter((attendee) => attendee.name !== '');
}

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

export function MesaEditor({
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

export function AgendaEditor({
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

export function VoteEditor({
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

export function StatementsEditor({
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

export function DeliberationItemsEditor({
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

export function ReferencedDocumentsEditor({
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

export function SignatoriesEditor({
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

// --- Presenças (G2) -------------------------------------------------------------
//
// The structured lista de presenças. `members_present` / `members_represented` remain the
// aggregate fallback; these rows are what lets the ata itself name who attended, in what
// capacity, with what weight, and — when represented — by whom. The ata templates render the
// roll when it is non-empty and fall back to reciting `attendance_reference` when it is not.

/**
 * Which weight a family's attendance rows carry: companies weight by capital, condominiums by
 * permilagem, and the non-profit families are one-member-one-vote (no weight column at all).
 * An unknown family (the entity query still in flight) keeps the capital column rather than
 * making the input flicker away under the operator.
 */
export function attendanceWeightKind(
  family: EntityFamily | undefined,
): 'Capital' | 'Permilage' | null {
  if (family === 'Condominium') return 'Permilage';
  if (family === 'CommercialCompany' || family === undefined) return 'Capital';
  return null;
}

/** The weight kind a row is already carrying, else the family default. */
function rowWeightKind(
  weight: ActAttendanceWeight | null,
  familyKind: 'Capital' | 'Permilage' | null,
): 'Capital' | 'Permilage' | null {
  if (weight && 'Permilage' in weight) return 'Permilage';
  if (weight && 'Capital' in weight) return 'Capital';
  return familyKind;
}

const weightValue = (weight: ActAttendanceWeight | null): string =>
  weight == null ? '' : String('Capital' in weight ? weight.Capital : weight.Permilage);

/**
 * The qualidades to offer for one attendance row: the entity's own list (derived server-side
 * from its legal type, so a sociedade anonima offers Acionista and a condominio Condomino),
 * plus whatever the row already carries.
 *
 * The row's own value is appended when the list does not contain it, so a qualidade captured
 * before the entity's legal type changed - or by an API client - stays visible and selected
 * instead of the picker silently snapping to another capacity. Falls back to the full
 * vocabulary while the entity query is still in flight, rather than to an empty picker.
 */
export function attendeeQualityOptions(
  offered: SignatoryCapacity[] | undefined,
  current: SignatoryCapacity | undefined,
): SignatoryCapacity[] {
  const base =
    offered && offered.length > 0
      ? offered
      : [...SIGNATORY_CAPACITIES, ...ATTENDEE_ONLY_CAPACITIES];
  return current && !base.includes(current) ? [...base, current] : [...base];
}

const emptyAttendee = (offered: SignatoryCapacity[] | undefined): ActAttendee => ({
  name: '',
  quality: attendeeQualityOptions(offered, undefined)[0],
  quality_note: null,
  presence: 'InPerson',
  represented_by: null,
  weight: null,
});

export function AttendeesEditor({
  attendees,
  family,
  qualities,
  disabled,
  onChange,
}: {
  attendees: ActAttendee[];
  family: EntityFamily | undefined;
  /** `EntityProfile.attendee_qualities` - the qualidades this legal type offers. */
  qualities: SignatoryCapacity[] | undefined;
  disabled: boolean;
  onChange: (next: ActAttendee[]) => void;
}) {
  const t = useT();
  const familyKind = attendanceWeightKind(family);
  const update = (i: number, patch: Partial<ActAttendee>) =>
    onChange(attendees.map((a, idx) => (idx === i ? { ...a, ...patch } : a)));
  // `represented_by` must be set iff the presence is `Represented` (the API 422s otherwise), so
  // switching away from `Represented` drops the proxy rather than leaving an orphaned name.
  const setPresence = (i: number, presence: PresenceMode) =>
    update(i, {
      presence,
      ...(presence === 'Represented' ? {} : { represented_by: null }),
    });
  // The free-text qualidade is only accepted alongside `Other` (the API 422s otherwise), so
  // moving to a structured capacity drops the note the same way.
  const setQuality = (i: number, quality: SignatoryCapacity) =>
    update(i, { quality, ...(quality === 'Other' ? {} : { quality_note: null }) });
  const count = (presence: PresenceMode) => attendees.filter((a) => a.presence === presence).length;

  return (
    <div className="stack--tight">
      {attendees.map((attendee, i) => {
        const kind = rowWeightKind(attendee.weight, familyKind);
        return (
          <div className="rowline" key={i}>
            <Field label={t('acts.attendees.nameAria')} help={ataFieldHelp.attendeeName}>
              <Input
                aria-label={t('acts.attendees.nameAria')}
                placeholder={t('acts.namePlaceholder')}
                value={attendee.name}
                disabled={disabled}
                onChange={(e) => update(i, { name: e.target.value })}
              />
            </Field>
            <Field label={t('acts.attendees.qualityAria')} help={ataFieldHelp.attendeeQuality}>
              <Select
                aria-label={t('acts.attendees.qualityAria')}
                value={attendee.quality}
                disabled={disabled}
                onChange={(e) => setQuality(i, e.target.value as SignatoryCapacity)}
                options={optionsFrom(
                  attendeeQualityOptions(qualities, attendee.quality),
                  attendeeQualityLabels,
                )}
              />
            </Field>
            {attendee.quality === 'Other' ? (
              <Field
                label={t('acts.attendees.qualityNoteAria')}
                help={ataFieldHelp.attendeeQualityNote}
              >
                <Input
                  aria-label={t('acts.attendees.qualityNoteAria')}
                  placeholder={t('acts.attendees.qualityNotePlaceholder')}
                  value={attendee.quality_note ?? ''}
                  disabled={disabled}
                  onChange={(e) => update(i, { quality_note: e.target.value })}
                />
                {(attendee.quality_note ?? '').trim() === '' ? (
                  <InlineWarning>{t('acts.attendees.qualityNoteMissing')}</InlineWarning>
                ) : null}
              </Field>
            ) : null}
            <Field label={t('acts.attendees.presenceAria')} help={ataFieldHelp.attendeePresence}>
              <Select
                aria-label={t('acts.attendees.presenceAria')}
                value={attendee.presence}
                disabled={disabled}
                onChange={(e) => setPresence(i, e.target.value as PresenceMode)}
                options={optionsFrom(PRESENCE_MODES, presenceModeLabels)}
              />
            </Field>
            {attendee.presence === 'Represented' ? (
              <Field
                label={t('acts.attendees.representedByAria')}
                help={ataFieldHelp.attendeeRepresentedBy}
              >
                <Input
                  aria-label={t('acts.attendees.representedByAria')}
                  placeholder={t('acts.namePlaceholder')}
                  value={attendee.represented_by ?? ''}
                  disabled={disabled}
                  onChange={(e) => update(i, { represented_by: e.target.value })}
                />
                {(attendee.represented_by ?? '').trim() === '' ? (
                  <InlineWarning>{t('acts.attendees.representedByRequired')}</InlineWarning>
                ) : null}
              </Field>
            ) : null}
            {kind !== null ? (
              <Field
                label={
                  kind === 'Permilage'
                    ? t('acts.signatoryPermilageAria')
                    : t('acts.attendees.capitalAria')
                }
                help={ataFieldHelp.attendeeWeight}
              >
                <Input
                  className={kind === 'Permilage' ? 'input--permilage' : undefined}
                  type="number"
                  min={0}
                  {...(kind === 'Permilage' ? { max: 1000 } : {})}
                  aria-label={
                    kind === 'Permilage'
                      ? t('acts.signatoryPermilageAria')
                      : t('acts.attendees.capitalAria')
                  }
                  placeholder={
                    kind === 'Permilage'
                      ? t('acts.signatoryPermilagePlaceholder')
                      : t('acts.attendees.capitalPlaceholder')
                  }
                  value={weightValue(attendee.weight)}
                  disabled={disabled}
                  onChange={(e) =>
                    update(i, {
                      weight:
                        e.target.value === ''
                          ? null
                          : kind === 'Permilage'
                            ? { Permilage: Math.trunc(Number(e.target.value)) }
                            : { Capital: Math.trunc(Number(e.target.value)) },
                    })
                  }
                />
              </Field>
            ) : null}
            {!disabled ? (
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Trash />}
                onClick={() => onChange(attendees.filter((_, idx) => idx !== i))}
              >
                {t('common.remove')}
              </Button>
            ) : null}
          </div>
        );
      })}
      {!disabled ? (
        <Button
          type="button"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() => onChange([...attendees, emptyAttendee(qualities)])}
        >
          {t('acts.attendees.add')}
        </Button>
      ) : null}
      {attendees.length > 0 ? (
        <p className="muted">
          {t('acts.attendees.summary', {
            present: count('InPerson'),
            represented: count('Represented'),
            absent: count('Absent'),
          })}
        </p>
      ) : (
        <p className="muted">{t('acts.attendees.none')}</p>
      )}
    </div>
  );
}

export function AttachmentsEditor({
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
                  {/* A written-resolution receipt is evidence of who reviewed and when. */}
                  <DateTime value={receipt.reviewed_at} evidentiary className="mono" />
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
  const t = useT();
  const missingMeetingDate = meetingDate.trim() === '';
  const missingEvidence = convocationNoticeEvidenceMissing(convening);
  if (!missingMeetingDate && !missingEvidence) return null;

  return (
    <InlineWarning tone="info" title={t('acts.convening.advisory.title')}>
      <ul className="stack--tight">
        {missingMeetingDate ? <li>{t('acts.convening.advisory.missingMeetingDate')}</li> : null}
        {missingEvidence ? <li>{t('acts.convening.advisory.missingEvidence')}</li> : null}
      </ul>
      <p className="muted">{t('acts.convening.advisory.noClaims')}</p>
    </InlineWarning>
  );
}

/** True when the convening record carries anything at all — used only to flag the contradiction. */
function conveningHasContent(convening: DraftConvening): boolean {
  return (
    convening.convener.trim() !== '' ||
    convening.convener_capacity !== '' ||
    convening.dispatch_date.trim() !== '' ||
    convening.antecedence_days.trim() !== '' ||
    convening.channel !== '' ||
    convening.evidence_reference.trim() !== '' ||
    convening.recipients.length > 0 ||
    convening.second_call != null
  );
}

/**
 * Records that a meeting was held with **no** convening notice, and on what basis.
 *
 * Not a bare "skip convening" checkbox: the ata recites what is entered here, so the basis has to
 * be a statement someone can stand behind. The copy names CSC art. 54.º for the assembleia
 * universal option and otherwise defers to counsel — the rule packs, not this form, decide whether
 * the recorded basis holds up.
 */
function ConveningWaiverEditor({
  waiver,
  convening,
  disabled,
  onChange,
}: {
  waiver: DraftConveningWaiver;
  convening: DraftConvening;
  disabled: boolean;
  onChange: (next: DraftConveningWaiver) => void;
}) {
  const t = useT();
  const set = <K extends keyof DraftConveningWaiver>(key: K, value: DraftConveningWaiver[K]) =>
    onChange({ ...waiver, [key]: value });
  const universal = waiver.basis === 'AssembleiaUniversal';

  return (
    <section className="stack--tight" aria-labelledby="ed-convening-waiver-title">
      <p className="field__label" id="ed-convening-waiver-title">
        {t('acts.convening.waiver.title')}
      </p>
      <p className="field__hint">{t('acts.convening.waiver.hint')}</p>
      <label className="checkline">
        <input
          type="checkbox"
          id="ed-convening-waiver-toggle"
          checked={waiver.enabled}
          disabled={disabled}
          onChange={(e) => set('enabled', e.target.checked)}
        />
        {t('acts.convening.waiver.toggle')}
      </label>

      {waiver.enabled ? (
        <>
          {conveningHasContent(convening) ? (
            <InlineWarning tone="warn" title={t('acts.convening.waiver.title')}>
              <p>{t('acts.convening.waiver.conflict')}</p>
            </InlineWarning>
          ) : null}
          <Field label={t('acts.convening.waiver.basis')} htmlFor="ed-convening-waiver-basis">
            <Select
              id="ed-convening-waiver-basis"
              value={waiver.basis}
              disabled={disabled}
              options={[
                {
                  value: 'AssembleiaUniversal',
                  label: t('acts.convening.waiver.basis.universal'),
                },
                { value: 'Other', label: t('acts.convening.waiver.basis.other') },
              ]}
              onChange={(e) => set('basis', e.target.value as NoConveningBasis)}
            />
          </Field>
          {universal ? (
            <>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={waiver.all_agreed_to_meet}
                  disabled={disabled}
                  onChange={(e) => set('all_agreed_to_meet', e.target.checked)}
                />
                {t('acts.convening.waiver.agreedToMeet')}
              </label>
              <label className="checkline">
                <input
                  type="checkbox"
                  checked={waiver.all_agreed_to_agenda}
                  disabled={disabled}
                  onChange={(e) => set('all_agreed_to_agenda', e.target.checked)}
                />
                {t('acts.convening.waiver.agreedToAgenda')}
              </label>
            </>
          ) : null}
          <Field label={t('acts.convening.waiver.grounds')} htmlFor="ed-convening-waiver-grounds">
            <TextArea
              id="ed-convening-waiver-grounds"
              rows={2}
              value={waiver.grounds}
              disabled={disabled}
              onChange={(e) => set('grounds', e.target.value)}
            />
          </Field>
          <Field
            label={t('acts.convening.waiver.evidenceReference')}
            htmlFor="ed-convening-waiver-evidence"
          >
            <Input
              id="ed-convening-waiver-evidence"
              value={waiver.evidence_reference}
              disabled={disabled}
              onChange={(e) => set('evidence_reference', e.target.value)}
            />
          </Field>
        </>
      ) : null}
    </section>
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
  const setRecipients = (recipients: ActConveningRecipient[]) =>
    setConvening('recipients', recipients);
  const addRecipient = () => setRecipients([...convening.recipients, emptyConveningRecipient()]);
  const updateRecipient = (index: number, patch: Partial<ActConveningRecipient>) =>
    setRecipients(
      convening.recipients.map((recipient, i) =>
        i === index ? { ...recipient, ...patch } : recipient,
      ),
    );
  const removeRecipient = (index: number) =>
    setRecipients(convening.recipients.filter((_, i) => i !== index));

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
      <section className="stack--tight" aria-labelledby="ed-convening-recipients-title">
        <div className="rowline">
          <div>
            <p className="field__label" id="ed-convening-recipients-title">
              {t('acts.convening.recipients.title')}
            </p>
            <p className="field__hint">{t('acts.convening.recipients.hint')}</p>
          </div>
          <Button
            type="button"
            variant="secondary"
            icon={<Icon.Plus />}
            disabled={disabled}
            onClick={addRecipient}
          >
            {t('acts.convening.recipients.add')}
          </Button>
        </div>
        {convening.recipients.length === 0 ? (
          <p className="muted">{t('acts.convening.recipients.empty')}</p>
        ) : (
          convening.recipients.map((recipient, index) => {
            const rowLabel = t('acts.convening.recipients.rowLabel', { number: index + 1 });
            const nameId = `ed-convening-recipient-${index}-name`;
            const contactId = `ed-convening-recipient-${index}-contact`;
            const channelId = `ed-convening-recipient-${index}-channel`;
            const referenceId = `ed-convening-recipient-${index}-reference`;
            const dispatchedAtId = `ed-convening-recipient-${index}-dispatched-at`;
            return (
              <div className="form" role="group" aria-label={rowLabel} key={index}>
                <div className="rowline">
                  <Field label={t('acts.convening.recipients.name')} htmlFor={nameId}>
                    <Input
                      id={nameId}
                      value={recipient.name}
                      disabled={disabled}
                      onChange={(e) => updateRecipient(index, { name: e.target.value })}
                    />
                  </Field>
                  <Field label={t('acts.convening.recipients.contact')} htmlFor={contactId}>
                    <Input
                      id={contactId}
                      value={recipient.contact ?? ''}
                      disabled={disabled}
                      placeholder={t('acts.convening.recipients.contactPlaceholder')}
                      onChange={(e) => updateRecipient(index, { contact: orNull(e.target.value) })}
                    />
                  </Field>
                  <Field label={t('acts.convening.recipients.channel')} htmlFor={channelId}>
                    <Select
                      id={channelId}
                      value={recipient.channel ?? ''}
                      disabled={disabled}
                      onChange={(e) =>
                        updateRecipient(index, {
                          channel:
                            e.target.value === '' ? null : (e.target.value as DispatchChannel),
                        })
                      }
                      options={channelOptions}
                    />
                  </Field>
                </div>
                <div className="rowline">
                  <Field
                    label={t('acts.convening.recipients.dispatchedAt')}
                    htmlFor={dispatchedAtId}
                  >
                    <Input
                      id={dispatchedAtId}
                      type="date"
                      value={recipient.dispatched_at ?? ''}
                      disabled={disabled}
                      onChange={(e) =>
                        updateRecipient(index, { dispatched_at: orNull(e.target.value) })
                      }
                    />
                  </Field>
                  <Field label={t('acts.convening.recipients.reference')} htmlFor={referenceId}>
                    <Input
                      id={referenceId}
                      value={recipient.reference ?? ''}
                      disabled={disabled}
                      placeholder={t('acts.convening.recipients.referencePlaceholder')}
                      onChange={(e) =>
                        updateRecipient(index, { reference: orNull(e.target.value) })
                      }
                    />
                  </Field>
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Trash />}
                    disabled={disabled}
                    onClick={() => removeRecipient(index)}
                  >
                    {t('acts.convening.recipients.remove')}
                  </Button>
                </div>
              </div>
            );
          })
        )}
      </section>
    </div>
  );
}

function conveningDispatchRecipientNames(convening: DraftConvening): string[] {
  return normalizedConveningRecipients(convening.recipients).map((recipient) => recipient.name);
}

function conveningRecipientNames(recipients: ActConveningRecipient[]): string[] {
  return normalizedConveningRecipients(recipients).map((recipient) => recipient.name);
}

function conveningDispatchEvidenceBody(convening: DraftConvening): DispatchActConveningBody | null {
  const dispatchedAt = convening.dispatch_date.trim();
  const recipients = conveningDispatchRecipientNames(convening);
  if (dispatchedAt === '' || recipients.length === 0) return null;

  const body: DispatchActConveningBody = {
    dispatched_at: dispatchedAt,
    recipients,
  };
  if (convening.channel !== '') body.channel = convening.channel;
  const reference = convening.evidence_reference.trim();
  if (reference !== '') body.reference = reference;
  return body;
}

function ConveningDispatchEvidenceAction({
  convening,
  persistedRecipients,
  disabled,
  pending,
  error,
  scope,
  onRecord,
}: {
  convening: DraftConvening;
  persistedRecipients: ActConveningRecipient[];
  disabled: boolean;
  pending: boolean;
  error: unknown;
  scope: CanScope;
  onRecord: () => void;
}) {
  const t = useT();
  const recipients = conveningDispatchRecipientNames(convening);
  const recipientCount = recipients.length;
  const persistedRecipientSet = new Set(conveningRecipientNames(persistedRecipients));
  const recipientsPersisted =
    recipientCount > 0 && recipients.every((recipient) => persistedRecipientSet.has(recipient));
  const hasDispatchDate = convening.dispatch_date.trim() !== '';
  const ready = !disabled && !pending && hasDispatchDate && recipientsPersisted;

  // `aria-label` on a generic (role-less) element is ignored by assistive technology; the
  // grouping role is what makes this label reach the accessibility tree.
  return (
    <div className="stack--tight" role="group" aria-label={t('acts.convening.evidence.aria')}>
      {error ? <ErrorNote error={error} /> : null}
      <p className="field__hint">{t('acts.convening.evidence.boundary')}</p>
      {hasDispatchDate && recipientsPersisted ? (
        <p className="muted">{t('acts.convening.evidence.ready', { count: recipientCount })}</p>
      ) : hasDispatchDate && recipientCount > 0 ? (
        <p className="muted">{t('acts.convening.evidence.saveRecipients')}</p>
      ) : (
        <p className="muted">{t('acts.convening.evidence.requirements')}</p>
      )}
      <GateButton
        perm="act.edit"
        scope={scope}
        type="button"
        variant="secondary"
        icon={<Icon.Check />}
        disabled={!ready}
        onClick={onRecord}
      >
        {pending ? t('acts.convening.evidence.recording') : t('acts.convening.evidence.record')}
      </GateButton>
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
  // `actStateLabels` is a live per-locale proxy, so the step list is built per render
  // (never hoisted to a module const) to stay correct across a locale switch.
  const steps: StepperStep<ActState>[] = ACT_STATES.map((state) => ({
    id: state,
    label: actStateLabels[state],
  }));
  const next = nextState(current);
  const signingBlockedByAiReview =
    current === 'TextApproved' &&
    next === 'Signing' &&
    aiHumanVerificationStatus != null &&
    aiHumanVerificationStatus !== 'accepted_by_human';
  return (
    <div className="stack--tight">
      <Stepper steps={steps} current={current} ariaLabel={t('acts.lifecycle')} />
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
              <DateTime value={reviewedAt} evidentiary className="mono" />
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

function WorkflowProvenanceReviewPanel({
  act,
  complianceReport,
}: {
  act: ActView;
  complianceReport?: ComplianceReport | null;
}) {
  const t = useT();
  const toast = useToast();
  const markerCountsId = useId();
  const missingCountsId = useId();
  const noClaimsId = useId();
  const [copiedPacket, setCopiedPacket] = useState(false);
  const evidence = buildWorkflowProvenanceReviewEvidence(act, complianceReport);
  const copyPayloadJson = formatWorkflowProvenanceReviewCopyPayload(act, complianceReport);
  const workflow = evidence.workflows[0];
  const markerCounts = Object.entries(evidence.workflow_summary.marker_counts);
  const missingUnknownCounts = Object.entries(evidence.workflow_summary.missing_unknown_counts);
  const noClaimFlags = Object.entries(evidence.no_claim_flags);
  const hasMissingUnknowns = evidence.workflow_summary.missing_unknown_counts.total > 0;

  async function copyReviewPacket() {
    try {
      await navigator.clipboard.writeText(copyPayloadJson);
      setCopiedPacket(true);
      window.setTimeout(() => setCopiedPacket(false), 1500);
      toast.success(t('acts.workflowReview.packet.copied'));
    } catch {
      toast.error(t('acts.workflowReview.packet.copyFailed'));
    }
  }

  return (
    <div className="stack--tight workflow-review">
      <div className="row-wrap ai-review__status">
        <Badge tone={hasMissingUnknowns ? 'warn' : 'ok'}>{workflow.workflow_state}</Badge>
        <Button
          type="button"
          variant="ghost"
          icon={copiedPacket ? <Icon.Check /> : <Icon.Copy />}
          onClick={() => void copyReviewPacket()}
        >
          {copiedPacket
            ? t('acts.workflowReview.packet.copiedButton')
            : t('acts.workflowReview.packet.copy')}
        </Button>
      </div>
      <p className="muted">{t('acts.workflowReview.body')}</p>
      <dl className="deflist deflist--tight ai-review__meta">
        <div>
          <dt>{t('acts.workflowReview.lifecycleBucket')}</dt>
          <dd className="mono">{workflow.workflow_state}</dd>
        </div>
        <div>
          <dt>{t('acts.workflowReview.aiHumanReviewBucket')}</dt>
          <dd className="mono">{workflow.human_review.status}</dd>
        </div>
        <div>
          <dt>{t('acts.workflowReview.compliance')}</dt>
          <dd className="mono">
            {`errors=${evidence.workflow_summary.compliance_buckets.errors} warnings=${evidence.workflow_summary.compliance_buckets.warnings}`}
          </dd>
        </div>
      </dl>

      <section className="stack--tight" aria-labelledby={markerCountsId}>
        <h3 id={markerCountsId}>{t('acts.workflowReview.markerCounts')}</h3>
        <dl className="deflist deflist--tight">
          {markerCounts.map(([key, count]) => (
            <div key={key}>
              <dt className="mono">{key}</dt>
              <dd>{count}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="stack--tight" aria-labelledby={missingCountsId}>
        <h3 id={missingCountsId}>{t('acts.workflowReview.missingUnknownCounts')}</h3>
        <dl className="deflist deflist--tight">
          {missingUnknownCounts.map(([key, count]) => (
            <div key={key}>
              <dt className="mono">{key}</dt>
              <dd>{count}</dd>
            </div>
          ))}
        </dl>
      </section>

      <section className="stack--tight" aria-labelledby={noClaimsId}>
        <h3 id={noClaimsId}>{t('acts.workflowReview.noClaimFlags')}</h3>
        <p className="mono workflow-review__flags">
          {noClaimFlags.map(([key, value]) => `${key}: ${String(value)}`).join(' · ')}
        </p>
      </section>
    </div>
  );
}

/** The PATCH body assembled from the working draft (all §2.4 fields, additive). */
function draftToPatch(draft: Draft) {
  const recipients = normalizedConveningRecipients(draft.convening.recipients);
  const convening: ActConvening | null =
    draft.convening.dispatch_date.trim() === '' &&
    draft.convening.antecedence_days.trim() === '' &&
    draft.convening.channel === '' &&
    draft.convening.evidence_reference.trim() === '' &&
    draft.convening.convener.trim() === '' &&
    draft.convening.convener_capacity === '' &&
    recipients.length === 0 &&
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
          recipients,
          second_call: draft.convening.second_call,
        };

  // An `Other` basis with no stated ground is a 422 at the API, so it is never sent: the editor
  // keeps it as an in-progress draft until the operator says what the ground was.
  const waiverDraft = draft.convening_waiver;
  const waiverGrounds = waiverDraft.grounds.trim();
  const convening_waiver: ActConveningWaiver | null =
    !waiverDraft.enabled || (waiverDraft.basis === 'Other' && waiverGrounds === '')
      ? null
      : {
          basis: waiverDraft.basis,
          grounds: waiverGrounds === '' ? null : waiverGrounds,
          all_agreed_to_meet: waiverDraft.all_agreed_to_meet,
          all_agreed_to_agenda: waiverDraft.all_agreed_to_agenda,
          evidence_reference: orNull(waiverDraft.evidence_reference),
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
    attendees: normalizedAttendees(draft.attendees),
    mesa: { presidente: orNull(draft.mesa.presidente ?? ''), secretarios: draft.mesa.secretarios },
    agenda: draft.agenda,
    referenced_documents: draft.referenced_documents,
    deliberations: draft.deliberations,
    deliberation_items: draft.deliberation_items,
    telematic_evidence: orNull(draft.telematic_evidence),
    convening,
    convening_waiver,
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
  signedEvidence,
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
  signedEvidence: boolean;
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
  const ready = checked && (signedEvidence || referenceReady) && !pending;
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
            {t(signedEvidence ? 'acts.sealing.signedAck.title' : 'acts.sealing.warningAck.title')}
          </h2>
        </header>
        <form className="modal__body" onSubmit={submit}>
          <div className="modal__intro">
            <p>
              {t(signedEvidence ? 'acts.sealing.signedAck.body' : 'acts.sealing.warningAck.body')}
            </p>
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

          {!signedEvidence ? (
            <>
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
            </>
          ) : null}

          <label className="checkline">
            <input
              type="checkbox"
              checked={checked}
              disabled={pending}
              onChange={(e) => onCheckedChange(e.target.checked)}
            />
            {t(
              signedEvidence
                ? warningCount > 0
                  ? 'acts.sealing.signedAck.checkboxWithWarnings'
                  : 'acts.sealing.signedAck.checkbox'
                : warningCount > 0
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
  const signature = useActSignature(
    id,
    act.data?.state === 'Signing' || act.data?.state === 'Sealed' || act.data?.state === 'Archived',
  );
  const update = useUpdateAct(id);
  const dispatchConvening = useDispatchActConvening(id);
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
  const handledConveningHashRef = useRef<string | null>(null);

  // Unsaved-work guard (t52). This editor does NOT autosave — `onSave` is an explicit
  // "Guardar" button — so the working `draft` is the one genuinely expensive thing in the
  // app that a closed tab or a stray navigation would destroy. Dirtiness is DERIVED from
  // the working copy vs. the act as the server last returned it, so saving, reverting an
  // edit, or a refetch all clear it with no extra bookkeeping (and the happy path after a
  // save never prompts). Both sides go through `draftToPatch`, so the comparison is
  // literally "what a save would send" vs "what the server already has": the trim/null
  // normalisation the patch applies cannot leave the page stuck dirty after a save.
  useUnsavedChanges(
    draft != null &&
      act.data != null &&
      JSON.stringify(draftToPatch(draft)) !== JSON.stringify(draftToPatch(toDraft(act.data))),
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

  useEffect(() => {
    if (location.hash !== ACT_CONVENING_GUIDANCE_HASH) {
      handledConveningHashRef.current = null;
      return;
    }
    if (!act.data || !draft) return;
    const targetKey = `${act.data.id}:${location.hash}`;
    if (handledConveningHashRef.current === targetKey) return;

    const scrollTarget = () => {
      document.getElementById(ACT_CONVENING_GUIDANCE_ID)?.scrollIntoView({
        block: 'start',
        behavior: 'smooth',
      });
    };

    if (typeof window.requestAnimationFrame === 'function') {
      window.requestAnimationFrame(scrollTarget);
    } else {
      window.setTimeout(scrollTarget, 0);
    }
    handledConveningHashRef.current = targetKey;
  }, [act.data, draft, location.hash]);

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
  const signing = a.state === 'Signing';
  const sealedOrArchived = a.state === 'Sealed' || a.state === 'Archived';
  const readOnly = signing || sealedOrArchived;
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

  function onRecordConveningDispatch() {
    if (!draft) return;
    const body = conveningDispatchEvidenceBody(draft.convening);
    if (!body) return;
    dispatchConvening.mutate(body, {
      onSuccess: (next) => {
        const updatedConvening = next.convening;
        if (updatedConvening) {
          setDraft((current) =>
            current
              ? {
                  ...current,
                  convening: {
                    ...current.convening,
                    recipients: updatedConvening.recipients,
                  },
                }
              : current,
          );
        }
        toast.success(t('acts.convening.evidence.recorded'));
      },
      onError: (e) => toast.error(e),
    });
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
    if (
      !hasSignedEvidence &&
      !manualSignatureOriginalReferenceReady(manualSignatureOriginalReference)
    ) {
      return;
    }
    seal.mutate(
      {
        ...(acknowledgeWarnings ? { acknowledge_warnings: true } : {}),
        ...(!hasSignedEvidence
          ? {
              manual_signature_original_reference: manualSignatureOriginalReferenceFromDraft(
                manualSignatureOriginalReference,
              ),
            }
          : {}),
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
  const hasSignedEvidence = signature.data?.status === 'signed';
  const canSeal = signing && sealAllowed;
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

      {signing ? (
        <InlineWarning tone="info" title={t('acts.signingSnapshot.title')}>
          {t('acts.signingSnapshot.body')}
        </InlineWarning>
      ) : sealedOrArchived ? (
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

      {/* The lifecycle reads as a full-width form-progress bar above the two-column split,
          not as a card squeezed into the 22rem aside. */}
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

          <Card title={t('acts.attendees')}>
            <p className="field__hint">{t('acts.attendees.hint')}</p>
            <AttendeesEditor
              attendees={draft.attendees}
              family={entity.data?.family}
              qualities={entity.data?.profile?.attendee_qualities}
              disabled={readOnly}
              onChange={(next) => set('attendees', next)}
            />
          </Card>

          <div id={ACT_CONVENING_GUIDANCE_ID} data-testid={ACT_CONVENING_GUIDANCE_ID}>
            <Card title={t('acts.convening')}>
              <p className="field__hint">{t('acts.convening.hint')}</p>
              <ConvocationNoticeAdvisoryCue
                meetingDate={draft.meeting_date}
                convening={draft.convening}
              />
              <ConveningWaiverEditor
                waiver={draft.convening_waiver}
                convening={draft.convening}
                disabled={readOnly}
                onChange={(next) => set('convening_waiver', next)}
              />
              <ConveningEditor
                convening={draft.convening}
                disabled={readOnly}
                onChange={(next) => set('convening', next)}
              />
              <ConveningDispatchEvidenceAction
                convening={draft.convening}
                persistedRecipients={a.convening?.recipients ?? []}
                disabled={readOnly}
                pending={dispatchConvening.isPending}
                error={dispatchConvening.error}
                scope={bookScope}
                onRecord={onRecordConveningDispatch}
              />
            </Card>
          </div>

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

          <Card title={t('acts.workflowReview.title')}>
            <WorkflowProvenanceReviewPanel act={a} complianceReport={compliance.data} />
          </Card>

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
              {signing && !hasSignedEvidence ? (
                <InlineWarning tone="warn" title={t('acts.manualSignature.title')}>
                  {t('acts.manualSignature.body')}
                </InlineWarning>
              ) : null}
              {seal.error ? <ErrorNote error={seal.error} /> : null}
              {signing ? (
                <>
                  <p className="muted">
                    {!sealAllowed
                      ? t('acts.sealing.fixErrors')
                      : hasSignedEvidence
                        ? t('acts.sealing.signedReady')
                        : t('acts.sealing.signatureRequired')}
                  </p>
                  {sealAllowed && hasComplianceWarnings ? (
                    <p className="muted">{t('acts.sealing.readyWithWarnings')}</p>
                  ) : null}
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
              ) : a.state === 'Archived' ? (
                <p className="muted">{t('acts.archived')}</p>
              ) : (
                <p className="muted">{t('acts.sealing.unavailableState')}</p>
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
        signedEvidence={hasSignedEvidence}
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
