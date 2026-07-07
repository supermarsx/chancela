/**
 * AtaEditorPage — the centerpiece editor (plan t5 §features/acts; restructured t31).
 *
 * It composes: meeting metadata (date/time/place + present/represented counts), the
 * mesa (bureau — presidente + secretários), the ordem de trabalhos (agenda), a free-text
 * deliberations editor with a read-only preview, a structured per-item deliberations
 * editor (text + VoteResult + member statements), referenced documents, signatories and
 * attachments panels, a lifecycle stepper, a live CompliancePanel, and a SealAction that
 * stays disabled until `seal_allowed`. Once the act is Sealed/Archived it is read-only.
 *
 * The mesa presidente is the seal-unblocker: the CSC pack (csc-art63/v2) raises a blocking
 * `CSC-63/mesa-presidente` Error until it is filled, so the input below is what lets a
 * commercial-company ata reach «Conforme». The free-text `deliberations` field stays a
 * valid substance path alongside `deliberation_items` (plan R1/R3 — additive coexistence).
 * The SIG-03 manual-signature warning (UX-41) shows during signing because there is no
 * qualified-signature backend yet — sealing attests a manual signature.
 */
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  useAct,
  useAdvanceAct,
  useArchiveAct,
  useBook,
  useCompliance,
  useSealAct,
  useUpdateAct,
} from '../../api/hooks';
import {
  actStateLabels,
  attachmentKindLabels,
  meetingChannelLabels,
  optionsFrom,
  signatoryCapacityLabels,
} from '../../api/labels';
import {
  ACT_STATES,
  ATTACHMENT_KINDS,
  MEETING_CHANNELS,
  SIGNATORY_CAPACITIES,
  type ActAgendaItem,
  type ActAttachment,
  type ActDeliberationItem,
  type ActDocumentReference,
  type ActMemberStatement,
  type ActMesa,
  type ActSignatory,
  type ActState,
  type ActView,
  type ActVoteResult,
  type AttachmentKind,
  type MeetingChannel,
  type SignatoryCapacity,
} from '../../api/types';
import { formatAtaNumber } from '../../format';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  Digest,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Loading,
  PageHeader,
  Select,
  Skeleton,
  TextArea,
} from '../../ui';
import { CompliancePanel } from './CompliancePanel';

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
  attachments: ActAttachment[];
  signatories: ActSignatory[];
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
      <Field label={t('acts.mesa.presidente')} htmlFor="ed-presidente" hint={t('acts.mesa.hint')}>
        <Input
          id="ed-presidente"
          value={mesa.presidente ?? ''}
          disabled={disabled}
          placeholder={t('acts.mesa.presidentePlaceholder')}
          onChange={(e) => onChange({ ...mesa, presidente: e.target.value })}
        />
      </Field>
      <Field label={t('acts.mesa.secretarios')}>
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
      <Field label={t('acts.vote.mode')}>
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
          <Field label={t('acts.vote.emFavor')}>
            <Input
              type="number"
              min={0}
              aria-label={t('acts.vote.emFavor')}
              value={recorded.em_favor}
              disabled={disabled}
              onChange={(e) => setRecorded({ em_favor: num(e.target.value) })}
            />
          </Field>
          <Field label={t('acts.vote.contra')}>
            <Input
              type="number"
              min={0}
              aria-label={t('acts.vote.contra')}
              value={recorded.contra}
              disabled={disabled}
              onChange={(e) => setRecorded({ contra: num(e.target.value) })}
            />
          </Field>
          <Field label={t('acts.vote.abstencoes')}>
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
    <div className="stack--tight">
      <p className="card__label">{t('acts.statements')}</p>
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
          <Field label={t('acts.deliberationItems.agendaLink')}>
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
          <Field label={t('acts.deliberationItems.textAria')}>
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
          <Input
            aria-label={t('acts.referencedDocuments.labelAria')}
            placeholder={t('acts.referencedDocuments.labelPlaceholder')}
            value={doc.label}
            disabled={disabled}
            onChange={(e) => update(i, { label: e.target.value })}
          />
          <Input
            aria-label={t('acts.referencedDocuments.refAria')}
            placeholder={t('acts.referencedDocuments.refPlaceholder')}
            value={doc.reference ?? ''}
            disabled={disabled}
            onChange={(e) => update(i, { reference: orNull(e.target.value) })}
          />
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
          <Input
            aria-label={t('acts.signatoryNameAria')}
            placeholder={t('acts.namePlaceholder')}
            value={s.name}
            disabled={disabled}
            onChange={(e) => update(i, { name: e.target.value })}
          />
          <Select
            aria-label={t('acts.capacityAria')}
            value={s.capacity}
            disabled={disabled}
            onChange={(e) => update(i, { capacity: e.target.value as SignatoryCapacity })}
            options={optionsFrom(SIGNATORY_CAPACITIES, signatoryCapacityLabels)}
          />
          {s.capacity === 'CondoOwner' ? (
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
          ) : null}
          <label className="check">
            <input
              type="checkbox"
              checked={s.signed}
              disabled={disabled}
              onChange={(e) => update(i, { signed: e.target.checked })}
            />{' '}
            {t('acts.signed')}
          </label>
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
          <Input
            aria-label={t('acts.attachmentDescAria')}
            placeholder={t('acts.descPlaceholder')}
            value={a.label}
            disabled={disabled}
            onChange={(e) => update(i, { label: e.target.value })}
          />
          <Select
            aria-label={t('acts.attachmentKindAria')}
            value={a.kind}
            disabled={disabled}
            onChange={(e) => update(i, { kind: e.target.value as AttachmentKind })}
            options={optionsFrom(ATTACHMENT_KINDS, attachmentKindLabels)}
          />
          {a.digest ? (
            <code className="mono" title={a.digest}>
              {a.digest.slice(0, 10)}…
            </code>
          ) : null}
          <label className="check">
            <input
              type="checkbox"
              checked={a.beginning_of_proof ?? false}
              disabled={disabled}
              onChange={(e) => update(i, { beginning_of_proof: e.target.checked })}
            />{' '}
            {t('acts.attachment.beginningOfProof')}
          </label>
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

function LifecycleStepper({
  current,
  onAdvance,
  pending,
}: {
  current: ActState;
  onAdvance: (to: ActState) => void;
  pending: boolean;
}) {
  const t = useT();
  const currentIdx = ACT_STATES.indexOf(current);
  const next = nextState(current);
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
        <Button
          type="button"
          variant="primary"
          icon={<Icon.ArrowRight />}
          disabled={pending}
          onClick={() => onAdvance(next)}
        >
          {pending ? t('acts.advancing') : t('acts.advanceTo', { state: actStateLabels[next] })}
        </Button>
      ) : null}
    </div>
  );
}

/** The PATCH body assembled from the working draft (all §2.4 fields, additive). */
function draftToPatch(draft: Draft) {
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
    attachments: draft.attachments,
    signatories: draft.signatories,
  };
}

export function AtaEditorPage() {
  const t = useT();
  const { id = '' } = useParams();
  const act = useAct(id);
  const book = useBook(act.data?.book_id ?? '');
  const compliance = useCompliance(id);
  const update = useUpdateAct(id);
  const advance = useAdvanceAct(id);
  const seal = useSealAct(id);
  const archive = useArchiveAct(id);

  const [draft, setDraft] = useState<Draft | null>(null);

  // Seed the working copy once per act identity; refetches of the same act (after an
  // advance/seal) update the read-only header via the cache without clobbering edits.
  useEffect(() => {
    if (act.data) setDraft(toDraft(act.data));
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
  const set = <K extends keyof Draft>(key: K, value: Draft[K]) =>
    setDraft((d) => (d ? { ...d, [key]: value } : d));

  function onSave() {
    if (!draft) return;
    update.mutate(draftToPatch(draft));
  }

  const sealAllowed = compliance.data?.seal_allowed ?? false;

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
        </InlineWarning>
      ) : null}

      <div className="split">
        <div className="split__main stack">
          <Card
            title={t('acts.reuniao')}
            actions={
              !readOnly ? (
                <Button
                  type="button"
                  variant="primary"
                  icon={<Icon.Save />}
                  disabled={update.isPending}
                  onClick={onSave}
                >
                  {update.isPending ? t('acts.saving') : t('common.save')}
                </Button>
              ) : null
            }
          >
            {update.error ? <ErrorNote error={update.error} /> : null}
            <div className="form">
              <Field label={t('acts.title')} htmlFor="ed-title">
                <Input
                  id="ed-title"
                  value={draft.title}
                  disabled={readOnly}
                  onChange={(e) => set('title', e.target.value)}
                />
              </Field>
              <Field label={t('acts.channel')} htmlFor="ed-channel">
                <Select
                  id="ed-channel"
                  value={draft.channel}
                  disabled={readOnly}
                  onChange={(e) => set('channel', e.target.value as MeetingChannel)}
                  options={optionsFrom(MEETING_CHANNELS, meetingChannelLabels)}
                />
              </Field>
              <div className="rowline">
                <Field label={t('acts.meetingDate')} htmlFor="ed-date">
                  <Input
                    id="ed-date"
                    type="date"
                    value={draft.meeting_date}
                    disabled={readOnly}
                    onChange={(e) => set('meeting_date', e.target.value)}
                  />
                </Field>
                <Field label={t('acts.meetingTime')} htmlFor="ed-time">
                  <Input
                    id="ed-time"
                    type="time"
                    value={draft.meeting_time}
                    disabled={readOnly}
                    onChange={(e) => set('meeting_time', e.target.value)}
                  />
                </Field>
              </div>
              <Field label={t('acts.local')} htmlFor="ed-place">
                <Input
                  id="ed-place"
                  value={draft.place}
                  disabled={readOnly}
                  onChange={(e) => set('place', e.target.value)}
                />
              </Field>
              <Field label={t('acts.attendanceRef')} htmlFor="ed-attendance">
                <Input
                  id="ed-attendance"
                  value={draft.attendance_reference}
                  disabled={readOnly}
                  onChange={(e) => set('attendance_reference', e.target.value)}
                />
              </Field>
              <div className="rowline">
                <Field label={t('acts.membersPresent')} htmlFor="ed-present">
                  <Input
                    id="ed-present"
                    type="number"
                    min={0}
                    value={draft.members_present}
                    disabled={readOnly}
                    onChange={(e) => set('members_present', e.target.value)}
                  />
                </Field>
                <Field label={t('acts.membersRepresented')} htmlFor="ed-represented">
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
                <Field label={t('acts.text')} htmlFor="ed-delib" hint={t('acts.textHint')}>
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

          <Card title={t('acts.referencedDocuments')}>
            <p className="field__hint">{t('acts.referencedDocuments.hint')}</p>
            <ReferencedDocumentsEditor
              documents={draft.referenced_documents}
              disabled={readOnly}
              onChange={(next) => set('referenced_documents', next)}
            />
          </Card>

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
        </div>

        <div className="split__aside stack">
          <Card title={t('acts.lifecycle')}>
            {advance.error ? <ErrorNote error={advance.error} /> : null}
            <LifecycleStepper
              current={a.state}
              pending={advance.isPending}
              onAdvance={(to) => advance.mutate(to)}
            />
          </Card>

          <Card title={t('acts.compliance')}>
            {compliance.isLoading ? (
              <Loading />
            ) : compliance.error ? (
              <ErrorNote error={compliance.error} />
            ) : compliance.data ? (
              <CompliancePanel report={compliance.data} />
            ) : null}
          </Card>

          {a.state === 'Signing' ? (
            <InlineWarning tone="warn" title={t('acts.manualSignature.title')}>
              {t('acts.manualSignature.body')}
            </InlineWarning>
          ) : null}

          <Card title={t('acts.sealing.title')}>
            {seal.error ? <ErrorNote error={seal.error} /> : null}
            {!readOnly ? (
              <div className="stack--tight">
                <p className="muted">
                  {sealAllowed
                    ? t('acts.sealing.ready')
                    : a.state !== 'Signing'
                      ? t('acts.sealing.unavailableState')
                      : t('acts.sealing.fixErrors')}
                </p>
                <Button
                  type="button"
                  variant="primary"
                  icon={<Icon.Seal />}
                  disabled={!sealAllowed || seal.isPending}
                  onClick={() => seal.mutate({ acknowledge_warnings: true })}
                >
                  {seal.isPending ? t('acts.sealing.sealing') : t('acts.sealing.seal')}
                </Button>
              </div>
            ) : a.state === 'Sealed' ? (
              <div className="stack--tight">
                <p className="muted">{t('acts.sealed.archiveHint')}</p>
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.Archive />}
                  disabled={archive.isPending}
                  onClick={() => archive.mutate()}
                >
                  {archive.isPending ? t('acts.archiving') : t('acts.archive')}
                </Button>
                {archive.error ? <ErrorNote error={archive.error} /> : null}
              </div>
            ) : (
              <p className="muted">{t('acts.archived')}</p>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
