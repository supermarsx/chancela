/**
 * AtaEditorPage — the centerpiece editor (plan t5 §features/acts).
 *
 * It composes: meeting metadata, a structured deliberations editor with a read-only
 * preview, signatories and attachments panels, a lifecycle stepper that `advance`s
 * the act through Review → … → Signing, a live CompliancePanel, and a SealAction that
 * stays disabled until `seal_allowed` (compliance clean AND state Signing). Once the
 * act is Sealed/Archived it becomes read-only (the payload is frozen). The SIG-03
 * manual-signature warning (UX-41) shows during the signing phase because there is no
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
  type ActAttachment,
  type ActSignatory,
  type ActState,
  type ActView,
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

// Working (editable) copy of the mutable act fields.
interface Draft {
  title: string;
  channel: MeetingChannel;
  meeting_date: string;
  place: string;
  attendance_reference: string;
  deliberations: string;
  telematic_evidence: string;
  attachments: ActAttachment[];
  signatories: ActSignatory[];
}

function toDraft(act: ActView): Draft {
  return {
    title: act.title,
    channel: act.channel,
    meeting_date: act.meeting_date ?? '',
    place: act.place ?? '',
    attendance_reference: act.attendance_reference ?? '',
    deliberations: act.deliberations,
    telematic_evidence: act.telematic_evidence ?? '',
    attachments: act.attachments,
    signatories: act.signatories,
  };
}

/** ISO-empty → null, so the API stores an absent optional rather than "". */
const orNull = (s: string): string | null => (s.trim() === '' ? null : s);

/** The next lifecycle target, capped at Signing (Sealed/Archived need the seal flow). */
function nextState(current: ActState): ActState | null {
  const idx = ACT_STATES.indexOf(current);
  const signingIdx = ACT_STATES.indexOf('Signing');
  if (idx < 0 || idx >= signingIdx) return null;
  return ACT_STATES[idx + 1];
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
          onClick={() => onChange([...attachments, { label: '', kind: 'Exhibit', digest: null }])}
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
    update.mutate({
      title: draft.title,
      channel: draft.channel,
      meeting_date: orNull(draft.meeting_date),
      place: orNull(draft.place),
      attendance_reference: orNull(draft.attendance_reference),
      deliberations: draft.deliberations,
      telematic_evidence: orNull(draft.telematic_evidence),
      attachments: draft.attachments,
      signatories: draft.signatories,
    });
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
              <Field label={t('acts.meetingDate')} htmlFor="ed-date">
                <Input
                  id="ed-date"
                  type="date"
                  value={draft.meeting_date}
                  disabled={readOnly}
                  onChange={(e) => set('meeting_date', e.target.value)}
                />
              </Field>
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
