/**
 * TermoEncerramentoEditor — the termo de encerramento as a document in its own right (t44), the
 * CLOSE mirror of {@link ./TermoAberturaEditor}.
 *
 * An OPEN book closed two-phase (`POST /close` with `one_shot: false`) keeps its `Open` state and
 * gains a `Draft` termo de encerramento. This panel drives the termo's whole lifecycle as an ata:
 *
 *   • **Draft** — the title, body clauses, closing fields (closing date, closing reason incl.
 *     "Other" + note, book number, place, predecessor note) and signatory slots are freely editable
 *     and saved with a PATCH. "Avançar para assinatura" freezes the content (`advance`).
 *   • **Signing** — the content is frozen; each required signatory signs in order (`sign`), then
 *     "Encerrar livro" seals the termo and closes the book (`close`).
 *   • **Sealed** — the termo took effect and the book is closed; the record is immutable.
 *
 * Honest fail-closed close: real per-slot PAdES signing SHIPS —
 * {@link ../../api/hooks#useSignBookTermoEncerramentoPkcs12} drives
 * `POST …/termo/encerramento/sign/pkcs12`, which signs the frozen snapshot and records the
 * signature in `instrument_signatures`. The `close` endpoint still FAILS CLOSED with a `409` while
 * any required slot lacks one: a reference `sign` records completion metadata and no signature, so
 * it sets `slot.signed` without ever satisfying the gate. It
 * also fails closed with a `409` when the frozen snapshot no longer re-renders to the bytes the
 * signatories signed. Each cause is surfaced distinctly, told apart by the server's stable error
 * `code` and never by its prose ({@link closeErrorKind}); the book stays `Open` in every case — the
 * panel never pretends it closed.
 *
 * All copy is ASSURANCE except the two genuinely legal framings reused from the abertura (the
 * capacity allow-list and the at-least-one-signatory minimum). Closing fixity is never described as
 * discharging the encadernação duty.
 */
import { useMemo, useState } from 'react';
import { ApiError } from '../../api/client';
import {
  useAdvanceBookTermoEncerramento,
  useBookTermoEncerramento,
  useCloseBookFromTermo,
  usePatchBookTermoEncerramento,
  useSignBookTermoEncerramentoPkcs12,
} from '../../api/hooks';
import { closingReasonLabels, optionsFrom, signatoryCapacityLabels } from '../../api/labels';
import {
  CLOSING_REASONS,
  SIGNATORY_CAPACITIES,
  type ClosingReason,
  type ClosingReasonWire,
  type PatchTermoEncerramentoBody,
  type SignatoryCapacity,
  type TermoClauseView,
  type TermoCompletionPolicy,
  type TermoInstrumentView,
  type TermoSlotView,
} from '../../api/types';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  GuardedActionModal,
  Icon,
  InlineWarning,
  Input,
  Select,
  Skeleton,
  TextArea,
  Toggle,
  useGuardedActionPolicy,
  useToast,
} from '../../ui';
import { useApiErrorHeadline } from '../../i18n/apiErrorFallback';
import { useTermoT } from './termoStrings';
import { useEncerramentoT } from './termoEncerramentoStrings';
import { TermoSlotPkcs12Signer } from './TermoSlotPkcs12Signer';

/** Local, editable copy of a clause (a new clause has no server id yet). */
type ClauseDraft = { heading: string; text: string };

/** Local, editable copy of a signatory slot. */
type SlotDraft = {
  name: string;
  email: string;
  capacity: SignatoryCapacity;
  capacityNote: string;
  required: boolean;
  order: number;
};

/** The reason picker value: a modelled reason or the custom `Other` sentinel. */
type ReasonKind = ClosingReason | 'Other';

function clauseToDraft(clause: TermoClauseView): ClauseDraft {
  return { heading: clause.heading ?? '', text: clause.text };
}

function slotToDraft(slot: TermoSlotView): SlotDraft {
  return {
    name: slot.name,
    email: slot.email ?? '',
    capacity: slot.capacity,
    capacityNote: slot.capacity_note ?? '',
    required: slot.required,
    order: slot.order,
  };
}

/** Which fail-closed `close` refusal came back, one per server `code`. */
type CloseRefusal = 'notSigned' | 'staleFacts' | 'renderDrift' | 'snapshotMismatch';

/**
 * The `close` refusals this panel renders itself, keyed by the server's stable error `code`
 * (`chancela-api`'s `termo.rs`). Every other error falls through to {@link ErrorNote}.
 *
 * `termo_snapshot_mismatch` is what the snapshot guard reports today; `termo_stale_facts` and
 * `termo_snapshot_render_drift` are the narrower causes the server will report once the facts a
 * snapshot was rendered from are recorded at advance. They are mapped here because each has its own
 * reviewed sentence and must never degrade into the generic one.
 */
const CLOSE_REFUSAL_BY_CODE: Readonly<Record<string, CloseRefusal>> = {
  termo_encerramento_not_signed: 'notSigned',
  termo_stale_facts: 'staleFacts',
  termo_snapshot_render_drift: 'renderDrift',
  termo_snapshot_mismatch: 'snapshotMismatch',
};

/**
 * Classify a `close` failure by the server's stable error **code**.
 *
 * This used to test the message with `/nova ata|número de atas/i`, which made the server's prose
 * load-bearing application behaviour: rewording it — a translation sweep, a corrected explanation —
 * silently flipped the branch and showed the operator the wrong reason for a fail-closed refusal on
 * a legal instrument, and no test could catch a regex over prose. **Nothing here reads
 * `error.message`.** An unrecognised `409` now resolves to `null` and renders through
 * {@link ErrorNote}, rather than being asserted to be the not-signed refusal on no evidence.
 */
function closeErrorKind(error: unknown): CloseRefusal | null {
  if (!(error instanceof ApiError) || error.status !== 409) return null;
  return CLOSE_REFUSAL_BY_CODE[error.code ?? ''] ?? null;
}

/** Render a completion policy as plain assurance copy — never as a legal claim about who must sign. */
function useFormatPolicy(): (policy: TermoCompletionPolicy) => string {
  const tt = useTermoT();
  return (policy) => {
    if (policy === 'AllRequired') return tt('books.termo.policy.AllRequired');
    if (policy === 'SingleQualifying') return tt('books.termo.policy.SingleQualifying');
    return tt('books.termo.policy.AtLeast', { n: policy.AtLeast });
  };
}

function StateBadge({ termo }: { termo: TermoInstrumentView }) {
  const tt = useTermoT();
  const tone = termo.state === 'Sealed' ? 'ok' : termo.state === 'Signing' ? 'accent' : 'neutral';
  return <Badge tone={tone}>{tt(`books.termo.state.${termo.state}`)}</Badge>;
}

/** The draft-editing form. Remounted (via `key`) when the termo identity changes, so it seeds once. */
function TermoDraftForm({ termo }: { termo: TermoInstrumentView }) {
  const tt = useTermoT();
  const et = useEncerramentoT();
  const toast = useToast();
  const patch = usePatchBookTermoEncerramento(termo.book_id);
  const advance = useAdvanceBookTermoEncerramento(termo.book_id);
  // `termo_encerramento.advance` is a guarded action in the server's registry, and one the server
  // does not re-enforce: for a `confirm`-floored action the client IS the gate.
  const advancePolicy = useGuardedActionPolicy('termo_encerramento.advance');
  const [confirmAdvance, setConfirmAdvance] = useState(false);

  const [title, setTitle] = useState(termo.title);
  const [clauses, setClauses] = useState<ClauseDraft[]>(termo.body.map(clauseToDraft));
  const [closingDate, setClosingDate] = useState(termo.fields.instrument_date ?? '');
  // The termo view does not echo the closing reason back (it is not part of `TermoFieldsView`), so
  // the picker seeds to the modelled default; the PATCH still persists whatever the operator sets.
  const [reasonKind, setReasonKind] = useState<ReasonKind>('BookFull');
  const [reasonNote, setReasonNote] = useState('');
  const [place, setPlace] = useState(termo.fields.place ?? '');
  const [bookNumber, setBookNumber] = useState(
    termo.fields.book_number != null ? String(termo.fields.book_number) : '',
  );
  const [predecessorNote, setPredecessorNote] = useState(termo.fields.predecessor_note ?? '');
  const [slots, setSlots] = useState<SlotDraft[]>(termo.signatories.map(slotToDraft));

  const capacityOptions = [
    ...optionsFrom(SIGNATORY_CAPACITIES, signatoryCapacityLabels),
    { value: 'Other', label: tt('books.termo.signatory.other') },
  ];
  const reasonOptions = [
    ...optionsFrom(CLOSING_REASONS, closingReasonLabels),
    { value: 'Other', label: et('books.encerramento.reason.other') },
  ];

  function updateClause(index: number, next: Partial<ClauseDraft>) {
    setClauses((rows) => rows.map((row, idx) => (idx === index ? { ...row, ...next } : row)));
  }
  function updateSlot(index: number, next: Partial<SlotDraft>) {
    setSlots((rows) => rows.map((row, idx) => (idx === index ? { ...row, ...next } : row)));
  }

  function closingReason(): ClosingReasonWire {
    return reasonKind === 'Other' ? { Other: { note: reasonNote.trim() } } : reasonKind;
  }

  function buildBody(): PatchTermoEncerramentoBody {
    return {
      title,
      body: clauses.map((clause) => ({
        heading: clause.heading.trim() || undefined,
        text: clause.text,
      })),
      closing_date: closingDate || undefined,
      closing_reason: closingReason(),
      place: place.trim() || undefined,
      book_number: bookNumber ? Number(bookNumber) : undefined,
      predecessor_note: predecessorNote.trim() || undefined,
      signatories: slots.map((slot, index) => ({
        name: slot.name.trim(),
        email: slot.email.trim() || undefined,
        capacity: slot.capacity,
        capacity_note:
          slot.capacity === 'Other' ? slot.capacityNote.trim() || undefined : undefined,
        required: slot.required,
        order: slot.order || index + 1,
      })),
    };
  }

  function onSave() {
    patch.mutate(buildBody(), {
      onSuccess: () => toast.success(tt('books.termo.editor.saved')),
      onError: (error) => toast.error(error),
    });
  }

  /**
   * Persist the current edits first (the freeze validates the saved termo), then advance — one
   * promise, so the confirm dialog waits for the whole thing and reports either half's failure.
   */
  async function runAdvance(): Promise<void> {
    await patch.mutateAsync(buildBody());
    await advance.mutateAsync(undefined);
  }

  function onAdvance() {
    if (!advancePolicy.gated) {
      // Only when the policy positively resolves the action to `off`; the unreadable-policy case
      // falls back to `confirm` and takes the dialog.
      runAdvance().catch((error: unknown) => toast.error(error));
      return;
    }
    setConfirmAdvance(true);
  }

  const busy = patch.isPending || advance.isPending;

  return (
    <div className="stack termo-editor">
      <InlineWarning tone="info" title={tt(`books.termo.state.Draft`)}>
        {tt('books.termo.state.DraftHint')}
      </InlineWarning>

      <div className="form settings-rows termo-editor__rows">
        <Field
          label={tt('books.termo.editor.titleLabel')}
          htmlFor="encerramento-title"
          help={tt('books.termo.editor.titleHelp')}
        >
          <Input id="encerramento-title" value={title} onChange={(e) => setTitle(e.target.value)} />
        </Field>

        <p className="card__label termo-editor__section-label" role="heading" aria-level={4}>
          {tt('books.termo.editor.fieldsLegend')}
        </p>

        {/* Fields (all ASSURANCE/product). */}
        <Field
          label={et('books.encerramento.field.closingDate')}
          htmlFor="encerramento-date"
          help={et('books.encerramento.field.closingDateHelp')}
        >
          <Input
            id="encerramento-date"
            type="date"
            value={closingDate}
            onChange={(e) => setClosingDate(e.target.value)}
          />
        </Field>
        <Field
          label={et('books.encerramento.field.closingReason')}
          htmlFor="encerramento-reason"
          help={et('books.encerramento.field.closingReasonHelp')}
        >
          <Select
            id="encerramento-reason"
            value={reasonKind}
            onChange={(e) => setReasonKind(e.target.value as ReasonKind)}
            options={reasonOptions}
          />
        </Field>
        {reasonKind === 'Other' ? (
          <Field
            label={et('books.encerramento.reason.otherNote')}
            htmlFor="encerramento-reason-note"
            help={et('books.encerramento.reason.otherNoteHelp')}
          >
            <Input
              id="encerramento-reason-note"
              value={reasonNote}
              required
              placeholder={et('books.encerramento.reason.otherPlaceholder')}
              onChange={(e) => setReasonNote(e.target.value)}
            />
          </Field>
        ) : null}
        <Field
          label={tt('books.termo.field.bookNumber')}
          htmlFor="encerramento-number"
          help={tt('books.termo.field.bookNumberHelp')}
        >
          <Input
            id="encerramento-number"
            type="number"
            min={1}
            value={bookNumber}
            onChange={(e) => setBookNumber(e.target.value)}
          />
        </Field>
        <Field
          label={tt('books.termo.field.place')}
          htmlFor="encerramento-place"
          help={tt('books.termo.field.placeHelp')}
        >
          <Input id="encerramento-place" value={place} onChange={(e) => setPlace(e.target.value)} />
        </Field>
        <Field
          label={tt('books.termo.field.predecessorNote')}
          htmlFor="encerramento-predecessor-note"
          help={tt('books.termo.field.predecessorNoteHelp')}
        >
          <Input
            id="encerramento-predecessor-note"
            value={predecessorNote}
            onChange={(e) => setPredecessorNote(e.target.value)}
          />
        </Field>
        {/* Body clauses. */}
        <Field label={tt('books.termo.editor.bodyLegend')} hint={tt('books.termo.editor.bodyHelp')}>
          <div className="stack--tight termo-editor__collection">
            {clauses.length === 0 ? (
              <p className="field__hint">{tt('books.termo.editor.noClauses')}</p>
            ) : null}
            {clauses.map((clause, index) => (
              <div className="field-table termo-editor__block" key={index}>
                <Field
                  label={tt('books.termo.editor.clauseHeading')}
                  htmlFor={`encerramento-clause-heading-${index}`}
                >
                  <Input
                    id={`encerramento-clause-heading-${index}`}
                    value={clause.heading}
                    onChange={(e) => updateClause(index, { heading: e.target.value })}
                  />
                </Field>
                <Field
                  label={tt('books.termo.editor.clauseText')}
                  htmlFor={`encerramento-clause-text-${index}`}
                >
                  <TextArea
                    id={`encerramento-clause-text-${index}`}
                    rows={3}
                    value={clause.text}
                    onChange={(e) => updateClause(index, { text: e.target.value })}
                  />
                </Field>
                <div className="termo-editor__block-actions">
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Trash />}
                    onClick={() => setClauses((rows) => rows.filter((_, idx) => idx !== index))}
                  >
                    {tt('books.termo.editor.removeClause')}
                  </Button>
                </div>
              </div>
            ))}
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={() => setClauses((rows) => [...rows, { heading: '', text: '' }])}
            >
              {tt('books.termo.editor.addClause')}
            </Button>
          </div>
        </Field>

        {/* Signatory slots. */}
        <Field
          label={tt('books.termo.editor.signatoriesLegend')}
          hint={tt('books.termo.rule.allowList')}
        >
          <div className="stack--tight termo-editor__collection">
            {slots.map((slot, index) => (
              <div className="field-table termo-editor__block" key={index}>
                <Field
                  label={tt('books.termo.signatory.name')}
                  htmlFor={`encerramento-slot-name-${index}`}
                  help={tt('books.termo.signatory.nameHelp')}
                >
                  <Input
                    id={`encerramento-slot-name-${index}`}
                    value={slot.name}
                    onChange={(e) => updateSlot(index, { name: e.target.value })}
                  />
                </Field>
                <Field
                  label={tt('books.termo.signatory.capacity')}
                  htmlFor={`encerramento-slot-capacity-${index}`}
                  help={tt('books.termo.signatory.capacityHelp')}
                >
                  <Select
                    id={`encerramento-slot-capacity-${index}`}
                    value={slot.capacity}
                    onChange={(e) =>
                      updateSlot(index, { capacity: e.target.value as SignatoryCapacity })
                    }
                    options={capacityOptions}
                  />
                </Field>
                {slot.capacity === 'Other' ? (
                  <Field
                    label={tt('books.termo.signatory.other')}
                    htmlFor={`encerramento-slot-note-${index}`}
                    help={tt('books.termo.signatory.otherHelp')}
                  >
                    <Input
                      id={`encerramento-slot-note-${index}`}
                      value={slot.capacityNote}
                      required
                      placeholder={tt('books.termo.signatory.otherPlaceholder')}
                      onChange={(e) => updateSlot(index, { capacityNote: e.target.value })}
                    />
                  </Field>
                ) : null}
                <Field
                  label={tt('books.termo.signatory.email')}
                  htmlFor={`encerramento-slot-email-${index}`}
                  help={tt('books.termo.signatory.emailHelp')}
                >
                  <Input
                    id={`encerramento-slot-email-${index}`}
                    type="email"
                    value={slot.email}
                    onChange={(e) => updateSlot(index, { email: e.target.value })}
                  />
                </Field>
                <Field
                  label={tt('books.termo.signatory.order')}
                  htmlFor={`encerramento-slot-order-${index}`}
                  help={tt('books.termo.signatory.orderHelp')}
                >
                  <Input
                    id={`encerramento-slot-order-${index}`}
                    type="number"
                    min={1}
                    value={String(slot.order)}
                    onChange={(e) => updateSlot(index, { order: Number(e.target.value) })}
                  />
                </Field>
                <Field label={tt('books.termo.signatory.required')}>
                  <Toggle
                    id={`encerramento-slot-required-${index}`}
                    checked={slot.required}
                    onChange={(required) => updateSlot(index, { required })}
                    label={<span className="sr-only">{tt('books.termo.signatory.required')}</span>}
                  />
                </Field>
                <div className="termo-editor__block-actions">
                  <Button
                    type="button"
                    variant="ghost"
                    icon={<Icon.Trash />}
                    onClick={() => setSlots((rows) => rows.filter((_, idx) => idx !== index))}
                  >
                    {tt('books.termo.editor.removeSignatory')}
                  </Button>
                </div>
              </div>
            ))}
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Plus />}
              onClick={() =>
                setSlots((rows) => [
                  ...rows,
                  {
                    name: '',
                    email: '',
                    capacity: 'Manager',
                    capacityNote: '',
                    required: true,
                    order: rows.length + 1,
                  },
                ])
              }
            >
              {tt('books.termo.editor.addSignatory')}
            </Button>
          </div>
        </Field>

        {patch.error ? <ErrorNote error={patch.error} /> : null}
        {advance.error ? <ErrorNote error={advance.error} /> : null}
        <Field
          label={tt('books.termo.editor.actionsLegend')}
          hint={tt('books.termo.action.advanceHint')}
        >
          <div className="form__actions termo-editor__actions">
            <Button type="button" variant="secondary" onClick={onSave} disabled={busy}>
              {patch.isPending ? tt('books.termo.editor.saving') : tt('books.termo.editor.save')}
            </Button>
            <Button
              type="button"
              variant="primary"
              icon={<Icon.PenNib />}
              onClick={onAdvance}
              disabled={busy}
            >
              {advance.isPending
                ? tt('books.termo.action.advancing')
                : tt('books.termo.action.advance')}
            </Button>
          </div>
        </Field>
      </div>

      <GuardedActionModal
        action="termo_encerramento.advance"
        open={confirmAdvance}
        onClose={() => setConfirmAdvance(false)}
        title={tt('books.termo.advance.confirm.title')}
        intro={<p>{tt('books.termo.advance.confirm.intro')}</p>}
        confirmLabel={tt('books.termo.advance.confirm.action')}
        pendingLabel={tt('books.termo.action.advancing')}
        pending={busy}
        onConfirm={async () => {
          // Resolves either way so the dialog closes onto the panel's own error rendering, which
          // is unchanged from before the gate: an `ErrorNote` above the actions plus the toast.
          await runAdvance().catch((error: unknown) => toast.error(error));
        }}
      />
    </div>
  );
}

/** The signing phase: content frozen, per-slot signatures collected, then the book is closed. */
function TermoSigningView({ termo }: { termo: TermoInstrumentView }) {
  const tt = useTermoT();
  const et = useEncerramentoT();
  const formatPolicy = useFormatPolicy();
  const sign = useSignBookTermoEncerramentoPkcs12(termo.book_id);
  const closeBook = useCloseBookFromTermo(termo.book_id);
  // `termo_encerramento.close` is a guarded action in the server's registry — floored at
  // confirm-with-reauth-and-phrase, because `chancela_core::book` has no `Closed -> Open`
  // transition. The server declares the level; this dialog applies it.
  const closePolicy = useGuardedActionPolicy('termo_encerramento.close');
  const [confirmClose, setConfirmClose] = useState(false);
  // The slot whose real per-slot PAdES co-signature form is open (null = none expanded yet).
  const [activeSlotId, setActiveSlotId] = useState<string | null>(null);

  const orderedSlots = useMemo(
    () => [...termo.signatories].sort((a, b) => a.order - b.order),
    [termo.signatories],
  );
  // Sequential collection: the next slot allowed to sign is the earliest unsigned required one.
  const nextSlotId = orderedSlots.find((slot) => slot.required && !slot.signed)?.id;

  const apiErrorHeadline = useApiErrorHeadline();
  const closeError = closeErrorKind(closeBook.error);

  return (
    <div className="stack termo-editor">
      <InlineWarning tone="info" title={tt('books.termo.signing.legend')}>
        {et('books.encerramento.signing.intro')}
      </InlineWarning>

      <dl className="deflist termo-status-table">
        <div>
          <dt>{tt('books.termo.editor.policyLabel')}</dt>
          <dd>{formatPolicy(termo.completion_policy)}</dd>
        </div>
        <div>
          <dt>{tt('books.termo.editor.signatoriesLegend')}</dt>
          <dd>
            {termo.completion.complete
              ? tt('books.termo.completion.complete')
              : tt('books.termo.completion.pending', {
                  count:
                    termo.completion.required_slot_count -
                    termo.completion.signed_required_slot_count,
                  total: termo.completion.required_slot_count,
                })}
          </dd>
        </div>
      </dl>

      <ul
        className="termo-signatories-table"
        aria-label={tt('books.termo.editor.signatoriesLegend')}
      >
        {orderedSlots.map((slot) => (
          <li className="termo-signatory-row" key={slot.id}>
            <span className="termo-signatory-row__identity">
              {slot.name || '—'}
              {' · '}
              {slot.capacity === 'Other'
                ? (slot.capacity_note ?? tt('books.termo.signatory.other'))
                : signatoryCapacityLabels[slot.capacity]}
            </span>
            <div className="termo-signatory-row__state">
              {slot.signed ? (
                <Badge tone="ok">{tt('books.termo.signing.slotDone')}</Badge>
              ) : slot.id === nextSlotId ? (
                slot.id === activeSlotId ? null : (
                  <Button
                    type="button"
                    variant="primary"
                    icon={<Icon.PenNib />}
                    onClick={() => setActiveSlotId(slot.id)}
                    disabled={sign.isPending}
                  >
                    {tt('books.termo.action.sign')}
                  </Button>
                )
              ) : (
                <span className="field__hint">{tt('books.termo.signing.slotWaiting')}</span>
              )}
            </div>
            {slot.id === nextSlotId && slot.id === activeSlotId && !slot.signed ? (
              <div className="termo-signatory-row__expanded">
                <TermoSlotPkcs12Signer
                  slotId={slot.id}
                  sign={(body) => sign.mutateAsync(body)}
                  isPending={sign.isPending}
                  onSigned={() => setActiveSlotId(null)}
                  onCancel={() => setActiveSlotId(null)}
                />
              </div>
            ) : null}
          </li>
        ))}
      </ul>

      {closeError === 'notSigned' ? (
        <InlineWarning tone="warn" title={et('books.encerramento.close.notSignedTitle')}>
          {et('books.encerramento.close.notSignedBody')}
        </InlineWarning>
      ) : closeError === 'staleFacts' ? (
        <InlineWarning tone="warn" title={et('books.encerramento.close.staleTitle')}>
          {et('books.encerramento.close.staleBody')}
        </InlineWarning>
      ) : closeError !== null ? (
        // `renderDrift` and `snapshotMismatch` have no titled pair here: each states a *different*
        // established cause and neither may borrow the stale-fact title, which asserts the book's
        // facts moved. Their reviewed sentence comes from the shared api-error catalog, keyed by the
        // same code that selected this branch.
        <InlineWarning tone="warn">
          {/* Narrowed rather than asserted: reaching this branch already required `closeErrorKind`
              to see an `ApiError` with a recognised code, so the guard is a type-level restatement
              of a fact the branch condition established, not a new runtime possibility. */}
          {apiErrorHeadline(closeBook.error instanceof ApiError ? closeBook.error : null)}
        </InlineWarning>
      ) : closeBook.error ? (
        <ErrorNote error={closeBook.error} />
      ) : null}

      <div className="termo-action-row">
        <span className="field__label">{tt('books.termo.editor.actionsLegend')}</span>
        <div className="stack--tight">
          <div className="form__actions">
            <Button
              type="button"
              variant="primary"
              icon={<Icon.BookClosed />}
              onClick={() => {
                if (!closePolicy.gated) {
                  closeBook.mutate(undefined);
                  return;
                }
                setConfirmClose(true);
              }}
              disabled={closeBook.isPending}
            >
              {closeBook.isPending
                ? et('books.encerramento.action.closing')
                : et('books.encerramento.action.close')}
            </Button>
          </div>
          <p className="field__hint">{et('books.encerramento.action.closeHint')}</p>
        </div>
      </div>

      <GuardedActionModal
        action="termo_encerramento.close"
        open={confirmClose}
        onClose={() => setConfirmClose(false)}
        title={et('books.encerramento.close.confirm.title')}
        intro={<p>{et('books.encerramento.close.confirm.intro')}</p>}
        confirmLabel={et('books.encerramento.close.confirm.action')}
        pendingLabel={et('books.encerramento.action.closing')}
        pending={closeBook.isPending}
        onConfirm={async () => {
          // Resolves either way so the dialog closes onto this panel's own refusal rendering: one
          // reviewed sentence per fail-closed cause ({@link closeErrorKind}), `ErrorNote` for the
          // rest. Rejecting would keep the dialog open over that, showing the raw sentence twice.
          await closeBook.mutateAsync(undefined).catch(() => undefined);
        }}
      />
    </div>
  );
}

/** A read-only summary for a sealed termo (the book is closed; the record is immutable). */
function TermoSealedView({ termo }: { termo: TermoInstrumentView }) {
  const tt = useTermoT();
  const et = useEncerramentoT();
  return (
    <div className="stack termo-editor">
      <InlineWarning tone="info" title={tt('books.termo.state.Sealed')}>
        {et('books.encerramento.state.SealedHint')}
      </InlineWarning>
      <dl className="deflist termo-status-table">
        <div>
          <dt>{tt('books.termo.editor.titleLabel')}</dt>
          <dd>{termo.title}</dd>
        </div>
        <div>
          <dt>{et('books.encerramento.field.closingDate')}</dt>
          <dd>{termo.fields.instrument_date ?? '—'}</dd>
        </div>
      </dl>
    </div>
  );
}

/**
 * The termo de encerramento panel for a book's opening section. Renders the right phase for the
 * loaded termo, or an honest note when the book has no separately editable termo (a one-shot/legacy
 * book). Only shown for a book being closed two-phase.
 */
export function TermoEncerramentoEditor({ bookId }: { bookId: string }) {
  const et = useEncerramentoT();
  const termo = useBookTermoEncerramento(bookId);

  if (termo.isLoading) {
    return (
      <Card title={et('books.encerramento.title')}>
        <div className="stack--tight">
          <Skeleton height="2.4rem" />
          <Skeleton height="2.4rem" />
          <Skeleton height="2.4rem" />
        </div>
      </Card>
    );
  }

  // A book with no encerramento draft (one-shot/legacy, or not yet in the two-phase close flow):
  // the endpoint 404s. That is not an error to surface — it is the honest "no separately editable
  // termo de encerramento" case, and the panel simply renders nothing so the acts view stays clean.
  if (termo.error instanceof ApiError && termo.error.status === 404) {
    return null;
  }
  if (termo.error) return <ErrorNote error={termo.error} />;
  if (!termo.data) return null;

  const data = termo.data;

  return (
    <Card title={et('books.encerramento.title')} actions={<StateBadge termo={data} />}>
      <p className="field__hint">{et('books.encerramento.subtitle')}</p>
      {data.state === 'Draft' ? (
        <TermoDraftForm termo={data} key={data.id} />
      ) : data.state === 'Signing' ? (
        <TermoSigningView termo={data} />
      ) : (
        <TermoSealedView termo={data} />
      )}
    </Card>
  );
}
