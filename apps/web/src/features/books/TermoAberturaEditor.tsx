/**
 * TermoAberturaEditor — the termo de abertura as a document in its own right (t23, Cluster B).
 *
 * A book opened two-phase (`one_shot: false`) lands in `Created` with a `Draft` termo de abertura.
 * This panel drives the termo's whole lifecycle as an ata:
 *
 *   • **Draft** — the title, body clauses, fields and signatory slots are freely editable and saved
 *     with a PATCH. "Avançar para assinatura" freezes the content (`advance`).
 *   • **Signing** — the content is frozen; each required signatory signs in order (`sign`), then
 *     "Abrir livro" seals the termo and opens the book (`open`).
 *   • **Sealed** — the termo took effect and the book is open; the record is immutable.
 *
 * Honest fail-closed open (t23/t41): real per-slot PAdES signing SHIPS — the "Assinar" button drives
 * `POST …/termo/abertura/sign/pkcs12`, which signs the frozen snapshot with a local PKCS#12
 * certificate and records the signature in `instrument_signatures`. What still fails closed is a
 * termo whose required slots are not ALL really signed: `slot.signed` is provisional workflow state
 * that the reference-only `POST …/termo/abertura/sign` endpoint also sets, and only a real signature
 * satisfies the server's gate. The panel surfaces that one refusal — matched on the server's stable
 * `termo_abertura_not_signed` code, never on a bare 409 — and keeps the book `Created`; it never
 * pretends the book was opened. All copy is ASSURANCE except the two genuinely legal framings (the
 * capacity allow-list and the at-least-one-signatory minimum).
 */
import { useMemo, useState } from 'react';
import { ApiError } from '../../api/client';
import {
  useAdvanceBookTermoAbertura,
  useBook,
  useBookTermoAbertura,
  useDownloadBookTermoAberturaDocument,
  useDownloadBookTermoAberturaSignatureDocument,
  useEntity,
  useOpenBookFromTermo,
  usePatchBookTermoAbertura,
  useSignBookTermoAberturaPkcs12,
} from '../../api/hooks';
import { optionsFrom, signatoryCapacityLabels } from '../../api/labels';
import {
  SIGNATORY_CAPACITIES,
  type PatchTermoAberturaBody,
  type SignatoryCapacity,
  type TermoClauseView,
  type TermoCompletionPolicy,
  type TermoInstrumentView,
  type TermoSlotView,
} from '../../api/types';
import { saveBlobAs } from '../../desktop/saveFile';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  Skeleton,
  TextArea,
  Toggle,
  useToast,
} from '../../ui';
import { useTermoT } from './termoStrings';
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

/**
 * Whether an `open` failure is the server's evidentiary fail-closed refusal, identified by its
 * stable error **code** (`chancela-api`'s `termo.rs` `TermoSignatureGate`).
 *
 * Matched on the code, not on `status === 409` alone: the open path answers 409 for other reasons
 * too (the book is no longer `Created`, for one), and rendering those under a headline that asserts
 * the termo is unsigned tells the operator the wrong cause. Anything unrecognised falls through to
 * {@link ErrorNote}, which reports what the server actually said. Mirrors
 * `TermoEncerramentoEditor`'s `closeErrorKind`.
 */
function isNotSignedRefusal(error: unknown): boolean {
  return (
    error instanceof ApiError && error.status === 409 && error.code === 'termo_abertura_not_signed'
  );
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

/**
 * The preserved termo artifacts. Multi-signatory termos intentionally expose one independently
 * verifiable PAdES revision per signed slot; no client-side merge can preserve those signatures.
 */
function TermoDocumentActions({ termo }: { termo: TermoInstrumentView }) {
  const t = useT();
  const tt = useTermoT();
  const toast = useToast();
  const base = useDownloadBookTermoAberturaDocument(termo.book_id);
  const signed = useDownloadBookTermoAberturaSignatureDocument(termo.book_id);
  // `slot.signed` is only workflow collection state. A signed-PDF action exists solely when the
  // server confirms that this slot has a stored PAdES artifact.
  const signedSlots = termo.signatories.filter((slot) => slot.pades_document_available === true);

  function saveBase() {
    base.mutate(undefined, {
      onSuccess: async (blob) => {
        try {
          await saveBlobAs({
            blob,
            filename: `termo-de-abertura-${termo.book_id}-base-sem-assinaturas.pdf`,
            contentType: 'application/pdf',
          });
          toast.success(t('toast.document.downloaded'));
        } catch (error) {
          toast.error(error);
        }
      },
      onError: (error) => toast.error(error),
    });
  }

  function saveSigned(slot: TermoSlotView) {
    signed.mutate(slot.id, {
      onSuccess: async (blob) => {
        try {
          await saveBlobAs({
            blob,
            filename: `termo-de-abertura-assinado-${slot.id}.pdf`,
            contentType: 'application/pdf',
          });
          toast.success(t('toast.signing.downloaded'));
        } catch (error) {
          toast.error(error);
        }
      },
      onError: (error) => toast.error(error),
    });
  }

  return (
    <div className="row-wrap">
      <Button
        type="button"
        variant="secondary"
        icon={<Icon.Tray />}
        disabled={base.isPending}
        onClick={saveBase}
      >
        {tt('books.termo.document.downloadUnsignedBase')}
      </Button>
      {signedSlots.map((slot) => (
        <Button
          key={slot.id}
          type="button"
          variant="secondary"
          icon={<Icon.Tray />}
          disabled={signed.isPending}
          onClick={() => saveSigned(slot)}
        >
          {t('signing.download')}: {slot.name}
        </Button>
      ))}
    </div>
  );
}

/**
 * The draft-editing form. Remounted (via `key`) when the termo identity changes, so it seeds once.
 *
 * The sede box is the one field that does NOT seed once. `entitySeatDefault` (the entity's
 * registered office) arrives from its own query, possibly after this form mounts, so the box shows
 * the operator's edit when they have made one and the entity default otherwise — a late-arriving
 * default fills an untouched box instead of clobbering typed text. `entitySeatPending` says the
 * default is still unknown, which is why the "no registered office" warning waits for it: an empty
 * box during loading is not evidence the entity has no seat.
 *
 * What the operator sees in the box is what the termo declares: the form always sends it, so a
 * later edit to the entity cannot restate a drafted termo behind their back. Clearing the box sends
 * `''`, which drops the termo back to tracking the entity — it never declares a blank office, and
 * the server refuses to seal one either way.
 */
function TermoDraftForm({
  termo,
  entitySeatDefault,
  entitySeatPending,
}: {
  termo: TermoInstrumentView;
  entitySeatDefault: string;
  entitySeatPending: boolean;
}) {
  const tt = useTermoT();
  const toast = useToast();
  const patch = usePatchBookTermoAbertura(termo.book_id);
  const advance = useAdvanceBookTermoAbertura(termo.book_id);

  const [title, setTitle] = useState(termo.title);
  const [clauses, setClauses] = useState<ClauseDraft[]>(termo.body.map(clauseToDraft));
  const [purpose, setPurpose] = useState(termo.fields.purpose ?? '');
  const [openingDate, setOpeningDate] = useState(termo.fields.instrument_date ?? '');
  const [pageCapacity, setPageCapacity] = useState(
    termo.fields.page_capacity != null ? String(termo.fields.page_capacity) : '',
  );
  const [place, setPlace] = useState(termo.fields.place ?? '');
  // `null` = the operator has not touched the box, so it still tracks whatever default resolves.
  const [entitySeatEdit, setEntitySeatEdit] = useState<string | null>(
    termo.fields.entity_seat ?? null,
  );
  const entitySeat = entitySeatEdit ?? entitySeatDefault;
  const [bookNumber, setBookNumber] = useState(
    termo.fields.book_number != null ? String(termo.fields.book_number) : '',
  );
  const [predecessorNote, setPredecessorNote] = useState(termo.fields.predecessor_note ?? '');
  const [slots, setSlots] = useState<SlotDraft[]>(termo.signatories.map(slotToDraft));

  const capacityOptions = [
    ...optionsFrom(SIGNATORY_CAPACITIES, signatoryCapacityLabels),
    { value: 'Other', label: tt('books.termo.signatory.other') },
  ];

  function updateClause(index: number, next: Partial<ClauseDraft>) {
    setClauses((rows) => rows.map((row, idx) => (idx === index ? { ...row, ...next } : row)));
  }
  function updateSlot(index: number, next: Partial<SlotDraft>) {
    setSlots((rows) => rows.map((row, idx) => (idx === index ? { ...row, ...next } : row)));
  }

  function buildBody(): PatchTermoAberturaBody {
    return {
      title,
      body: clauses.map((clause) => ({
        heading: clause.heading.trim() || undefined,
        text: clause.text,
      })),
      purpose: purpose.trim() || undefined,
      opening_date: openingDate || undefined,
      page_capacity: pageCapacity ? Number(pageCapacity) : undefined,
      place: place.trim() || undefined,
      book_number: bookNumber ? Number(bookNumber) : undefined,
      predecessor_note: predecessorNote.trim() || undefined,
      // Sent even when empty (unlike the fields above): '' is how the operator clears the
      // declared office and goes back to tracking the entity's, which omitting the key cannot say.
      entity_seat: entitySeat.trim(),
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

  function onAdvance() {
    // Persist the current edits first (the freeze validates the saved termo), then advance.
    patch.mutate(buildBody(), {
      onSuccess: () =>
        advance.mutate(undefined, {
          onError: (error) => toast.error(error),
        }),
      onError: (error) => toast.error(error),
    });
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
          htmlFor="termo-title"
          help={tt('books.termo.editor.titleHelp')}
        >
          <Input id="termo-title" value={title} onChange={(e) => setTitle(e.target.value)} />
        </Field>

        <p className="card__label termo-editor__section-label" role="heading" aria-level={4}>
          {tt('books.termo.editor.fieldsLegend')}
        </p>

        {/* Fields (all ASSURANCE/product). */}
        <Field
          label={tt('books.termo.field.purpose')}
          htmlFor="termo-purpose"
          help={tt('books.termo.field.purposeHelp')}
        >
          <Input id="termo-purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)} />
        </Field>
        <Field
          label={tt('books.termo.field.openingDate')}
          htmlFor="termo-date"
          help={tt('books.termo.field.openingDateHelp')}
        >
          <Input
            id="termo-date"
            type="date"
            value={openingDate}
            onChange={(e) => setOpeningDate(e.target.value)}
          />
        </Field>
        <Field
          label={tt('books.termo.field.pageCapacity')}
          htmlFor="termo-pages"
          help={tt('books.termo.field.pageCapacityHelp')}
        >
          <Input
            id="termo-pages"
            type="number"
            min={1}
            value={pageCapacity}
            onChange={(e) => setPageCapacity(e.target.value)}
          />
        </Field>
        <Field
          label={tt('books.termo.field.bookNumber')}
          htmlFor="termo-number"
          help={tt('books.termo.field.bookNumberHelp')}
        >
          <Input
            id="termo-number"
            type="number"
            min={1}
            value={bookNumber}
            onChange={(e) => setBookNumber(e.target.value)}
          />
        </Field>
        {/* The registered office, kept adjacent to "Local" precisely because the two are easy to
            confuse: this is the entity's registered address, that is where the act was drawn up. */}
        <Field
          label={tt('books.termo.field.entitySeat')}
          htmlFor="termo-entity-seat"
          help={tt('books.termo.field.entitySeatHelp')}
        >
          <Input
            id="termo-entity-seat"
            value={entitySeat}
            onChange={(e) => setEntitySeatEdit(e.target.value)}
          />
        </Field>
        {!entitySeatPending && entitySeat.trim() === '' ? (
          <InlineWarning tone="warn" title={tt('books.termo.field.entitySeat')}>
            {tt('books.termo.field.entitySeatMissing')}
          </InlineWarning>
        ) : null}
        <Field
          label={tt('books.termo.field.place')}
          htmlFor="termo-place"
          help={tt('books.termo.field.placeHelp')}
        >
          <Input id="termo-place" value={place} onChange={(e) => setPlace(e.target.value)} />
        </Field>
        <Field
          label={tt('books.termo.field.predecessorNote')}
          htmlFor="termo-predecessor-note"
          help={tt('books.termo.field.predecessorNoteHelp')}
        >
          <Input
            id="termo-predecessor-note"
            value={predecessorNote}
            onChange={(e) => setPredecessorNote(e.target.value)}
          />
        </Field>

        {/* Body clauses: each clause is itself a compact label/control table. */}
        <Field label={tt('books.termo.editor.bodyLegend')} hint={tt('books.termo.editor.bodyHelp')}>
          <div className="stack--tight termo-editor__collection">
            {clauses.length === 0 ? (
              <p className="field__hint">{tt('books.termo.editor.noClauses')}</p>
            ) : null}
            {clauses.map((clause, index) => (
              <div className="field-table termo-editor__block" key={index}>
                <Field
                  label={tt('books.termo.editor.clauseHeading')}
                  htmlFor={`termo-clause-heading-${index}`}
                >
                  <Input
                    id={`termo-clause-heading-${index}`}
                    value={clause.heading}
                    onChange={(e) => updateClause(index, { heading: e.target.value })}
                  />
                </Field>
                <Field
                  label={tt('books.termo.editor.clauseText')}
                  htmlFor={`termo-clause-text-${index}`}
                >
                  <TextArea
                    id={`termo-clause-text-${index}`}
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

        {/* Signatory slots use the same nested row table, including the required flag that was
            previously persisted but not editable. */}
        <Field
          label={tt('books.termo.editor.signatoriesLegend')}
          hint={tt('books.termo.rule.allowList')}
        >
          <div className="stack--tight termo-editor__collection">
            {slots.map((slot, index) => (
              <div className="field-table termo-editor__block" key={index}>
                <Field
                  label={tt('books.termo.signatory.name')}
                  htmlFor={`termo-slot-name-${index}`}
                  help={tt('books.termo.signatory.nameHelp')}
                >
                  <Input
                    id={`termo-slot-name-${index}`}
                    value={slot.name}
                    onChange={(e) => updateSlot(index, { name: e.target.value })}
                  />
                </Field>
                <Field
                  label={tt('books.termo.signatory.capacity')}
                  htmlFor={`termo-slot-capacity-${index}`}
                  help={tt('books.termo.signatory.capacityHelp')}
                >
                  <Select
                    id={`termo-slot-capacity-${index}`}
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
                    htmlFor={`termo-slot-note-${index}`}
                    help={tt('books.termo.signatory.otherHelp')}
                  >
                    <Input
                      id={`termo-slot-note-${index}`}
                      value={slot.capacityNote}
                      required
                      placeholder={tt('books.termo.signatory.otherPlaceholder')}
                      onChange={(e) => updateSlot(index, { capacityNote: e.target.value })}
                    />
                  </Field>
                ) : null}
                <Field
                  label={tt('books.termo.signatory.email')}
                  htmlFor={`termo-slot-email-${index}`}
                  help={tt('books.termo.signatory.emailHelp')}
                >
                  <Input
                    id={`termo-slot-email-${index}`}
                    type="email"
                    value={slot.email}
                    onChange={(e) => updateSlot(index, { email: e.target.value })}
                  />
                </Field>
                <Field
                  label={tt('books.termo.signatory.order')}
                  htmlFor={`termo-slot-order-${index}`}
                  help={tt('books.termo.signatory.orderHelp')}
                >
                  <Input
                    id={`termo-slot-order-${index}`}
                    type="number"
                    min={1}
                    value={String(slot.order)}
                    onChange={(e) => updateSlot(index, { order: Number(e.target.value) })}
                  />
                </Field>
                <Field label={tt('books.termo.signatory.required')}>
                  <Toggle
                    id={`termo-slot-required-${index}`}
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
    </div>
  );
}

/** The signing phase: content frozen, per-slot signatures collected, then the book is opened. */
function TermoSigningView({ termo }: { termo: TermoInstrumentView }) {
  const tt = useTermoT();
  const formatPolicy = useFormatPolicy();
  const sign = useSignBookTermoAberturaPkcs12(termo.book_id);
  const openBook = useOpenBookFromTermo(termo.book_id);
  // The slot whose real per-slot PAdES co-signature form is open (null = none expanded yet).
  const [activeSlotId, setActiveSlotId] = useState<string | null>(null);

  const orderedSlots = useMemo(
    () => [...termo.signatories].sort((a, b) => a.order - b.order),
    [termo.signatories],
  );
  // Sequential collection: the next slot allowed to sign is the earliest unsigned required one.
  const nextSlotId = orderedSlots.find((slot) => slot.required && !slot.signed)?.id;

  const openFailedClosed = isNotSignedRefusal(openBook.error);

  return (
    <div className="stack termo-editor">
      <InlineWarning tone="info" title={tt('books.termo.signing.legend')}>
        {tt('books.termo.signing.intro')}
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

      {openFailedClosed ? (
        <InlineWarning tone="warn" title={tt('books.termo.open.notSignedTitle')}>
          {tt('books.termo.open.notSignedBody')}
        </InlineWarning>
      ) : openBook.error ? (
        <ErrorNote error={openBook.error} />
      ) : null}

      <div className="termo-action-row">
        <span className="field__label">{tt('books.termo.editor.actionsLegend')}</span>
        <div className="stack--tight">
          <TermoDocumentActions termo={termo} />
          <div className="form__actions">
            <Button
              type="button"
              variant="primary"
              icon={<Icon.BookPlus />}
              onClick={() => openBook.mutate(undefined)}
              disabled={openBook.isPending}
            >
              {openBook.isPending
                ? tt('books.termo.action.opening')
                : tt('books.termo.action.open')}
            </Button>
          </div>
          <p className="field__hint">{tt('books.termo.action.openHint')}</p>
        </div>
      </div>
    </div>
  );
}

/** A read-only summary for a sealed termo (the book is open; the record is immutable). */
function TermoSealedView({ termo }: { termo: TermoInstrumentView }) {
  const tt = useTermoT();
  return (
    <div className="stack termo-editor">
      <InlineWarning tone="info" title={tt('books.termo.state.Sealed')}>
        {tt('books.termo.state.SealedHint')}
      </InlineWarning>
      <dl className="deflist termo-status-table">
        <div>
          <dt>{tt('books.termo.editor.titleLabel')}</dt>
          <dd>{termo.title}</dd>
        </div>
        <div>
          <dt>{tt('books.termo.field.purpose')}</dt>
          <dd>{termo.fields.purpose ?? '—'}</dd>
        </div>
      </dl>
      <div className="termo-action-row">
        <span className="field__label">{tt('books.termo.editor.actionsLegend')}</span>
        <TermoDocumentActions termo={termo} />
      </div>
    </div>
  );
}

/**
 * The termo de abertura panel for a book's opening section. Renders the right phase for the loaded
 * termo, or an honest note when the book has no separately editable termo (a one-shot/legacy book).
 */
export function TermoAberturaEditor({ bookId }: { bookId: string }) {
  const tt = useTermoT();
  const termo = useBookTermoAbertura(bookId);
  // The sede default: the book names the entity, the entity holds the registered office. Read here
  // rather than passed down from the page so the panel stays a `bookId`-only component.
  const book = useBook(bookId);
  const entityId = book.data?.entity_id;
  const entity = useEntity(entityId ?? '', !!entityId);
  const entitySeatDefault = entity.data?.seat ?? '';
  // Still resolving while the book is in flight, or the entity behind it is. A failure on either
  // settles it: the office is then simply unknown, and the draft form says so rather than stalling.
  const entitySeatPending = book.isPending || (!!entityId && entity.isPending);

  if (termo.isLoading) {
    return (
      <Card title={tt('books.termo.title')}>
        <div className="stack--tight">
          <Skeleton height="2.4rem" />
          <Skeleton height="2.4rem" />
          <Skeleton height="2.4rem" />
        </div>
      </Card>
    );
  }

  // A one-shot/legacy book has no draft termo: the endpoint 404s. That is not an error to surface —
  // it is the honest "this book has no separately editable termo" case.
  if (termo.error instanceof ApiError && termo.error.status === 404) {
    return (
      <InlineWarning tone="info" title={tt('books.termo.title')}>
        {tt('books.termo.none')}
      </InlineWarning>
    );
  }
  if (termo.error) return <ErrorNote error={termo.error} />;
  if (!termo.data) return null;

  const data = termo.data;

  return (
    <Card title={tt('books.termo.title')} actions={<StateBadge termo={data} />}>
      <p className="field__hint">{tt('books.termo.subtitle')}</p>
      {data.state === 'Draft' ? (
        <TermoDraftForm
          termo={data}
          entitySeatDefault={entitySeatDefault}
          entitySeatPending={entitySeatPending}
          key={data.id}
        />
      ) : data.state === 'Signing' ? (
        <TermoSigningView termo={data} />
      ) : (
        <TermoSealedView termo={data} />
      )}
    </Card>
  );
}
