/**
 * Write the termo de encerramento and close a book (WFL-13, `POST /v1/books/:id/close`).
 * Extracted from the book detail aside onto its own route (`/books/:id/close`) so the
 * book view runs full width (t13 item 7). The optional `onClosed` callback lets the host
 * page navigate back to the book once it is closed.
 *
 * Two ways to close (t44, mirroring the two-phase abertura):
 *   • **One-shot** (the default) — closes the book in a single commit with a static termo de
 *     encerramento generated from this form. Today's behaviour, byte-for-byte.
 *   • **Two-phase** — mints only a `Draft` termo de encerramento for the still-`Open` book; the
 *     operator then drafts, signs and seals it through the {@link ./TermoEncerramentoEditor} before
 *     the book actually closes.
 *
 * DA1 — the reason picker offers the modelled reasons plus "Other", which reveals a required
 * free-text note (`{ Other: { note } }`). The note is ASSURANCE — a stated reason is never legally
 * required — but when chosen it must not be blank (the server rejects a blank note).
 *
 * `book.close` is a guarded action in the server's registry, floored at
 * confirm-with-reauth-and-phrase — and the server VERIFIES the proof on BOTH modes above, so this
 * form gathers it through {@link GuardedActionModal} before submitting. The dialog is not the
 * barrier; it is how the barrier is satisfied.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCloseBook } from '../../api/hooks';
import { closingReasonLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import {
  CLOSING_REASONS,
  type CloseBookBody,
  type ClosingReason,
  type ClosingReasonWire,
  type ConfirmationProof,
} from '../../api/types';
import {
  Button,
  ErrorNote,
  Field,
  GuardedActionModal,
  Icon,
  Input,
  Select,
  useGuardedActionPolicy,
  useToast,
} from '../../ui';
import {
  TermoSignatoryFields,
  parseTermoSignatories,
  type TermoSignatoryDraft,
} from './OpenBookForm';
import { useEncerramentoT } from './termoEncerramentoStrings';

/** The reason picker value: a modelled reason or the custom `Other` sentinel (DA1). */
type ReasonKind = ClosingReason | 'Other';

/** How the book is closed: one-shot (default) or a drafted-then-signed termo. */
type CloseMode = 'oneShot' | 'twoPhase';

/**
 * The typed phrase `ConfirmationAction::BookClose` carries. **Fixed and deliberately
 * non-localised** — a token to transcribe, not a sentence to read — so it never comes from a locale
 * catalog and is compared byte-exact by the server.
 */
const BOOK_CLOSE_CONFIRM_PHRASE = 'ENCERRAR LIVRO';

export function CloseBookForm({ bookId, onClosed }: { bookId: string; onClosed?: () => void }) {
  const t = useT();
  const et = useEncerramentoT();
  const toast = useToast();
  const navigate = useNavigate();
  const close = useCloseBook(bookId);
  // The server declares the level for `book.close`; this dialog applies it.
  const closePolicy = useGuardedActionPolicy('book.close');
  const [confirmClose, setConfirmClose] = useState(false);
  const [mode, setMode] = useState<CloseMode>('oneShot');
  const [reasonKind, setReasonKind] = useState<ReasonKind>('BookFull');
  const [reasonNote, setReasonNote] = useState('');
  const [closingDate, setClosingDate] = useState('');
  const [signatories, setSignatories] = useState<TermoSignatoryDraft[]>([
    { name: '', capacity: '', email: '' },
  ]);

  const reasonOptions = [
    ...optionsFrom(CLOSING_REASONS, closingReasonLabels),
    { value: 'Other', label: et('books.encerramento.reason.other') },
  ];

  function closingReason(): ClosingReasonWire {
    return reasonKind === 'Other' ? { Other: { note: reasonNote.trim() } } : reasonKind;
  }

  const twoPhase = mode === 'twoPhase';

  function closeBody(confirmation?: ConfirmationProof): CloseBookBody {
    return {
      reason: closingReason(),
      closing_date: closingDate,
      required_signatories: parseTermoSignatories(signatories),
      ...(twoPhase ? { one_shot: false } : {}),
      ...(confirmation ? { confirmation } : {}),
    };
  }

  function onClosedOrDrafted() {
    if (twoPhase) {
      // The book stays Open with a Draft termo de encerramento; land on the termo section so
      // the operator can draft, sign and seal it.
      toast.success(et('books.encerramento.createdToast'));
      navigate(`/books/${bookId}/opening`);
    } else {
      toast.success(t('toast.book.closed'));
      onClosed?.();
    }
  }

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    // An `off` policy has no proof to gather, so submitting is the whole action; anything gated
    // goes through the dialog, which is where the step-up and the typed phrase are collected.
    if (!closePolicy.gated) {
      close.mutate(closeBody(), {
        onSuccess: onClosedOrDrafted,
        onError: (err) => toast.error(err),
      });
      return;
    }
    setConfirmClose(true);
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <Field
        label={et('books.encerramento.mode.legend')}
        htmlFor="close-mode"
        help={
          mode === 'twoPhase'
            ? et('books.encerramento.mode.twoPhaseHelp')
            : et('books.encerramento.mode.oneShotHelp')
        }
      >
        <Select
          id="close-mode"
          value={mode}
          onChange={(e) => setMode(e.target.value as CloseMode)}
          options={[
            { value: 'oneShot', label: et('books.encerramento.mode.oneShot') },
            { value: 'twoPhase', label: et('books.encerramento.mode.twoPhase') },
          ]}
        />
      </Field>
      <Field label={t('books.close.reason')} htmlFor="close-reason">
        <Select
          id="close-reason"
          value={reasonKind}
          onChange={(e) => setReasonKind(e.target.value as ReasonKind)}
          options={reasonOptions}
        />
      </Field>
      {reasonKind === 'Other' ? (
        <Field
          label={et('books.encerramento.reason.otherNote')}
          htmlFor="close-reason-note"
          help={et('books.encerramento.reason.otherNoteHelp')}
        >
          <Input
            id="close-reason-note"
            value={reasonNote}
            required
            placeholder={et('books.encerramento.reason.otherPlaceholder')}
            onChange={(e) => setReasonNote(e.target.value)}
          />
        </Field>
      ) : null}
      <Field label={t('books.close.date')} htmlFor="close-date">
        <Input
          id="close-date"
          type="date"
          required
          value={closingDate}
          onChange={(e) => setClosingDate(e.target.value)}
        />
      </Field>
      <Field label={t('books.close.signatories')}>
        <TermoSignatoryFields
          idPrefix="close-signatories"
          rows={signatories}
          onChange={setSignatories}
        />
      </Field>
      {close.error ? <ErrorNote error={close.error} /> : null}
      <div className="form__actions">
        <Button
          type="submit"
          variant="secondary"
          icon={<Icon.BookClosed />}
          disabled={close.isPending}
        >
          {close.isPending ? t('books.close.closing') : t('books.closeBook')}
        </Button>
      </div>

      <GuardedActionModal
        action="book.close"
        open={confirmClose}
        onClose={() => setConfirmClose(false)}
        title={et('books.encerramento.start.confirm.title')}
        intro={
          <p>
            {et(
              twoPhase
                ? 'books.encerramento.start.confirm.twoPhaseIntro'
                : 'books.encerramento.start.confirm.oneShotIntro',
            )}
          </p>
        }
        confirmLabel={et('books.encerramento.start.confirm.action')}
        pendingLabel={t('books.close.closing')}
        pending={close.isPending}
        onConfirm={async ({ reauth }) => {
          // The server VERIFIES this proof: `book.close` is floored at
          // confirm-with-reauth-and-phrase and the route checks it before either arm runs, so a
          // request without both halves is a `403` that closes nothing and drafts nothing. The
          // dialog gathers them; this call site transmits them — the phrase is a byte-exact
          // literal, deliberately non-localised.
          //
          // Resolves either way so the dialog closes onto this form's own refusal rendering
          // (`ErrorNote` above plus the toast), rather than staying open over it and showing the
          // same sentence twice.
          await close
            .mutateAsync(closeBody({ reauth, confirm_phrase: BOOK_CLOSE_CONFIRM_PHRASE }))
            .then(onClosedOrDrafted)
            .catch((err) => toast.error(err));
        }}
      />
    </form>
  );
}
