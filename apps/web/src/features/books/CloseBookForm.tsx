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
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCloseBook } from '../../api/hooks';
import { closingReasonLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import { CLOSING_REASONS, type ClosingReason, type ClosingReasonWire } from '../../api/types';
import { Button, ErrorNote, Field, Icon, Input, Select, useToast } from '../../ui';
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

export function CloseBookForm({ bookId, onClosed }: { bookId: string; onClosed?: () => void }) {
  const t = useT();
  const et = useEncerramentoT();
  const toast = useToast();
  const navigate = useNavigate();
  const close = useCloseBook(bookId);
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

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const twoPhase = mode === 'twoPhase';
    close.mutate(
      {
        reason: closingReason(),
        closing_date: closingDate,
        required_signatories: parseTermoSignatories(signatories),
        ...(twoPhase ? { one_shot: false } : {}),
      },
      {
        onSuccess: () => {
          if (twoPhase) {
            // The book stays Open with a Draft termo de encerramento; land on the termo section so
            // the operator can draft, sign and seal it.
            toast.success(et('books.encerramento.createdToast'));
            navigate(`/books/${bookId}/opening`);
          } else {
            toast.success(t('toast.book.closed'));
            onClosed?.();
          }
        },
        onError: (e) => toast.error(e),
      },
    );
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
    </form>
  );
}
