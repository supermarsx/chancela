/**
 * Write the termo de encerramento and close a book (WFL-13, `POST /v1/books/:id/close`).
 * Extracted from the book detail aside onto its own route (`/livros/:id/encerrar`) so the
 * book view runs full width (t13 item 7). The optional `onClosed` callback lets the host
 * page navigate back to the book once it is closed.
 */
import { useState } from 'react';
import { useCloseBook } from '../../api/hooks';
import { closingReasonLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import { CLOSING_REASONS, type ClosingReason } from '../../api/types';
import { Button, ErrorNote, Field, Icon, Input, Select, TextArea } from '../../ui';
import { parseLines } from './OpenBookForm';

export function CloseBookForm({ bookId, onClosed }: { bookId: string; onClosed?: () => void }) {
  const t = useT();
  const close = useCloseBook(bookId);
  const [reason, setReason] = useState<ClosingReason>('BookFull');
  const [closingDate, setClosingDate] = useState('');
  const [signatories, setSignatories] = useState('');

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    close.mutate(
      {
        reason,
        closing_date: closingDate,
        required_signatories: parseLines(signatories),
      },
      { onSuccess: () => onClosed?.() },
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <Field label={t('books.close.reason')} htmlFor="close-reason">
        <Select
          id="close-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value as ClosingReason)}
          options={optionsFrom(CLOSING_REASONS, closingReasonLabels)}
        />
      </Field>
      <Field label={t('books.close.date')} htmlFor="close-date">
        <Input
          id="close-date"
          type="date"
          required
          value={closingDate}
          onChange={(e) => setClosingDate(e.target.value)}
        />
      </Field>
      <Field
        label={t('books.close.signatories')}
        htmlFor="close-signatories"
        hint={t('books.oneNamePerLine')}
      >
        <TextArea
          id="close-signatories"
          rows={3}
          value={signatories}
          onChange={(e) => setSignatories(e.target.value)}
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
