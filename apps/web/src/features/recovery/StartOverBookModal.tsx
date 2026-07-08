/**
 * Per-book start-over (t54-E4). Archives the current book + chain and opens a fresh
 * successor (`POST /v1/books/{id}/start-over`). Non-destructive — the old events stay
 * append-only and the archive is retained — so it is a single confirm + a required reason
 * plus the opening spec of the new book (no re-auth, no type-phrase). It is a
 * forward-writing lifecycle op, so the server blocks it (503) while the instance is
 * degraded; that error surfaces through the shared modal's inline + toast path.
 */
import { useState } from 'react';
import { useStartOverBook } from '../../api/hooks';
import type { BookView, NumberingScheme } from '../../api/types';
import { NUMBERING_SCHEMES } from '../../api/types';
import { numberingSchemeLabels, optionsFrom } from '../../api/labels';
import { useT } from '../../i18n';
import { ConfirmActionModal, Field, Input, Select, TextArea, useToast } from '../../ui';

export function StartOverBookModal({ book, onClose }: { book: BookView; onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const startOver = useStartOverBook(book.id);
  const [reason, setReason] = useState('');
  const [purpose, setPurpose] = useState(book.purpose ?? '');
  const [openingDate, setOpeningDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [signatories, setSignatories] = useState('');
  const [scheme, setScheme] = useState<NumberingScheme>(book.numbering_scheme ?? 'Sequential');

  const parsedSignatories = signatories
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const ready =
    reason.trim().length > 0 &&
    purpose.trim().length > 0 &&
    openingDate.length > 0 &&
    parsedSignatories.length > 0;

  return (
    <ConfirmActionModal
      open
      onClose={onClose}
      title={t('integrity.startOver.title')}
      intro={t('integrity.startOver.body')}
      confirmLabel={t('integrity.startOver.confirm')}
      pendingLabel={t('integrity.startOver.pending')}
      pending={startOver.isPending}
      canConfirm={ready}
      onConfirm={async () => {
        await startOver.mutateAsync({
          reason: reason.trim(),
          purpose: purpose.trim(),
          opening_date: openingDate,
          required_signatories: parsedSignatories,
          numbering_scheme: scheme,
        });
        toast.success(t('integrity.startOver.done'));
      }}
    >
      <Field label={t('integrity.startOver.reasonLabel')} htmlFor="so-reason">
        <TextArea
          id="so-reason"
          value={reason}
          placeholder={t('integrity.startOver.reasonPlaceholder')}
          onChange={(e) => setReason(e.target.value)}
        />
      </Field>
      <Field label={t('integrity.startOver.purposeLabel')} htmlFor="so-purpose">
        <Input id="so-purpose" value={purpose} onChange={(e) => setPurpose(e.target.value)} />
      </Field>
      <Field label={t('integrity.startOver.openingDateLabel')} htmlFor="so-date">
        <Input
          id="so-date"
          type="date"
          value={openingDate}
          onChange={(e) => setOpeningDate(e.target.value)}
        />
      </Field>
      <Field
        label={t('integrity.startOver.signatoriesLabel')}
        htmlFor="so-signatories"
        hint={t('integrity.startOver.signatoriesHint')}
      >
        <Input
          id="so-signatories"
          value={signatories}
          placeholder={t('integrity.startOver.signatoriesPlaceholder')}
          onChange={(e) => setSignatories(e.target.value)}
        />
      </Field>
      <Field label={t('integrity.startOver.numberingLabel')} htmlFor="so-scheme">
        <Select
          id="so-scheme"
          value={scheme}
          onChange={(e) => setScheme(e.target.value as NumberingScheme)}
          options={optionsFrom(NUMBERING_SCHEMES, numberingSchemeLabels)}
        />
      </Field>
    </ConfirmActionModal>
  );
}
