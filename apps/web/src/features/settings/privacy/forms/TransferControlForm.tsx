/**
 * The create/edit form for a controlo de transferência (t55). Moved verbatim out of
 * `PrivacyComplianceSection.tsx`, where — like the breach form — it rendered in a transient
 * `<Card>` above the list rather than at an address of its own.
 *
 * Twelve fields including the destination country, the transfer mechanism and the safeguards a
 * RGPD Cap. V transfer rests on. Prose, checked against a regulation, returned to.
 */
import type { FormEvent } from 'react';
import type { PrivacyRecordStatus, PrivacyRiskLevel } from '../../../../api/types';
import { useT } from '../../../../i18n';
import { Field, InlineWarning, Input, Select, TextArea } from '../../../../ui';
import { splitList, type TransferControlFormState } from '../privacyFormState';
import { riskSelectOptionsFor, statusSelectOptionsFor } from '../privacyLabels';
import { PrivacyFormActions } from './PrivacyFormActions';

export function TransferControlForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  cancelTo,
  onSubmit,
}: {
  form: TransferControlFormState;
  setForm: (next: TransferControlFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel?: () => void;
  cancelTo?: string;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-transfer-${editing ? 'edit' : 'new'}`;
  const canSubmit =
    form.name.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    form.recipient.trim().length > 0 &&
    form.destinationCountry.trim().length > 0 &&
    form.transferMechanism.trim().length > 0 &&
    splitList(form.dataCategories).length > 0 &&
    splitList(form.safeguards).length > 0 &&
    !saving;

  return (
    <form
      className="form settings-rows"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.transfer.field.name')} htmlFor={`${idPrefix}-name`}>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field label={t('settings.privacy.transfer.field.purpose')} htmlFor={`${idPrefix}-purpose`}>
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>
      <Field label={t('settings.privacy.transfer.field.legalBasis')} htmlFor={`${idPrefix}-legal`}>
        <Input
          id={`${idPrefix}-legal`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.transfer.field.categories')}
        htmlFor={`${idPrefix}-categories`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.transfer.field.recipient')}
          htmlFor={`${idPrefix}-recipient`}
        >
          <Input
            id={`${idPrefix}-recipient`}
            value={form.recipient}
            onChange={(e) => setForm({ ...form, recipient: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.transfer.field.destination')}
          htmlFor={`${idPrefix}-destination`}
        >
          <Input
            id={`${idPrefix}-destination`}
            value={form.destinationCountry}
            onChange={(e) => setForm({ ...form, destinationCountry: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field
        label={t('settings.privacy.transfer.field.mechanism')}
        htmlFor={`${idPrefix}-mechanism`}
      >
        <Input
          id={`${idPrefix}-mechanism`}
          value={form.transferMechanism}
          onChange={(e) => setForm({ ...form, transferMechanism: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.transfer.field.safeguards')}
        htmlFor={`${idPrefix}-safeguards`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-safeguards`}
          value={form.safeguards}
          onChange={(e) => setForm({ ...form, safeguards: e.target.value })}
          rows={3}
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.field.risk')} htmlFor={`${idPrefix}-risk`}>
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptionsFor(t)}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptionsFor(t)}
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.field.reviewNotes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.reviewNotes}
          onChange={(e) => setForm({ ...form, reviewNotes: e.target.value })}
          rows={3}
        />
      </Field>
      <InlineWarning tone="info" title={t('settings.privacy.evidence.operator.title')}>
        {t('settings.privacy.evidence.operator.transferBody')}
      </InlineWarning>
      <Field
        label={t('settings.privacy.evidence.field.notes')}
        htmlFor={`${idPrefix}-evidence-notes`}
      >
        <TextArea
          id={`${idPrefix}-evidence-notes`}
          value={form.evidenceNotes}
          onChange={(e) => setForm({ ...form, evidenceNotes: e.target.value })}
          rows={2}
        />
      </Field>
      <PrivacyFormActions
        editing={editing}
        saving={saving}
        canSubmit={canSubmit}
        onCancel={onCancel}
        cancelTo={cancelTo}
      />
    </form>
  );
}
