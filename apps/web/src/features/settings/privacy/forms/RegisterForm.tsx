/**
 * The create/edit form for the two register-shaped surfaces — the registo de atividades de
 * tratamento and the AIPD (t55). Moved verbatim out of `PrivacyComplianceSection.tsx`.
 *
 * `kind` is the only difference between the two: it picks the primary field's label and help, and
 * gates the DPIA-only evidence block. Two components for a six-line difference would be worse.
 *
 * The form is presentational — it holds no state, runs no mutation and knows no address. Its
 * owner (the record page, or for now the list panel's modal) supplies `form`/`setForm` and decides
 * what submit and cancel mean.
 */
import type { FormEvent } from 'react';
import type {
  DpiaEvidenceKind,
  PrivacyRecordStatus,
  PrivacyRiskLevel,
} from '../../../../api/types';
import { useT } from '../../../../i18n';
import { Field, InlineWarning, Input, Select, TextArea } from '../../../../ui';
import { splitList, type RegisterFormState, type RegisterKind } from '../privacyFormState';
import {
  breachEvidenceOptionsFor,
  riskSelectOptionsFor,
  statusSelectOptionsFor,
} from '../privacyLabels';
import { PrivacyFormActions } from './PrivacyFormActions';

export function RegisterForm({
  kind,
  form,
  setForm,
  editing,
  saving,
  onCancel,
  cancelTo,
  onSubmit,
}: {
  kind: RegisterKind;
  form: RegisterFormState;
  setForm: (next: RegisterFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel?: () => void;
  cancelTo?: string;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-${kind}-${editing ? 'edit' : 'new'}`;
  const primaryLabel =
    kind === 'processor'
      ? t('settings.privacy.register.field.processorName')
      : t('settings.privacy.register.field.dpiaTitle');
  const parsedCategories = splitList(form.dataCategories);
  const canSubmit =
    form.primary.trim().length > 0 &&
    form.purpose.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    parsedCategories.length > 0 &&
    !saving;

  return (
    <form
      className="form settings-rows"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field
        label={primaryLabel}
        htmlFor={`${idPrefix}-primary`}
        help={
          kind === 'processor'
            ? t('settings.privacy.help.processor')
            : t('settings.privacy.help.dpia')
        }
      >
        <Input
          id={`${idPrefix}-primary`}
          value={form.primary}
          onChange={(e) => setForm({ ...form, primary: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.purpose')}
        htmlFor={`${idPrefix}-purpose`}
        help={t('settings.privacy.help.purpose')}
      >
        <TextArea
          id={`${idPrefix}-purpose`}
          value={form.purpose}
          onChange={(e) => setForm({ ...form, purpose: e.target.value })}
          rows={3}
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.legalBasis')}
        htmlFor={`${idPrefix}-legal-basis`}
        help={t('settings.privacy.help.legalBasis')}
      >
        <Input
          id={`${idPrefix}-legal-basis`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.categories')}
        htmlFor={`${idPrefix}-data-categories`}
        hint={t('settings.privacy.register.hint.categories')}
      >
        <TextArea
          id={`${idPrefix}-data-categories`}
          value={form.dataCategories}
          onChange={(e) => setForm({ ...form, dataCategories: e.target.value })}
          rows={3}
        />
      </Field>

      <Field
        label={t('settings.privacy.register.field.subprocessors')}
        htmlFor={`${idPrefix}-subprocessors`}
        hint={t('settings.privacy.register.hint.subprocessors')}
      >
        <TextArea
          id={`${idPrefix}-subprocessors`}
          value={form.subprocessors}
          onChange={(e) => setForm({ ...form, subprocessors: e.target.value })}
          rows={3}
        />
      </Field>

      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.field.risk')}
          htmlFor={`${idPrefix}-risk`}
          help={t('settings.privacy.help.risk')}
        >
          <Select
            id={`${idPrefix}-risk`}
            value={form.riskLevel}
            onChange={(e) => setForm({ ...form, riskLevel: e.target.value as PrivacyRiskLevel })}
            options={riskSelectOptionsFor(t)}
          />
        </Field>
        <Field
          label={t('settings.privacy.field.status')}
          htmlFor={`${idPrefix}-status`}
          help={t('settings.privacy.help.status')}
        >
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as PrivacyRecordStatus })}
            options={statusSelectOptionsFor(t)}
          />
        </Field>
      </div>

      {kind === 'dpia' ? (
        <>
          <InlineWarning tone="info" title={t('settings.privacy.evidence.operator.title')}>
            {t('settings.privacy.evidence.operator.dpiaBody')}
          </InlineWarning>
          <div className="api-key-rate-grid">
            <Field
              label={t('settings.privacy.evidence.field.type')}
              htmlFor={`${idPrefix}-evidence-type`}
            >
              <Select
                id={`${idPrefix}-evidence-type`}
                value={form.evidenceType}
                onChange={(e) =>
                  setForm({ ...form, evidenceType: e.target.value as DpiaEvidenceKind })
                }
                options={breachEvidenceOptionsFor(t)}
              />
            </Field>
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
          </div>
        </>
      ) : null}

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
