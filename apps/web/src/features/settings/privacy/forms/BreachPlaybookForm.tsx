/**
 * The create/edit form for a procedimento de resposta a violações de dados pessoais (t55).
 * Moved verbatim out of `PrivacyComplianceSection.tsx`, where it rendered inside a transient
 * `<Card>` shoved ABOVE the list — no address, no Back, and the table pushed down the page.
 *
 * Eleven fields, several of them prose a compliance officer drafts against RGPD art. 33.º/34.º.
 * That is a page's worth of work, which is exactly why the editor moved onto one.
 */
import type { FormEvent } from 'react';
import type {
  BreachEvidenceKind,
  PrivacyRecordStatus,
  PrivacyRiskLevel,
} from '../../../../api/types';
import { useT } from '../../../../i18n';
import { Field, InlineWarning, Input, Select, TextArea } from '../../../../ui';
import { splitList, type BreachPlaybookFormState } from '../privacyFormState';
import {
  breachEvidenceOptionsFor,
  riskSelectOptionsFor,
  statusSelectOptionsFor,
} from '../privacyLabels';
import { PrivacyFormActions } from './PrivacyFormActions';

export function BreachPlaybookForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  cancelTo,
  onSubmit,
}: {
  form: BreachPlaybookFormState;
  setForm: (next: BreachPlaybookFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel?: () => void;
  cancelTo?: string;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-breach-${editing ? 'edit' : 'new'}`;
  const canSubmit =
    form.title.trim().length > 0 &&
    form.scope.trim().length > 0 &&
    splitList(form.detectionChannels).length > 0 &&
    splitList(form.containmentSteps).length > 0 &&
    !saving;

  return (
    <form
      className="form settings-rows"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.breach.field.title')} htmlFor={`${idPrefix}-title`}>
        <Input
          id={`${idPrefix}-title`}
          value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field label={t('settings.privacy.breach.field.scope')} htmlFor={`${idPrefix}-scope`}>
        <Input
          id={`${idPrefix}-scope`}
          value={form.scope}
          onChange={(e) => setForm({ ...form, scope: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.detection')}
        htmlFor={`${idPrefix}-detection`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-detection`}
          value={form.detectionChannels}
          onChange={(e) => setForm({ ...form, detectionChannels: e.target.value })}
          rows={3}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.containment')}
        htmlFor={`${idPrefix}-containment`}
        hint={t('settings.privacy.listHint')}
      >
        <TextArea
          id={`${idPrefix}-containment`}
          value={form.containmentSteps}
          onChange={(e) => setForm({ ...form, containmentSteps: e.target.value })}
          rows={3}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.roles')}
        htmlFor={`${idPrefix}-roles`}
        hint={t('settings.privacy.listHintOptional')}
      >
        <TextArea
          id={`${idPrefix}-roles`}
          value={form.notificationRoles}
          onChange={(e) => setForm({ ...form, notificationRoles: e.target.value })}
          rows={2}
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.authorityWindow')}
        htmlFor={`${idPrefix}-authority-window`}
      >
        <Input
          id={`${idPrefix}-authority-window`}
          value={form.authorityNotificationWindow}
          onChange={(e) => setForm({ ...form, authorityNotificationWindow: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <Field
        label={t('settings.privacy.breach.field.subjectGuidance')}
        htmlFor={`${idPrefix}-subject-guidance`}
      >
        <TextArea
          id={`${idPrefix}-subject-guidance`}
          value={form.subjectNotificationGuidance}
          onChange={(e) => setForm({ ...form, subjectNotificationGuidance: e.target.value })}
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
        {t('settings.privacy.evidence.operator.breachBody')}
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
              setForm({ ...form, evidenceType: e.target.value as BreachEvidenceKind })
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
