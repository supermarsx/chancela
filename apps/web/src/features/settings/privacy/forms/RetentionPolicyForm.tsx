/**
 * The create/edit form for a política de retenção (t55). Moved verbatim out of
 * `PrivacyComplianceSection.tsx`.
 *
 * This is the one register on the Retenção sub-tab, the one gated on `retention.manage` rather
 * than `privacy.manage`, and the one with its own status enum and disposal action — which is why
 * its page is a separate module from the other four.
 */
import type { FormEvent } from 'react';
import {
  RETENTION_DISPOSAL_ACTIONS,
  RETENTION_POLICY_STATUSES,
  type RetentionDisposalAction,
  type RetentionPolicyStatus,
} from '../../../../api/types';
import { useT } from '../../../../i18n';
import { Field, InlineWarning, Input, Select, TextArea } from '../../../../ui';
import type { RetentionPolicyFormState } from '../privacyFormState';
import { retentionDisposalLabel, retentionStatusLabel } from '../privacyLabels';
import { PrivacyFormActions } from './PrivacyFormActions';

export function RetentionPolicyForm({
  form,
  setForm,
  editing,
  saving,
  onCancel,
  cancelTo,
  onSubmit,
}: {
  form: RetentionPolicyFormState;
  setForm: (next: RetentionPolicyFormState) => void;
  editing: boolean;
  saving: boolean;
  onCancel?: () => void;
  cancelTo?: string;
  onSubmit: () => void;
}) {
  const t = useT();
  const idPrefix = `privacy-retention-${editing ? 'edit' : 'new'}`;
  const retentionStatusOptions = RETENTION_POLICY_STATUSES.map((status) => ({
    value: status,
    label: retentionStatusLabel(t, status),
  }));
  const retentionDisposalOptions = RETENTION_DISPOSAL_ACTIONS.map((action) => ({
    value: action,
    label: retentionDisposalLabel(t, action),
  }));
  const canSubmit =
    form.name.trim().length > 0 &&
    form.scope.trim().length > 0 &&
    form.category.trim().length > 0 &&
    form.scheduleId.trim().length > 0 &&
    form.retentionPeriod.trim().length > 0 &&
    form.legalBasis.trim().length > 0 &&
    !saving;

  return (
    <form
      className="form settings-rows"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (canSubmit) onSubmit();
      }}
    >
      <Field label={t('settings.privacy.retention.field.name')} htmlFor={`${idPrefix}-name`}>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field label={t('settings.privacy.retention.field.scope')} htmlFor={`${idPrefix}-scope`}>
          <Input
            id={`${idPrefix}-scope`}
            value={form.scope}
            onChange={(e) => setForm({ ...form, scope: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.retention.field.category')}
          htmlFor={`${idPrefix}-category`}
        >
          <Input
            id={`${idPrefix}-category`}
            value={form.category}
            onChange={(e) => setForm({ ...form, category: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.retention.field.scheduleId')}
          htmlFor={`${idPrefix}-schedule`}
        >
          <Input
            id={`${idPrefix}-schedule`}
            value={form.scheduleId}
            onChange={(e) => setForm({ ...form, scheduleId: e.target.value })}
            autoComplete="off"
          />
        </Field>
        <Field
          label={t('settings.privacy.retention.field.retentionPeriod')}
          htmlFor={`${idPrefix}-period`}
        >
          <Input
            id={`${idPrefix}-period`}
            value={form.retentionPeriod}
            onChange={(e) => setForm({ ...form, retentionPeriod: e.target.value })}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field label={t('settings.privacy.retention.field.legalBasis')} htmlFor={`${idPrefix}-legal`}>
        <Input
          id={`${idPrefix}-legal`}
          value={form.legalBasis}
          onChange={(e) => setForm({ ...form, legalBasis: e.target.value })}
          autoComplete="off"
        />
      </Field>
      <div className="api-key-rate-grid">
        <Field
          label={t('settings.privacy.retention.field.disposalAction')}
          htmlFor={`${idPrefix}-action`}
        >
          <Select
            id={`${idPrefix}-action`}
            value={form.disposalAction}
            onChange={(e) =>
              setForm({ ...form, disposalAction: e.target.value as RetentionDisposalAction })
            }
            options={retentionDisposalOptions}
          />
        </Field>
        <Field label={t('settings.privacy.field.status')} htmlFor={`${idPrefix}-status`}>
          <Select
            id={`${idPrefix}-status`}
            value={form.status}
            onChange={(e) => setForm({ ...form, status: e.target.value as RetentionPolicyStatus })}
            options={retentionStatusOptions}
          />
        </Field>
      </div>
      <label className="checkbox-row">
        <input
          type="checkbox"
          checked={form.active}
          onChange={(e) => setForm({ ...form, active: e.target.checked })}
        />
        {t('settings.privacy.retention.field.active')}
      </label>
      <Field label={t('settings.privacy.retention.field.notes')} htmlFor={`${idPrefix}-notes`}>
        <TextArea
          id={`${idPrefix}-notes`}
          value={form.notes}
          onChange={(e) => setForm({ ...form, notes: e.target.value })}
          rows={3}
        />
      </Field>
      <InlineWarning tone="info" title={t('settings.privacy.retention.notice.title')}>
        {t('settings.privacy.retention.notice.body')}
      </InlineWarning>
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
