/**
 * The record page for a política de retenção (t55) —
 * `/settings/privacy/retention-policies/new` and `/settings/privacy/retention-policies/:id`.
 *
 * The odd one out of the five, three times over: it is the only register on the Retenção sub-tab,
 * the only one gated on **`retention.manage`** rather than `privacy.manage` (the t27 granular
 * split — inheriting the section's gate is precisely the hole this closes), and the only one with
 * its own status enum and disposal action.
 *
 * Its return address comes from {@link privacyRetentionListPath}, which points at
 * `/settings/privacy` until t55-e5 makes the sub-tabs real path segments and upgrades that one
 * constant. Nothing here needs to change when it does.
 *
 * 🚫 The retention DRY-RUN, due-candidates, execution-review-queue and legal-hold status panels are
 * operational review surfaces, not record editors. They are out of t55's scope entirely and stay
 * exactly where they are, in `PrivacyComplianceSection.tsx`.
 */
import { useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  useCreatePrivacyRetentionPolicy,
  usePatchPrivacyRetentionPolicy,
  usePrivacyRetentionPolicies,
} from '../../../api/hooks';
import { useT } from '../../../i18n';
import { usePrivacyPagesT } from '../../../i18n/privacyPagesFallback';
import { useToast } from '../../../ui';
import { useCan } from '../../session/permissions';
import { RetentionPolicyForm } from './forms/RetentionPolicyForm';
import {
  EMPTY_RETENTION_FORM,
  retentionCreateBody,
  retentionFormFromRecord,
} from './privacyFormState';
import { PrivacyRecordPageShell, type PrivacyRecordPageState } from './PrivacyRecordPageShell';
import { privacyRetentionListPath } from './privacyRoutes';
import { usePrivacyRecordDraft } from './usePrivacyRecordDraft';

export function RetentionPolicyPage() {
  const t = useT();
  const pt = usePrivacyPagesT();
  const toast = useToast();
  const navigate = useNavigate();
  const { id } = useParams();
  const editing = id !== undefined;
  const listPath = privacyRetentionListPath();

  const can = useCan();
  const allowed = can('retention.manage');

  const list = usePrivacyRetentionPolicies(allowed);
  const create = useCreatePrivacyRetentionPolicy();
  const patch = usePatchPrivacyRetentionPolicy();
  const saving = create.isPending || patch.isPending;

  const record = useMemo(() => (list.data ?? []).find((row) => row.id === id), [list.data, id]);

  const seed = editing ? (record ? retentionFormFromRecord(record) : null) : EMPTY_RETENTION_FORM;
  const draft = usePrivacyRecordDraft(seed);

  const state: PrivacyRecordPageState = !editing
    ? 'ready'
    : list.error
      ? 'error'
      : list.isLoading
        ? 'loading'
        : record === undefined
          ? 'notFound'
          : draft.form === null
            ? 'loading'
            : 'ready';

  async function submit() {
    const form = draft.form;
    if (!form || saving) return;
    try {
      const body = retentionCreateBody(form);
      if (editing && id !== undefined) {
        await patch.mutateAsync({ id, body });
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        await create.mutateAsync(body);
        toast.success(t('settings.privacy.toast.created'));
      }
      draft.markSaved();
      void navigate(listPath);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <PrivacyRecordPageShell
      title={
        editing
          ? pt('settings.privacy.page.edit.retention')
          : pt('settings.privacy.page.new.retention')
      }
      listPath={listPath}
      state={state}
      error={list.error}
      notFoundMessage={pt('settings.privacy.page.notFound.retention')}
      allowed={allowed}
    >
      {draft.form ? (
        <RetentionPolicyForm
          form={draft.form}
          setForm={draft.setForm}
          editing={editing}
          saving={saving}
          cancelTo={listPath}
          onSubmit={submit}
        />
      ) : null}
    </PrivacyRecordPageShell>
  );
}
