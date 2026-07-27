/**
 * The record page for a procedimento de resposta a violações de dados pessoais (t55) —
 * `/settings/privacy/breach-playbooks/new` and `/settings/privacy/breach-playbooks/:id`.
 *
 * Before t55 this editor was an inline `<Card>` rendered ABOVE the list: no address, no Back, and
 * the table shoved down the page every time it opened. Same shape as the other four pages now —
 * see {@link PrivacyRecordPageShell} for the four states and the permission argument, and
 * {@link usePrivacyRecordDraft} for why nothing is written to browser storage.
 */
import { useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  useCreatePrivacyBreachPlaybook,
  usePatchPrivacyBreachPlaybook,
  usePrivacyBreachPlaybooks,
} from '../../../api/hooks';
import { useT } from '../../../i18n';
import { usePrivacyPagesT } from '../../../i18n/privacyPagesFallback';
import { useToast } from '../../../ui';
import { useCan } from '../../session/permissions';
import { BreachPlaybookForm } from './forms/BreachPlaybookForm';
import { EMPTY_BREACH_FORM, breachCreateBody, breachFormFromRecord } from './privacyFormState';
import { PrivacyRecordPageShell, type PrivacyRecordPageState } from './PrivacyRecordPageShell';
import { privacyListPath } from './privacyRoutes';
import { usePrivacyRecordDraft } from './usePrivacyRecordDraft';

export function BreachPlaybookPage() {
  const t = useT();
  const pt = usePrivacyPagesT();
  const toast = useToast();
  const navigate = useNavigate();
  const { id } = useParams();
  const editing = id !== undefined;
  const listPath = privacyListPath();

  const can = useCan();
  const allowed = can('privacy.manage');

  const list = usePrivacyBreachPlaybooks(allowed);
  const create = useCreatePrivacyBreachPlaybook();
  const patch = usePatchPrivacyBreachPlaybook();
  const saving = create.isPending || patch.isPending;

  const record = useMemo(() => (list.data ?? []).find((row) => row.id === id), [list.data, id]);

  const seed = editing ? (record ? breachFormFromRecord(record) : null) : EMPTY_BREACH_FORM;
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
      const body = breachCreateBody(form);
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
        editing ? pt('settings.privacy.page.edit.breach') : pt('settings.privacy.page.new.breach')
      }
      listPath={listPath}
      state={state}
      error={list.error}
      notFoundMessage={pt('settings.privacy.page.notFound.breach')}
      allowed={allowed}
    >
      {draft.form ? (
        <BreachPlaybookForm
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
