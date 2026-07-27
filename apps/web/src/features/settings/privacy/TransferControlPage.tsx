/**
 * The record page for a controlo de transferência (t55) —
 * `/settings/privacy/transfer-controls/new` and `/settings/privacy/transfer-controls/:id`.
 *
 * Same shape as its four siblings; see {@link PrivacyRecordPageShell} for the four states and the
 * permission argument, and {@link usePrivacyRecordDraft} for the no-browser-storage decision.
 */
import { useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  useCreatePrivacyTransferControl,
  usePatchPrivacyTransferControl,
  usePrivacyTransferControls,
} from '../../../api/hooks';
import { useT } from '../../../i18n';
import { usePrivacyPagesT } from '../../../i18n/privacyPagesFallback';
import { useToast } from '../../../ui';
import { useCan } from '../../session/permissions';
import { TransferControlForm } from './forms/TransferControlForm';
import {
  EMPTY_TRANSFER_FORM,
  transferCreateBody,
  transferFormFromRecord,
} from './privacyFormState';
import { PrivacyRecordPageShell, type PrivacyRecordPageState } from './PrivacyRecordPageShell';
import { privacyListPath } from './privacyRoutes';
import { usePrivacyRecordDraft } from './usePrivacyRecordDraft';

export function TransferControlPage() {
  const t = useT();
  const pt = usePrivacyPagesT();
  const toast = useToast();
  const navigate = useNavigate();
  const { id } = useParams();
  const editing = id !== undefined;
  const listPath = privacyListPath();

  const can = useCan();
  const allowed = can('privacy.manage');

  const list = usePrivacyTransferControls(allowed);
  const create = useCreatePrivacyTransferControl();
  const patch = usePatchPrivacyTransferControl();
  const saving = create.isPending || patch.isPending;

  const record = useMemo(() => (list.data ?? []).find((row) => row.id === id), [list.data, id]);

  const seed = editing ? (record ? transferFormFromRecord(record) : null) : EMPTY_TRANSFER_FORM;
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
      const body = transferCreateBody(form);
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
          ? pt('settings.privacy.page.edit.transfer')
          : pt('settings.privacy.page.new.transfer')
      }
      listPath={listPath}
      state={state}
      error={list.error}
      notFoundMessage={pt('settings.privacy.page.notFound.transfer')}
      allowed={allowed}
    >
      {draft.form ? (
        <TransferControlForm
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
