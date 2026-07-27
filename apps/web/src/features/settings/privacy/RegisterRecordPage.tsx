/**
 * The record page shared by the two register-shaped surfaces (t55): the registo de atividades de
 * tratamento (`processors`) and the AIPD (`dpias`).
 *
 * One module, two exported pages. The surfaces differ by a `kind` discriminant, two mutation
 * hooks and three strings; splitting them would put two of everything in the tree for that.
 *
 * ## Create and edit are the same page
 *
 * `/settings/privacy/dpias/new` renders create, `/settings/privacy/dpias/:id` renders edit. Same
 * form, same validation, same submit placement — only the title, the seed and the mutation differ.
 * t89 already settled why there is no trailing `/edit`: "the edit screen IS the route now". These
 * records have no read-only detail view, so `/edit` would be pure ceremony.
 *
 * ## The record is resolved from the list cache
 *
 * There is no `GET`-by-id on this API. The list query is already populated when the operator
 * arrives from the table, and a cold deep link fetches it; either way the record is found in the
 * cached list or the page says so by name ({@link PrivacyRecordPageShell}, state 4). Create and
 * patch both `setQueryData` + `invalidateQueries` on that same list key, so navigating back after
 * a save finds the list already correct — no cache work here.
 */
import { useMemo } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  useCreatePrivacyDpia,
  useCreatePrivacyProcessor,
  usePatchPrivacyDpia,
  usePatchPrivacyProcessor,
  usePrivacyDpias,
  usePrivacyProcessors,
} from '../../../api/hooks';
import type {
  CreateDpiaRecordBody,
  CreateProcessorRecordBody,
  PatchDpiaRecordBody,
  PatchProcessorRecordBody,
} from '../../../api/types';
import { useT } from '../../../i18n';
import { usePrivacyPagesT } from '../../../i18n/privacyPagesFallback';
import { useToast } from '../../../ui';
import { useCan } from '../../session/permissions';
import { RegisterForm } from './forms/RegisterForm';
import {
  EMPTY_FORM,
  createBody,
  formFromRecord,
  patchBody,
  type RegisterKind,
  type RegisterRecord,
} from './privacyFormState';
import { PrivacyRecordPageShell, type PrivacyRecordPageState } from './PrivacyRecordPageShell';
import { privacyListPath } from './privacyRoutes';
import { usePrivacyRecordDraft } from './usePrivacyRecordDraft';

function RegisterRecordPage({ kind }: { kind: RegisterKind }) {
  const t = useT();
  const pt = usePrivacyPagesT();
  const toast = useToast();
  const navigate = useNavigate();
  const { id } = useParams();
  const editing = id !== undefined;
  const listPath = privacyListPath();

  const can = useCan();
  const allowed = can('privacy.manage');

  // Both lists are queried so the hook order is stable across `kind`; only the relevant one is
  // enabled, so the other never issues a request.
  const processors = usePrivacyProcessors(allowed && kind === 'processor');
  const dpias = usePrivacyDpias(allowed && kind === 'dpia');
  const list = kind === 'processor' ? processors : dpias;

  const createProcessor = useCreatePrivacyProcessor();
  const patchProcessor = usePatchPrivacyProcessor();
  const createDpia = useCreatePrivacyDpia();
  const patchDpia = usePatchPrivacyDpia();
  const saving =
    kind === 'processor'
      ? createProcessor.isPending || patchProcessor.isPending
      : createDpia.isPending || patchDpia.isPending;

  const record = useMemo(
    () => ((list.data ?? []) as RegisterRecord[]).find((row) => row.id === id),
    [list.data, id],
  );

  const seed = editing ? (record ? formFromRecord(kind, record) : null) : EMPTY_FORM;
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

  const title = editing
    ? kind === 'processor'
      ? pt('settings.privacy.page.edit.processor')
      : pt('settings.privacy.page.edit.dpia')
    : kind === 'processor'
      ? pt('settings.privacy.page.new.processor')
      : pt('settings.privacy.page.new.dpia');

  const notFoundMessage =
    kind === 'processor'
      ? pt('settings.privacy.page.notFound.processor')
      : pt('settings.privacy.page.notFound.dpia');

  async function submit() {
    const form = draft.form;
    if (!form || saving) return;
    try {
      if (editing && id !== undefined) {
        const body = patchBody(kind, form);
        if (kind === 'processor') {
          await patchProcessor.mutateAsync({ id, body: body as PatchProcessorRecordBody });
        } else {
          await patchDpia.mutateAsync({ id, body: body as PatchDpiaRecordBody });
        }
        toast.success(t('settings.privacy.toast.updated'));
      } else {
        const body = createBody(kind, form);
        if (kind === 'processor') {
          await createProcessor.mutateAsync(body as CreateProcessorRecordBody);
        } else {
          await createDpia.mutateAsync(body as CreateDpiaRecordBody);
        }
        toast.success(t('settings.privacy.toast.created'));
      }
      // Consume the guard's one-shot bypass BEFORE navigating: the happy path must not prompt.
      draft.markSaved();
      void navigate(listPath);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <PrivacyRecordPageShell
      title={title}
      listPath={listPath}
      state={state}
      error={list.error}
      notFoundMessage={notFoundMessage}
      allowed={allowed}
    >
      {draft.form ? (
        <RegisterForm
          kind={kind}
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

export function ProcessorRecordPage() {
  return <RegisterRecordPage kind="processor" />;
}

export function DpiaRecordPage() {
  return <RegisterRecordPage kind="dpia" />;
}
