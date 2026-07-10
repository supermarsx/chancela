import { useEffect, useMemo, useState, type FormEvent } from 'react';
import {
  useActFollowUps,
  useCompleteFollowUp,
  useCreateActFollowUp,
  usePatchFollowUp,
} from '../../api/hooks';
import type {
  ActView,
  CreateFollowUpBody,
  FollowUpView,
  PatchFollowUpBody,
} from '../../api/types';
import { useT } from '../../i18n';
import {
  Badge,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Select,
  SkeletonText,
  TextArea,
  useToast,
} from '../../ui';
import { GateButton, scopeBook } from '../session/permissions';

type AnchorValue = '' | `agenda:${number}` | `deliberation:${number}`;

interface FollowUpDraft {
  title: string;
  detail: string;
  due_date: string;
  assignee: string;
}

const blankDraft: FollowUpDraft = {
  title: '',
  detail: '',
  due_date: '',
  assignee: '',
};

const orNull = (value: string): string | null => {
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed;
};

function draftFromFollowUp(row: FollowUpView): FollowUpDraft {
  return {
    title: row.title,
    detail: row.detail ?? '',
    due_date: row.due_date ?? '',
    assignee: row.assignee_display ?? row.assignee ?? '',
  };
}

function anchorFields(anchor: AnchorValue): Pick<CreateFollowUpBody, 'agenda_number' | 'deliberation_index'> {
  if (anchor.startsWith('agenda:')) {
    return { agenda_number: Number(anchor.slice('agenda:'.length)) };
  }
  if (anchor.startsWith('deliberation:')) {
    return { deliberation_index: Number(anchor.slice('deliberation:'.length)) };
  }
  return {};
}

function previewText(text: string, max = 70): string {
  const clean = text.replace(/\s+/g, ' ').trim();
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max - 1)}…`;
}

function useAnchorOptions(act: ActView) {
  const t = useT();
  return useMemo(
    () => [
      { value: '', label: t('acts.followUps.anchor.none') },
      ...act.agenda.map((item) => ({
        value: `agenda:${item.number}`,
        label: t('acts.followUps.anchor.agenda', { n: item.number, text: previewText(item.text) }),
      })),
      ...act.deliberation_items.map((item, index) => ({
        value: `deliberation:${index}`,
        label: t('acts.followUps.anchor.deliberation', {
          n: index + 1,
          text: previewText(item.text),
        }),
      })),
    ],
    [act.agenda, act.deliberation_items, t],
  );
}

function followUpAnchors(row: FollowUpView, t: ReturnType<typeof useT>): string {
  const labels: string[] = [];
  if (row.agenda_number != null) {
    labels.push(t('acts.followUps.anchor.agendaShort', { n: row.agenda_number }));
  }
  if (row.deliberation_index != null) {
    labels.push(t('acts.followUps.anchor.deliberationShort', { n: row.deliberation_index + 1 }));
  }
  return labels.length === 0 ? t('acts.followUps.anchor.none') : labels.join(' · ');
}

function followUpPatch(draft: FollowUpDraft): PatchFollowUpBody {
  const assignee = orNull(draft.assignee);
  return {
    title: draft.title,
    detail: orNull(draft.detail),
    due_date: orNull(draft.due_date),
    assignee,
    assignee_display: assignee,
  };
}

function FollowUpItem({
  row,
  act,
  onSave,
  onComplete,
  savePending,
  completePending,
}: {
  row: FollowUpView;
  act: ActView;
  onSave: (id: string, body: PatchFollowUpBody) => void;
  onComplete: (id: string) => void;
  savePending: boolean;
  completePending: boolean;
}) {
  const t = useT();
  const [draft, setDraft] = useState(() => draftFromFollowUp(row));
  const [titleError, setTitleError] = useState<string | null>(null);
  const completed = row.status === 'Completed';
  const scope = scopeBook(act.book_id);

  useEffect(() => {
    setDraft({
      title: row.title,
      detail: row.detail ?? '',
      due_date: row.due_date ?? '',
      assignee: row.assignee_display ?? row.assignee ?? '',
    });
    setTitleError(null);
  }, [
    row.id,
    row.title,
    row.detail,
    row.due_date,
    row.assignee,
    row.assignee_display,
    row.status,
  ]);

  function set<K extends keyof FollowUpDraft>(key: K, value: FollowUpDraft[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function save() {
    if (!draft.title.trim()) {
      setTitleError(t('acts.followUps.validation.title'));
      return;
    }
    setTitleError(null);
    onSave(row.id, followUpPatch(draft));
  }

  return (
    <article className="delib-item" aria-label={row.title}>
      <div className="delib-item__head">
        <span className="card__label">{followUpAnchors(row, t)}</span>
        <Badge tone={completed ? 'ok' : 'warn'}>
          {completed ? t('acts.followUps.completed') : t('acts.followUps.open')}
        </Badge>
      </div>

      <div className="form">
        <Field
          label={t('acts.followUps.titleLabel')}
          htmlFor={`follow-up-${row.id}-title`}
          error={titleError}
        >
          <Input
            id={`follow-up-${row.id}-title`}
            value={draft.title}
            disabled={completed}
            onChange={(event) => set('title', event.target.value)}
          />
        </Field>
        <Field label={t('acts.followUps.detailLabel')} htmlFor={`follow-up-${row.id}-detail`}>
          <TextArea
            id={`follow-up-${row.id}-detail`}
            rows={3}
            value={draft.detail}
            disabled={completed}
            placeholder={t('acts.followUps.noDetail')}
            onChange={(event) => set('detail', event.target.value)}
          />
        </Field>
        <div className="rowline">
          <Field label={t('acts.followUps.dueDate')} htmlFor={`follow-up-${row.id}-due`}>
            <Input
              id={`follow-up-${row.id}-due`}
              type="date"
              value={draft.due_date}
              disabled={completed}
              onChange={(event) => set('due_date', event.target.value)}
            />
          </Field>
          <Field label={t('acts.followUps.assignee')} htmlFor={`follow-up-${row.id}-assignee`}>
            <Input
              id={`follow-up-${row.id}-assignee`}
              value={draft.assignee}
              disabled={completed}
              placeholder={t('acts.followUps.assigneePlaceholder')}
              onChange={(event) => set('assignee', event.target.value)}
            />
          </Field>
        </div>
        <p className="field__hint">
          {t('acts.followUps.createdBy', { actor: row.created_by })}
          {row.completed_by
            ? ` · ${t('acts.followUps.completedBy', { actor: row.completed_by })}`
            : ''}
        </p>

        {!completed ? (
          <div className="rowline">
            <GateButton
              perm="act.edit"
              scope={scope}
              type="button"
              variant="secondary"
              icon={<Icon.Save />}
              disabled={savePending}
              onClick={save}
            >
              {savePending ? t('acts.followUps.saving') : t('acts.followUps.save')}
            </GateButton>
            <GateButton
              perm="act.edit"
              scope={scope}
              type="button"
              variant="primary"
              icon={<Icon.Check />}
              disabled={completePending}
              onClick={() => onComplete(row.id)}
            >
              {completePending ? t('acts.followUps.completing') : t('acts.followUps.complete')}
            </GateButton>
          </div>
        ) : null}
      </div>
    </article>
  );
}

export function FollowUpsPanel({ act }: { act: ActView }) {
  const t = useT();
  const toast = useToast();
  const followUps = useActFollowUps(act.id);
  const create = useCreateActFollowUp(act.id);
  const patch = usePatchFollowUp(act.id);
  const complete = useCompleteFollowUp(act.id);
  const [draft, setDraft] = useState<FollowUpDraft>(blankDraft);
  const [anchor, setAnchor] = useState<AnchorValue>('');
  const [titleError, setTitleError] = useState<string | null>(null);
  const anchorOptions = useAnchorOptions(act);
  const sealed = act.state === 'Sealed' || act.state === 'Archived';
  const scope = scopeBook(act.book_id);

  function set<K extends keyof FollowUpDraft>(key: K, value: FollowUpDraft[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
  }

  function onCreate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft.title.trim()) {
      setTitleError(t('acts.followUps.validation.title'));
      return;
    }
    setTitleError(null);
    const assignee = orNull(draft.assignee);
    create.mutate(
      {
        ...anchorFields(anchor),
        title: draft.title,
        detail: orNull(draft.detail),
        due_date: orNull(draft.due_date),
        assignee,
        assignee_display: assignee,
      },
      {
        onSuccess: () => {
          setDraft(blankDraft);
          setAnchor('');
          toast.success(t('toast.followUp.created'));
        },
        onError: (error) => toast.error(error),
      },
    );
  }

  function onSave(id: string, body: PatchFollowUpBody) {
    patch.mutate(
      { id, body },
      {
        onSuccess: () => toast.success(t('toast.followUp.saved')),
        onError: (error) => toast.error(error),
      },
    );
  }

  function onComplete(id: string) {
    complete.mutate(
      { id },
      {
        onSuccess: () => toast.success(t('toast.followUp.completed')),
        onError: (error) => toast.error(error),
      },
    );
  }

  return (
    <Card title={t('acts.followUps.title')}>
      <div className="stack--tight">
        <p className="field__hint">{t('acts.followUps.hint')}</p>
        {sealed ? (
          <InlineWarning tone="info" title={t('acts.followUps.sealedTitle')}>
            {t('acts.followUps.sealedBody')}
          </InlineWarning>
        ) : null}

        <form className="form" onSubmit={onCreate}>
          <Field label={t('acts.followUps.anchor')} htmlFor="follow-up-anchor">
            <Select
              id="follow-up-anchor"
              value={anchor}
              options={anchorOptions}
              onChange={(event) => setAnchor(event.target.value as AnchorValue)}
            />
          </Field>
          <Field
            label={t('acts.followUps.titleLabel')}
            htmlFor="follow-up-title"
            error={titleError}
          >
            <Input
              id="follow-up-title"
              value={draft.title}
              placeholder={t('acts.followUps.titlePlaceholder')}
              onChange={(event) => set('title', event.target.value)}
            />
          </Field>
          <Field label={t('acts.followUps.detailLabel')} htmlFor="follow-up-detail">
            <TextArea
              id="follow-up-detail"
              rows={3}
              value={draft.detail}
              placeholder={t('acts.followUps.detailPlaceholder')}
              onChange={(event) => set('detail', event.target.value)}
            />
          </Field>
          <div className="rowline">
            <Field label={t('acts.followUps.dueDate')} htmlFor="follow-up-due">
              <Input
                id="follow-up-due"
                type="date"
                value={draft.due_date}
                onChange={(event) => set('due_date', event.target.value)}
              />
            </Field>
            <Field label={t('acts.followUps.assignee')} htmlFor="follow-up-assignee">
              <Input
                id="follow-up-assignee"
                value={draft.assignee}
                placeholder={t('acts.followUps.assigneePlaceholder')}
                onChange={(event) => set('assignee', event.target.value)}
              />
            </Field>
          </div>
          {create.error ? <ErrorNote error={create.error} /> : null}
          <GateButton
            perm="act.edit"
            scope={scope}
            type="submit"
            variant="secondary"
            icon={<Icon.Plus />}
            disabled={create.isPending}
          >
            {create.isPending ? t('acts.followUps.creating') : t('acts.followUps.create')}
          </GateButton>
        </form>

        {followUps.isLoading ? (
          <SkeletonText lines={3} />
        ) : followUps.error ? (
          <ErrorNote error={followUps.error} />
        ) : followUps.data && followUps.data.length > 0 ? (
          <div className="stack--tight">
            {patch.error ? <ErrorNote error={patch.error} /> : null}
            {complete.error ? <ErrorNote error={complete.error} /> : null}
            {followUps.data.map((row) => (
              <FollowUpItem
                key={row.id}
                row={row}
                act={act}
                savePending={patch.isPending && patch.variables?.id === row.id}
                completePending={complete.isPending && complete.variables?.id === row.id}
                onSave={onSave}
                onComplete={onComplete}
              />
            ))}
          </div>
        ) : (
          <EmptyState title={t('acts.followUps.empty')} />
        )}
      </div>
    </Card>
  );
}
