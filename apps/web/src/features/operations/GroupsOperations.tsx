import { useMemo, useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  useAppendGroupTemplateLibraryRevision,
  useArchiveCompanyGroup,
  useArchiveGroupTemplateLibrary,
  useAssignEntityToGroup,
  useCompanyGroups,
  useCreateCompanyGroup,
  useCreateGroupTemplateLibrary,
  useGroupDashboard,
  useGroupTemplateLibraries,
  useGroupTemplateLibraryHistory,
  usePatchCompanyGroup,
  usePatchGroupTemplateLibrary,
  useRemoveEntityFromGroup,
  useTemplates,
} from '../../api/hooks';
import type {
  CompanyGroupView,
  Entity,
  GroupTemplateLibraryView,
  TemplateSummary,
} from '../../api/types';
import { useLocale, useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  Table,
  TextArea,
} from '../../ui';
import { GateButton, scopeEntity, scopeTemplateLibrary, scopeTenant } from '../session/permissions';

interface GroupsOperationsProps {
  tenantId: string;
  entities: Entity[];
}

function selectedValues(element: HTMLSelectElement): string[] {
  return Array.from(element.selectedOptions, (option) => option.value);
}

function TemplatePicker({
  id,
  templates,
  value,
  onChange,
}: {
  id: string;
  templates: TemplateSummary[];
  value: string[];
  onChange: (value: string[]) => void;
}) {
  const t = useT();
  return (
    <Field
      label={t('operations.groups.libraries.templates.label')}
      htmlFor={id}
      hint={t('operations.groups.libraries.templates.hint')}
    >
      <select
        id={id}
        className="control operations-multiselect"
        multiple
        size={Math.min(Math.max(templates.length, 4), 10)}
        value={value}
        onChange={(event) => onChange(selectedValues(event.currentTarget))}
      >
        {templates.map((template) => (
          <option key={template.id} value={template.id}>
            {template.id}
          </option>
        ))}
      </select>
    </Field>
  );
}

function CreateGroupForm({ tenantId }: { tenantId: string }) {
  const t = useT();
  const create = useCreateCompanyGroup();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    try {
      await create.mutateAsync({
        tenantId,
        body: { name: name.trim(), description: description.trim() || undefined },
      });
    } catch {
      // React Query retains and renders the typed API error through `create.error`; keep the
      // typed values so the operator can correct and resubmit.
      return;
    }
    setName('');
    setDescription('');
  }

  return (
    <Card title={t('operations.groups.create.title')}>
      <form className="form operations-form" onSubmit={(event) => void submit(event)}>
        <div className="operations-form-grid">
          <Field label={t('operations.groups.name')} htmlFor="operations-group-name">
            <Input
              id="operations-group-name"
              value={name}
              required
              maxLength={120}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Field label={t('operations.groups.description')} htmlFor="operations-group-description">
            <Input
              id="operations-group-description"
              value={description}
              maxLength={500}
              onChange={(event) => setDescription(event.target.value)}
            />
          </Field>
        </div>
        {create.error ? <ErrorNote error={create.error} /> : null}
        <div className="form__actions">
          <GateButton
            perm="entity.create"
            scope={scopeTenant(tenantId)}
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={create.isPending || !name.trim()}
          >
            {create.isPending ? t('common.saving') : t('operations.groups.create.action')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

function GroupDashboard({ tenantId, groupId }: { tenantId: string; groupId: string }) {
  const t = useT();
  const dashboard = useGroupDashboard(tenantId, groupId);
  if (dashboard.isLoading) return <p className="muted">{t('common.loading')}</p>;
  if (dashboard.error) return <ErrorNote error={dashboard.error} />;
  if (!dashboard.data) return null;

  return (
    <div className="stack--tight">
      <dl className="operations-metrics" aria-label={t('operations.groups.dashboard.aria')}>
        <div>
          <dt>{t('operations.groups.dashboard.members')}</dt>
          <dd>{dashboard.data.member_entities.length}</dd>
        </div>
        <div>
          <dt>{t('operations.groups.dashboard.books')}</dt>
          <dd>{dashboard.data.books_total}</dd>
        </div>
        <div>
          <dt>{t('operations.groups.dashboard.acts')}</dt>
          <dd>{dashboard.data.acts_total}</dd>
        </div>
        <div>
          <dt>{t('operations.groups.dashboard.overdue')}</dt>
          <dd>{dashboard.data.reminders_overdue}</dd>
        </div>
      </dl>
      {dashboard.data.reminders.length > 0 ? (
        <ul className="operations-compact-list">
          {dashboard.data.reminders.map((reminder) => (
            <li key={reminder.id}>
              <span>{reminder.title}</span>
              {reminder.overdue ? (
                <Badge tone="warn">{t('operations.groups.dashboard.reminder.overdue')}</Badge>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

function GroupMembers({
  tenantId,
  groupId,
  entities,
}: {
  tenantId: string;
  groupId: string;
  entities: Entity[];
}) {
  const t = useT();
  const dashboard = useGroupDashboard(tenantId, groupId);
  const assign = useAssignEntityToGroup();
  const remove = useRemoveEntityFromGroup();
  const available = entities.filter((entity) => entity.group_id === null);
  const [entityId, setEntityId] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!entityId) return;
    try {
      await assign.mutateAsync({ tenantId, groupId, entityId });
    } catch {
      // Rendered through `assign.error`; keep the chosen entity so it can be retried.
      return;
    }
    setEntityId('');
  }

  return (
    <Card title={t('operations.groups.members.title')}>
      <form className="operations-inline-form" onSubmit={(event) => void submit(event)}>
        <Field label={t('operations.groups.members.entity')} htmlFor="operations-group-member">
          <select
            id="operations-group-member"
            className="control control--select"
            value={entityId}
            onChange={(event) => setEntityId(event.target.value)}
          >
            <option value="">{t('operations.groups.members.choose')}</option>
            {available.map((entity) => (
              <option key={entity.id} value={entity.id}>
                {entity.name} · {entity.nipc}
              </option>
            ))}
          </select>
        </Field>
        <GateButton
          perm="entity.update"
          scope={scopeTenant(tenantId)}
          type="submit"
          variant="primary"
          disabled={!entityId || assign.isPending}
        >
          {t('operations.groups.members.assign')}
        </GateButton>
      </form>
      {assign.error ? <ErrorNote error={assign.error} /> : null}
      {remove.error ? <ErrorNote error={remove.error} /> : null}
      {dashboard.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
      {dashboard.error ? <ErrorNote error={dashboard.error} /> : null}
      {dashboard.data?.member_entities.length === 0 ? (
        <EmptyState title={t('operations.groups.members.empty')} />
      ) : null}
      {dashboard.data && dashboard.data.member_entities.length > 0 ? (
        <Table
          head={
            <tr>
              <th>{t('operations.groups.members.entity')}</th>
              <th>{t('operations.groups.members.nipc')}</th>
              <th>{t('operations.common.actions')}</th>
            </tr>
          }
        >
          {dashboard.data.member_entities.map((entity) => (
            <tr key={entity.id}>
              <td>{entity.name}</td>
              <td>{entity.nipc}</td>
              <td>
                <GateButton
                  perm="entity.update"
                  scope={scopeEntity(entity.id)}
                  type="button"
                  variant="ghost"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate({ tenantId, groupId, entityId: entity.id })}
                >
                  {t('operations.groups.members.remove')}
                </GateButton>
              </td>
            </tr>
          ))}
        </Table>
      ) : null}
    </Card>
  );
}

function LibraryDetail({
  tenantId,
  groupId,
  library,
  templates,
}: {
  tenantId: string;
  groupId: string;
  library: GroupTemplateLibraryView;
  templates: TemplateSummary[];
}) {
  const t = useT();
  const locale = useLocale();
  const patch = usePatchGroupTemplateLibrary();
  const archive = useArchiveGroupTemplateLibrary();
  const append = useAppendGroupTemplateLibraryRevision();
  const history = useGroupTemplateLibraryHistory(tenantId, groupId, library.id);
  const [name, setName] = useState(library.name);
  const [description, setDescription] = useState(library.description ?? '');
  const [templateIds, setTemplateIds] = useState(library.current_revision?.template_ids ?? []);

  return (
    <div className="stack">
      <form
        className="form operations-form"
        onSubmit={(event) => {
          event.preventDefault();
          patch.mutate({
            tenantId,
            groupId,
            libraryId: library.id,
            body: { name: name.trim(), description: description.trim() || null },
          });
        }}
      >
        <div className="operations-form-grid">
          <Field
            label={t('operations.groups.libraries.name')}
            htmlFor="operations-library-edit-name"
          >
            <Input
              id="operations-library-edit-name"
              value={name}
              required
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Field
            label={t('operations.groups.libraries.description')}
            htmlFor="operations-library-edit-description"
          >
            <Input
              id="operations-library-edit-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </Field>
        </div>
        <div className="form__actions">
          <GateButton
            perm="template.manage"
            scope={scopeTemplateLibrary(library.id)}
            type="submit"
            variant="primary"
            disabled={patch.isPending || !name.trim()}
          >
            {t('common.save')}
          </GateButton>
          <GateButton
            perm="template.manage"
            scope={scopeTemplateLibrary(library.id)}
            type="button"
            variant="ghost"
            icon={<Icon.Archive />}
            disabled={archive.isPending}
            onClick={() => archive.mutate({ tenantId, groupId, libraryId: library.id })}
          >
            {t('operations.groups.libraries.archive')}
          </GateButton>
        </div>
      </form>
      {patch.error ? <ErrorNote error={patch.error} /> : null}
      {archive.error ? <ErrorNote error={archive.error} /> : null}

      <form
        className="form operations-form"
        onSubmit={(event) => {
          event.preventDefault();
          if (templateIds.length === 0) return;
          append.mutate({
            tenantId,
            groupId,
            libraryId: library.id,
            body: { template_ids: templateIds },
          });
        }}
      >
        <h4>{t('operations.groups.libraries.revision.title')}</h4>
        <TemplatePicker
          id="operations-library-revision-templates"
          templates={templates}
          value={templateIds}
          onChange={setTemplateIds}
        />
        {append.error ? <ErrorNote error={append.error} /> : null}
        <div className="form__actions">
          <GateButton
            perm="template.manage"
            scope={scopeTemplateLibrary(library.id)}
            type="submit"
            variant="primary"
            disabled={append.isPending || templateIds.length === 0}
          >
            {t('operations.groups.libraries.revision.append')}
          </GateButton>
        </div>
      </form>

      <section aria-labelledby="operations-library-history-title">
        <h4 id="operations-library-history-title">
          {t('operations.groups.libraries.history.title')}
        </h4>
        {history.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
        {history.error ? <ErrorNote error={history.error} /> : null}
        {history.data?.length === 0 ? (
          <EmptyState title={t('operations.groups.libraries.history.empty')} />
        ) : null}
        {history.data && history.data.length > 0 ? (
          <Table
            head={
              <tr>
                <th>{t('operations.groups.libraries.history.revision')}</th>
                <th>{t('operations.groups.libraries.history.templates')}</th>
                <th>{t('operations.groups.libraries.history.actor')}</th>
                <th>{t('operations.groups.libraries.history.created')}</th>
              </tr>
            }
          >
            {history.data.map((revision) => (
              <tr key={revision.revision}>
                <td>{revision.revision}</td>
                <td>{revision.template_ids.join(', ')}</td>
                <td>{revision.created_by}</td>
                <td>{new Date(revision.created_at).toLocaleString(locale)}</td>
              </tr>
            ))}
          </Table>
        ) : null}
      </section>
    </div>
  );
}

function GroupLibraries({ tenantId, groupId }: { tenantId: string; groupId: string }) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const libraries = useGroupTemplateLibraries(tenantId, groupId);
  const templates = useTemplates();
  const create = useCreateGroupTemplateLibrary();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [templateIds, setTemplateIds] = useState<string[]>([]);
  const requested = params.get('library') ?? '';
  const selected = libraries.data?.find((library) => library.id === requested) ?? null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (templateIds.length === 0) return;
    let created: GroupTemplateLibraryView;
    try {
      created = await create.mutateAsync({
        tenantId,
        groupId,
        body: {
          name: name.trim(),
          description: description.trim() || undefined,
          template_ids: templateIds,
        },
      });
    } catch {
      // Rendered through `create.error`; the draft library stays on screen for a retry.
      return;
    }
    setName('');
    setDescription('');
    setTemplateIds([]);
    setParams((current) => {
      const next = new URLSearchParams(current);
      next.set('library', created.id);
      return next;
    });
  }

  return (
    <Card title={t('operations.groups.libraries.title')}>
      <InlineWarning tone="info">{t('operations.groups.libraries.caveat')}</InlineWarning>
      <form className="form operations-form" onSubmit={(event) => void submit(event)}>
        <div className="operations-form-grid">
          <Field label={t('operations.groups.libraries.name')} htmlFor="operations-library-name">
            <Input
              id="operations-library-name"
              value={name}
              required
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <Field
            label={t('operations.groups.libraries.description')}
            htmlFor="operations-library-description"
          >
            <Input
              id="operations-library-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
            />
          </Field>
        </div>
        <TemplatePicker
          id="operations-library-templates"
          templates={templates.data ?? []}
          value={templateIds}
          onChange={setTemplateIds}
        />
        {templates.error ? <ErrorNote error={templates.error} /> : null}
        {create.error ? <ErrorNote error={create.error} /> : null}
        <div className="form__actions">
          <GateButton
            perm="template.manage"
            scope={scopeTenant(tenantId)}
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={create.isPending || !name.trim() || templateIds.length === 0}
          >
            {t('operations.groups.libraries.create')}
          </GateButton>
        </div>
      </form>

      {libraries.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
      {libraries.error ? <ErrorNote error={libraries.error} /> : null}
      {libraries.data?.length === 0 ? (
        <EmptyState title={t('operations.groups.libraries.empty')} />
      ) : null}
      {libraries.data && libraries.data.length > 0 ? (
        <div
          className="operations-selector-list"
          aria-label={t('operations.groups.libraries.list')}
        >
          {libraries.data.map((library) => (
            <Button
              key={library.id}
              type="button"
              variant={selected?.id === library.id ? 'primary' : 'secondary'}
              onClick={() =>
                setParams((current) => {
                  const next = new URLSearchParams(current);
                  next.set('library', library.id);
                  return next;
                })
              }
            >
              {t('operations.groups.libraries.selector', {
                name: library.name,
                revision: library.current_revision?.revision ?? 0,
              })}
            </Button>
          ))}
        </div>
      ) : null}
      {selected ? (
        <LibraryDetail
          key={selected.id}
          tenantId={tenantId}
          groupId={groupId}
          library={selected}
          templates={templates.data ?? []}
        />
      ) : null}
    </Card>
  );
}

function GroupDetail({
  tenantId,
  group,
  entities,
}: {
  tenantId: string;
  group: CompanyGroupView;
  entities: Entity[];
}) {
  const t = useT();
  const patch = usePatchCompanyGroup();
  const archive = useArchiveCompanyGroup();
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description ?? '');

  return (
    <div className="stack">
      <Card title={t('operations.groups.detail.title')}>
        <form
          className="form operations-form"
          onSubmit={(event) => {
            event.preventDefault();
            patch.mutate({
              tenantId,
              groupId: group.id,
              body: { name: name.trim(), description: description.trim() || null },
            });
          }}
        >
          <div className="operations-form-grid">
            <Field label={t('operations.groups.name')} htmlFor="operations-group-edit-name">
              <Input
                id="operations-group-edit-name"
                value={name}
                required
                onChange={(event) => setName(event.target.value)}
              />
            </Field>
            <Field
              label={t('operations.groups.description')}
              htmlFor="operations-group-edit-description"
            >
              <TextArea
                id="operations-group-edit-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </Field>
          </div>
          <GroupDashboard tenantId={tenantId} groupId={group.id} />
          {patch.error ? <ErrorNote error={patch.error} /> : null}
          {archive.error ? <ErrorNote error={archive.error} /> : null}
          <div className="form__actions">
            <GateButton
              perm="entity.update"
              scope={scopeTenant(tenantId)}
              type="submit"
              variant="primary"
              disabled={patch.isPending || !name.trim()}
            >
              {t('common.save')}
            </GateButton>
            <GateButton
              perm="entity.update"
              scope={scopeTenant(tenantId)}
              type="button"
              variant="ghost"
              icon={<Icon.Archive />}
              disabled={archive.isPending || group.member_count > 0}
              onClick={() => archive.mutate({ tenantId, groupId: group.id })}
            >
              {t('operations.groups.archive')}
            </GateButton>
          </div>
          {group.member_count > 0 ? (
            <p className="field__hint">{t('operations.groups.archive.membersBlock')}</p>
          ) : null}
        </form>
      </Card>
      <GroupMembers tenantId={tenantId} groupId={group.id} entities={entities} />
      <GroupLibraries tenantId={tenantId} groupId={group.id} />
    </div>
  );
}

export function GroupsOperations({ tenantId, entities }: GroupsOperationsProps) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const groups = useCompanyGroups(tenantId);
  const requested = params.get('group') ?? '';
  const selected = useMemo(
    () => groups.data?.find((group) => group.id === requested) ?? null,
    [groups.data, requested],
  );

  return (
    <div className="stack">
      <InlineWarning tone="info" title={t('operations.groups.scope.title')}>
        {t('operations.groups.scope.body')}
      </InlineWarning>
      <CreateGroupForm tenantId={tenantId} />
      <Card title={t('operations.groups.list.title')}>
        {groups.isLoading ? <p className="muted">{t('common.loading')}</p> : null}
        {groups.error ? <ErrorNote error={groups.error} /> : null}
        {groups.data?.length === 0 ? <EmptyState title={t('operations.groups.empty')} /> : null}
        {groups.data && groups.data.length > 0 ? (
          <Table
            head={
              <tr>
                <th>{t('operations.groups.name')}</th>
                <th>{t('operations.groups.dashboard.members')}</th>
                <th>{t('operations.groups.libraries.title')}</th>
                <th>{t('operations.common.actions')}</th>
              </tr>
            }
          >
            {groups.data.map((group) => (
              <tr key={group.id}>
                <td>
                  <strong>{group.name}</strong>
                  {group.description ? <span className="muted"> · {group.description}</span> : null}
                </td>
                <td>{group.member_count}</td>
                <td>{group.template_library_count}</td>
                <td>
                  <Button
                    type="button"
                    variant={selected?.id === group.id ? 'primary' : 'secondary'}
                    onClick={() =>
                      setParams((current) => {
                        const next = new URLSearchParams(current);
                        next.set('group', group.id);
                        next.delete('library');
                        return next;
                      })
                    }
                  >
                    {t('operations.common.open')}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        ) : null}
      </Card>
      {selected ? (
        <GroupDetail key={selected.id} tenantId={tenantId} group={selected} entities={entities} />
      ) : null}
    </div>
  );
}
