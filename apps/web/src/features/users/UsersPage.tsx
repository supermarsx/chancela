/**
 * Utilizadores (plan t14 §2.8, t44 §5) — manage the accounts that attribute every ledger
 * mutation. Create a user (a lowercase-slug username validated client-side to match the
 * server, plus an optional display name), list all users ordered by creation, and
 * activate/deactivate them (`PATCH` — users are never deleted, so attribution history
 * stays intact). Signing in as a user happens from the picker in the shell.
 *
 * Since t41/t29, user profiles serve BOTH attribution AND access control: every mutation
 * requires a session, and each user may hold an optional sign-in secret (argon2id) and a
 * PKI audit-attestation key, managed per row by {@link UserAccessManager}. The password is
 * a local tamper speed-bump, not at-rest encryption; there is no admin reset.
 */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useCreateUser, useUpdateUser, useUsers } from '../../api/hooks';
import { ApiError } from '../../api/client';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  Input,
  PageHeader,
  SkeletonTable,
  Table,
} from '../../ui';
import { isValidUsername, usernameError } from './username';
import { UserAccessManager } from './UserAccessManager';
import type { UserView } from '../../api/types';

function UserRow({ user }: { user: UserView }) {
  const t = useT();
  const update = useUpdateUser(user.id);
  const [managing, setManaging] = useState(false);
  return (
    <>
      <tr>
        <td>
          <code className="mono">{user.username}</code>
        </td>
        <td>{user.display_name}</td>
        <td>
          {user.active ? (
            <Badge tone="ok">{t('users.status.active')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.status.inactive')}</Badge>
          )}
        </td>
        <td className="users-actions">
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Wrench />}
            aria-expanded={managing}
            onClick={() => setManaging((m) => !m)}
          >
            {t('users.access.title')}
          </Button>
          <Button
            type="button"
            variant="ghost"
            icon={user.active ? <Icon.Close /> : <Icon.Check />}
            disabled={update.isPending}
            onClick={() => update.mutate({ active: !user.active })}
          >
            {update.isPending
              ? t('common.saving')
              : user.active
                ? t('users.action.deactivate')
                : t('users.action.reactivate')}
          </Button>
        </td>
      </tr>
      {managing ? (
        <tr className="users-manage-row">
          <td colSpan={4}>
            <UserAccessManager user={user} />
          </td>
        </tr>
      ) : null}
    </>
  );
}

function CreateUserForm() {
  const t = useT();
  const create = useCreateUser();
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const fieldError = usernameError(username);

  // Surface a server duplicate (409) inline against the username field.
  const conflict =
    create.error instanceof ApiError && create.error.status === 409 ? create.error.message : null;

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!isValidUsername(username)) return;
    create.mutate(
      { username, display_name: displayName.trim() || undefined },
      {
        onSuccess: () => {
          setUsername('');
          setDisplayName('');
        },
      },
    );
  }

  return (
    <Card title={t('users.create.cardTitle')}>
      <form className="form" onSubmit={onSubmit}>
        <Field
          label={t('users.field.username.label')}
          htmlFor="user-username"
          hint={t('users.field.username.hint')}
          error={fieldError ?? conflict}
        >
          <Input
            id="user-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder={t('users.field.username.placeholder')}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
          />
        </Field>
        <Field label={t('users.field.displayName.label')} htmlFor="user-display">
          <Input
            id="user-display"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder={t('users.field.displayName.placeholder')}
            autoComplete="off"
          />
        </Field>
        {create.error && !conflict ? <ErrorNote error={create.error} /> : null}
        <div className="form__actions">
          <Button
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={create.isPending || !isValidUsername(username)}
          >
            {create.isPending ? t('users.create.submitting') : t('users.create.submit')}
          </Button>
        </div>
      </form>
    </Card>
  );
}

export function UsersPage() {
  const t = useT();
  const users = useUsers();

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            <Link to="/configuracoes">{t('users.breadcrumb.settings')}</Link> ·{' '}
            {t('users.breadcrumb.self')}
          </>
        }
        title={t('users.page.title')}
        lede={
          <>
            {t('users.page.ledeBefore')}
            <code className="mono">api</code>
            {t('users.page.ledeAfter')}
          </>
        }
      />

      <div className="settings-grid">
        <CreateUserForm />

        <Card title={t('users.list.cardTitle')}>
          {users.isLoading ? (
            <SkeletonTable cols={4} />
          ) : users.error ? (
            <ErrorNote error={users.error} />
          ) : (users.data ?? []).length === 0 ? (
            <EmptyState title={t('users.list.emptyTitle')}>
              <p>{t('users.list.emptyBody')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('users.table.username')}</th>
                  <th>{t('users.table.name')}</th>
                  <th>{t('users.table.state')}</th>
                  <th>{t('users.table.action')}</th>
                </tr>
              }
            >
              {(users.data ?? []).map((u) => (
                <UserRow key={u.id} user={u} />
              ))}
            </Table>
          )}
        </Card>
      </div>
    </div>
  );
}
