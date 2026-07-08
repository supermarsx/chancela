/**
 * Utilizadores — the roster (plan t14 §2.8, t44 §5, split into its own screen by t50 W2).
 * A neat full-width list of the accounts that attribute every ledger mutation: username,
 * display name, active state, and at-a-glance access indicators (whether a sign-in password
 * and an audit-attestation key are provisioned). Creating a user now lives on its own screen
 * (`/utilizadores/novo`); editing a user — identity, activation and the access/audit manager
 * — lives on `/utilizadores/:id`.
 *
 * Row actions are icon-only {@link IconButton}s with gilt tooltips (t50 item 6): **Editar**
 * (→ the edit screen), **Ativar/Desativar** (the in-place `PATCH` — users are never deleted,
 * so attribution history stays intact), and **Acesso e auditoria** (a link into the edit
 * screen's access section). Activate/deactivate keeps its distinct success toast (t44
 * retrofit-b).
 */
import { Link, useNavigate } from 'react-router-dom';
import { useUpdateUser, useUsers } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Badge,
  ButtonLink,
  Card,
  EmptyState,
  ErrorNote,
  Icon,
  IconButton,
  PageHeader,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import type { UserView } from '../../api/types';

function UserRow({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();
  const update = useUpdateUser(user.id);

  // Activate/deactivate; distinct toast per action (the target state is `!user.active`).
  function toggleActive() {
    const nextActive = !user.active;
    update.mutate(
      { active: nextActive },
      {
        onSuccess: () =>
          toast.success(nextActive ? t('toast.user.activated') : t('toast.user.deactivated')),
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
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
      <td>
        <span className="users-actions">
          {user.has_secret ? (
            <Badge tone="ok">{t('users.secret.label')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.secret.none')}</Badge>
          )}
          {user.has_attestation_key ? <Badge tone="accent">{t('users.key.label')}</Badge> : null}
          {user.has_recovery_phrase ? (
            <Badge tone="accent">{t('users.recovery.label')}</Badge>
          ) : null}
        </span>
      </td>
      <td className="users-actions">
        <IconButton
          icon={<Icon.Pencil />}
          label={t('users.action.edit')}
          onClick={() => navigate(`/utilizadores/${user.id}`)}
        />
        <IconButton
          icon={<Icon.Power />}
          label={user.active ? t('users.action.deactivate') : t('users.action.reactivate')}
          disabled={update.isPending}
          onClick={toggleActive}
        />
        <IconButton
          icon={<Icon.Wrench />}
          label={t('users.access.title')}
          onClick={() => navigate(`/utilizadores/${user.id}#acesso`)}
        />
      </td>
    </tr>
  );
}

export function UserListPage() {
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
        actions={
          <ButtonLink to="/utilizadores/novo" variant="primary" icon={<Icon.Plus />}>
            {t('users.list.newButton')}
          </ButtonLink>
        }
      />

      <Card title={t('users.list.cardTitle')}>
        {users.isLoading ? (
          <SkeletonTable cols={5} />
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
                <th>{t('users.table.access')}</th>
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
  );
}
