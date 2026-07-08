/**
 * Edit one user, on its own autonomous route (`/utilizadores/:id`, plan t50 W2). Absorbs
 * what used to be a per-row inline expander on the Utilizadores list into a full screen with
 * three sections:
 *
 *  1. **Identidade** — the immutable audit username (read-only `code`) and the editable
 *     display name (`PATCH /v1/users/{id}`).
 *  2. **Activation** — the active/inactive state with an icon-only toggle (the same `PATCH`;
 *     users are never deleted, so attribution history stays intact).
 *  3. **Acesso e auditoria** — the existing {@link UserAccessManager} (sign-in password +
 *     PKI audit-attestation key), moved here wholesale and unchanged.
 *
 * The user is resolved from the `useUsers()` list cache for an instant paint; a cold deep
 * link (empty cache) falls back to `GET /v1/users/{id}` via {@link useUser}.
 */
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useUpdateUser, useUser, useUsers } from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  PageHeader,
  Skeleton,
  SkeletonDeflist,
  useToast,
} from '../../ui';
import { UserAccessManager } from './UserAccessManager';
import { RoleAssignmentManager } from '../rbac/RoleAssignmentManager';
import type { UserView } from '../../api/types';

function IdentitySection({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const update = useUpdateUser(user.id);
  const [displayName, setDisplayName] = useState(user.display_name);

  // Keep the field in sync if the underlying user refetches (e.g. after a toggle).
  useEffect(() => {
    setDisplayName(user.display_name);
  }, [user.display_name]);

  const dirty = displayName.trim() !== user.display_name;

  function save(e: React.FormEvent) {
    e.preventDefault();
    if (!dirty) return;
    update.mutate(
      { display_name: displayName.trim() },
      {
        onSuccess: () => toast.success(t('toast.user.updated')),
        onError: (e) => toast.error(e),
      },
    );
  }

  return (
    <Card title={t('users.edit.identityCard')}>
      <form className="form" onSubmit={save}>
        <Field
          label={t('users.table.username')}
          htmlFor="edit-username"
          hint={t('users.edit.usernameHint')}
        >
          <Input id="edit-username" value={user.username} readOnly />
        </Field>
        <Field label={t('users.edit.displayNameLabel')} htmlFor="edit-display">
          <Input
            id="edit-display"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder={t('users.field.displayName.placeholder')}
            autoComplete="off"
          />
        </Field>
        <div className="form__actions">
          <Button type="submit" variant="primary" disabled={update.isPending || !dirty}>
            {update.isPending ? t('common.saving') : t('users.edit.save')}
          </Button>
        </div>
      </form>
    </Card>
  );
}

function ActivationSection({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const update = useUpdateUser(user.id);

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
    <Card title={t('users.edit.activationCard')}>
      <div className="users-actions">
        {user.active ? (
          <Badge tone="ok">{t('users.status.active')}</Badge>
        ) : (
          <Badge tone="neutral">{t('users.status.inactive')}</Badge>
        )}
        <IconButton
          icon={<Icon.Power />}
          label={user.active ? t('users.action.deactivate') : t('users.action.reactivate')}
          disabled={update.isPending}
          onClick={toggleActive}
        />
      </div>
    </Card>
  );
}

export function EditUserPage() {
  const t = useT();
  const { id = '' } = useParams();
  const users = useUsers();
  const cached = users.data?.find((u) => u.id === id);
  // Cold deep link (empty list cache) → fetch the single user directly.
  const single = useUser(cached ? '' : id);
  const user = cached ?? single.data;

  if (!user) {
    if (single.isLoading || users.isLoading) {
      return (
        <div className="stack">
          <PageHeader
            crumbs={<Link to="/utilizadores">{t('users.breadcrumb.self')}</Link>}
            title={<Skeleton width="16rem" height="1.6rem" />}
          />
          <Card title={t('users.edit.identityCard')}>
            <SkeletonDeflist />
          </Card>
        </div>
      );
    }
    if (single.error) return <ErrorNote error={single.error} />;
    return (
      <div className="stack">
        <PageHeader
          crumbs={<Link to="/utilizadores">{t('users.breadcrumb.self')}</Link>}
          title={t('users.edit.notFound')}
        />
      </div>
    );
  }

  return (
    <div className="stack">
      <PageHeader
        crumbs={
          <>
            <Link to="/utilizadores">{t('users.breadcrumb.self')}</Link> · {user.display_name}
          </>
        }
        title={user.display_name}
      />

      <IdentitySection user={user} />
      <ActivationSection user={user} />

      {/* Funções — scoped role assignment (t64-E6). Gated `role.assign` at each scope; the
          last-Owner-removal guard surfaces the server's honest 409. */}
      <RoleAssignmentManager user={user} />

      {/* Acesso e auditoria — the password + attestation-key manager, moved here from the
          old inline row. Anchor target for the list's "Acesso e auditoria" action. */}
      <section id="acesso" className="stack">
        <h3 className="section-subtitle">{t('users.access.title')}</h3>
        <Card>
          <UserAccessManager user={user} />
        </Card>
      </section>
    </div>
  );
}
