/**
 * Create a user inside Configurações → Utilizadores (`?sec=utilizadores&user=novo`). The
 * legacy `/utilizadores/novo` route redirects there. This file keeps only the reusable panel
 * that Settings mounts inline.
 *
 * The form itself lives in the reusable {@link UserCreateForm}; Settings is the authenticated
 * host. The signed-out entry-screen bootstrap path (t50 W3) mounts the same `UserCreateForm`
 * with its own `onCreated` (passwordless sign-in) — `POST /v1/users` is bootstrap-only when
 * signed out and session-gated otherwise, so that gating lives in W3's host, not here.
 */
import { useT } from '../../i18n';
import { Card, useToast } from '../../ui';
import { UserCreateForm } from './UserCreateForm';
import type { UserView } from '../../api/types';

export function NewUserPanel({ onCreated }: { onCreated?: (user: UserView) => void }) {
  const t = useT();
  const toast = useToast();

  return (
    <Card title={t('users.create.cardTitle')}>
      <UserCreateForm
        autoFocus
        onCreated={(user) => {
          toast.success(t('toast.user.created'));
          onCreated?.(user);
        }}
      />
    </Card>
  );
}
