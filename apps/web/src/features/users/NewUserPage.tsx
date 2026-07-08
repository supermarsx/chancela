/**
 * Create a user, on its own editorial route (`/utilizadores/novo`, plan t50 W2). The create
 * form used to sit inline on the Utilizadores page; it now has a dedicated screen reached
 * from the list's "Novo utilizador" button, so the roster runs full width. On success we
 * fire the create toast and follow the freshly created user to their edit screen, where a
 * sign-in password / audit key can be provisioned immediately.
 *
 * The form itself lives in the reusable {@link UserCreateForm}; this page is the
 * authenticated host. The signed-out entry-screen bootstrap path (t50 W3) mounts the same
 * `UserCreateForm` with its own `onCreated` (passwordless sign-in) — `POST /v1/users` is
 * bootstrap-only when signed out and session-gated otherwise, so that gating lives in W3's
 * host, not here.
 */
import { Link, useNavigate } from 'react-router-dom';
import { useT } from '../../i18n';
import { Card, PageHeader, useToast } from '../../ui';
import { UserCreateForm } from './UserCreateForm';

export function NewUserPage() {
  const t = useT();
  const toast = useToast();
  const navigate = useNavigate();

  return (
    <div className="stack form-page">
      <PageHeader
        crumbs={
          <>
            <Link to="/utilizadores">{t('users.breadcrumb.self')}</Link> · {t('users.new.crumb')}
          </>
        }
        title={t('users.new.title')}
      />

      <Card title={t('users.create.cardTitle')}>
        <UserCreateForm
          autoFocus
          onCreated={(user) => {
            // R6: the success toast fires even though we navigate away (ToastProvider is
            // above the router).
            toast.success(t('toast.user.created'));
            navigate(`/utilizadores/${user.id}`);
          }}
        />
      </Card>
    </div>
  );
}
