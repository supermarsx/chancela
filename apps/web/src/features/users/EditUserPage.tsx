/**
 * Edit one user — a dedicated screen at `/utilizadores/:id` (t89).
 *
 * ## Why a screen, and why there is now exactly ONE of them
 * Editing used to happen inline, as a panel appended below the roster inside
 * Configurações → Utilizadores (`?sec=utilizadores&user=:id`), while `/utilizadores/:id`
 * redirected *into* that state. That is the same defect t71 removed at creation time: two
 * addresses for one action, one of which buries a credential-editing surface under a list.
 * It is resolved the same way — the screen is the route, `EditUserPanel` is **deleted**
 * rather than left as a second entry point, and `?sec=utilizadores&user=:id` now redirects
 * **out** to here so old bookmarks resolve instead of 404-ing. The roster stays in
 * Configurações; the `#acesso` fragment still lands on the access section.
 *
 * ## Layout
 * Grouped cards, each an ordinary `form settings-rows` of `Field` rows — the same shape as
 * the create screen, so the two halves of one job read alike. `.settings-rows`, NOT
 * `.settings-grid`: the latter tiles whole cards into columns and silently breaks a form.
 *
 * ## Sections
 *  1. **Identidade** — the immutable audit username (read-only `code`), the display name and
 *     the contact e-mail (`PATCH /v1/users/{id}`).
 *  2. **Estado** — active/inactive (the same `PATCH`; users are never deleted, so attribution
 *     history stays intact).
 *  3. **Privacidade** — the DSR lifecycle, gated `user.manage`.
 *  4. **Funções** — scoped role assignment, gated `role.assign` at each scope.
 *  5. **Acesso e auditoria** — {@link UserAccessManager}: the sign-in password, the PKI
 *     audit-attestation key and the recovery phrase. Its cross-user credential-proof rules and
 *     the copy that explains them move with it **unchanged**, and stay adjacent to the controls
 *     they gate: editing another user's credentials proves that user's current password OR a
 *     valid recovery phrase, and generating an audit key requires the password specifically.
 *
 * The user is resolved from the `useUsers()` list cache for an instant paint; a cold deep
 * link (empty cache) falls back to `GET /v1/users/{id}` via {@link useUser}.
 */
import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  useCompleteUserDsrRequest,
  useCreateUserDsrRequest,
  useExportUserDsr,
  useUpdateUser,
  useUser,
  useUserDsrRequests,
  useUsers,
} from '../../api/hooks';
import { t as translateNow, useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  IconButton,
  Input,
  PageHeader,
  Select,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { UserAccessManager } from './UserAccessManager';
import { USERS_LIST_PATH } from './paths';
import { RoleAssignmentManager } from '../rbac/RoleAssignmentManager';
import {
  GateButton,
  PermissionDeniedNote,
  isPermissionError,
  useCan,
} from '../session/permissions';
import {
  DSR_REQUEST_TYPES,
  type DsrRequestStatus,
  type DsrRequestType,
  type UserView,
} from '../../api/types';

const DSR_EXPORT_CONTENT_TYPE = 'application/json';
const DSR_EXPORT_FILTERS = [{ name: 'JSON', extensions: ['json'] }];

function dsrExportBlob(data: unknown): Blob {
  return new Blob([JSON.stringify(data, null, 2)], { type: DSR_EXPORT_CONTENT_TYPE });
}

function safeFilenamePart(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, '-');
}

const DSR_REQUEST_TYPE_LABELS: Record<DsrRequestType, string> = {
  export: 'Exportação',
  rectification: 'Retificação',
  erasure: 'Apagamento',
  restriction: 'Restrição',
};

const DSR_REQUEST_STATUS_LABELS: Record<DsrRequestStatus, string> = {
  pending: 'Pendente',
  completed: 'Concluído',
};

function IdentitySection({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const update = useUpdateUser(user.id);
  const [displayName, setDisplayName] = useState(user.display_name);
  const [email, setEmail] = useState(user.email ?? '');

  // Keep the field in sync if the underlying user refetches (e.g. after a toggle).
  useEffect(() => {
    setDisplayName(user.display_name);
    setEmail(user.email ?? '');
  }, [user.display_name, user.email]);

  const trimmedDisplayName = displayName.trim();
  const trimmedEmail = email.trim();
  const dirty = trimmedDisplayName !== user.display_name || trimmedEmail !== (user.email ?? '');

  function save(e: React.FormEvent) {
    e.preventDefault();
    if (!dirty) return;
    const body = {
      ...(trimmedDisplayName !== user.display_name ? { display_name: trimmedDisplayName } : {}),
      ...(trimmedEmail !== (user.email ?? '')
        ? { email: trimmedEmail === '' ? null : trimmedEmail }
        : {}),
    };
    update.mutate(body, {
      onSuccess: () => toast.success(t('toast.user.updated')),
      onError: (e) => toast.error(e),
    });
  }

  return (
    <Card title={t('users.edit.identityCard')}>
      <form className="form settings-rows" onSubmit={save}>
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
        <Field label={t('registry.email.label')} htmlFor="edit-email">
          <Input
            id="edit-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('registry.email.placeholder')}
            autoComplete="email"
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

function PrivacyDsrSection({ user }: { user: UserView }) {
  const can = useCan();
  if (!can('user.manage')) return null;
  return <PrivacyDsrManager user={user} />;
}

function PrivacyDsrManager({ user }: { user: UserView }) {
  const toast = useToast();
  const dsrExport = useExportUserDsr(user.id);
  const requests = useUserDsrRequests(user.id);
  const createRequest = useCreateUserDsrRequest(user.id);
  const completeRequest = useCompleteUserDsrRequest(user.id);
  const [requestType, setRequestType] = useState<DsrRequestType>('export');

  function showSaveResult(result: SaveBlobResult) {
    if (result.kind === 'cancelled') {
      toast.info(saveBlobResultMessage(result));
      return;
    }
    toast.success(saveBlobResultMessage(result));
  }

  function download() {
    dsrExport.mutate(undefined, {
      onSuccess: async (data) => {
        try {
          const filename = `chancela-dsr-user-${safeFilenamePart(user.username)}.json`;
          showSaveResult(
            await saveBlobAs({
              blob: dsrExportBlob(data),
              filename,
              contentType: DSR_EXPORT_CONTENT_TYPE,
              filters: DSR_EXPORT_FILTERS,
              preferBrowserSavePicker: true,
            }),
          );
        } catch (e) {
          toast.error(e);
        }
      },
      onError: (e) => toast.error(e),
    });
  }

  function create(e: React.FormEvent) {
    e.preventDefault();
    createRequest.mutate(
      { request_type: requestType },
      {
        onSuccess: () => toast.success('Pedido DSR criado.'),
        onError: (e) => toast.error(e),
      },
    );
  }

  function complete(id: string) {
    completeRequest.mutate(id, {
      onSuccess: () => toast.success('Pedido DSR marcado como concluído.'),
      onError: (e) => toast.error(e),
    });
  }

  const list = requests.data ?? [];
  const busy = createRequest.isPending || completeRequest.isPending;

  return (
    <Card
      title={translateNow('uiLiteral.editUserPage.pedidosDsrPrivacidade')}
      actions={
        <GateButton
          perm="user.manage"
          type="button"
          variant="secondary"
          icon={<Icon.FileText />}
          disabled={dsrExport.isPending}
          onClick={download}
        >
          {dsrExport.isPending ? 'A preparar exportação DSR' : 'Descarregar exportação DSR'}
        </GateButton>
      }
    >
      <div className="stack">
        <p className="field__hint">
          {' '}
          {translateNow('uiLiteral.editUserPage.registaOCicloDeVidaDosPedidosDsr')}{' '}
        </p>

        <form className="form settings-rows" onSubmit={create}>
          <Field
            label={translateNow('uiLiteral.editUserPage.tipoDePedido')}
            htmlFor="dsr-request-type"
          >
            <Select
              id="dsr-request-type"
              value={requestType}
              onChange={(e) => setRequestType(e.target.value as DsrRequestType)}
              options={DSR_REQUEST_TYPES.map((type) => ({
                value: type,
                label: DSR_REQUEST_TYPE_LABELS[type],
              }))}
            />
          </Field>
          <div className="form__actions">
            <GateButton
              perm="user.manage"
              type="submit"
              variant="primary"
              icon={<Icon.Plus />}
              disabled={createRequest.isPending}
            >
              {createRequest.isPending ? 'A criar pedido DSR' : 'Criar pedido DSR'}
            </GateButton>
          </div>
        </form>

        {requests.isLoading ? (
          <SkeletonTable cols={6} />
        ) : requests.error ? (
          isPermissionError(requests.error) ? (
            <PermissionDeniedNote />
          ) : (
            <ErrorNote error={requests.error} />
          )
        ) : list.length === 0 ? (
          <EmptyState title={translateNow('uiLiteral.editUserPage.semPedidosDsr')}>
            <p>{translateNow('uiLiteral.editUserPage.aindaNaoHaPedidosDsrRegistadosParaEste')}</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>{translateNow('uiLiteral.editUserPage.tipo')}</th>
                <th>{translateNow('uiLiteral.editUserPage.estado')}</th>
                <th>{translateNow('uiLiteral.editUserPage.criado')}</th>
                <th>{translateNow('uiLiteral.editUserPage.criadoPor')}</th>
                <th>{translateNow('uiLiteral.editUserPage.concluido')}</th>
                <th>{translateNow('uiLiteral.editUserPage.acao')}</th>
              </tr>
            }
          >
            {list.map((request) => (
              <tr key={request.id}>
                <td>{DSR_REQUEST_TYPE_LABELS[request.request_type]}</td>
                <td>
                  <Badge tone={request.status === 'completed' ? 'ok' : 'warn'}>
                    {DSR_REQUEST_STATUS_LABELS[request.status]}
                  </Badge>
                </td>
                <td>
                  {/* A data-subject request is a privacy-compliance record: evidentiary. */}
                  <DateTime value={request.created_at} evidentiary />
                </td>
                <td>{request.created_by}</td>
                <td>
                  <DateTime value={request.completed_at} evidentiary />
                </td>
                <td className="users-actions">
                  {request.status === 'pending' ? (
                    <GateButton
                      perm="user.manage"
                      variant="secondary"
                      icon={<Icon.Check />}
                      disabled={busy}
                      onClick={() => complete(request.id)}
                    >
                      {' '}
                      {translateNow('uiLiteral.editUserPage.marcarConcluido')}{' '}
                    </GateButton>
                  ) : (
                    <span className="muted">{request.completed_by ?? '—'}</span>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </Card>
  );
}

function Crumbs({ trailing }: { trailing?: string }) {
  const t = useT();
  return (
    <>
      <Link to={USERS_LIST_PATH}>{t('users.breadcrumb.self')}</Link>
      {trailing ? ` · ${trailing}` : null}
    </>
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
    if (id && (single.isLoading || users.isLoading)) {
      return (
        <div className="stack">
          <PageHeader crumbs={<Crumbs />} title={<Skeleton width="16rem" height="1.6rem" />} />
          <Card title={t('users.edit.identityCard')}>
            <SkeletonDeflist />
          </Card>
        </div>
      );
    }
    if (single.error) {
      return (
        <div className="stack">
          <PageHeader crumbs={<Crumbs />} title={t('users.edit.title')} />
          <ErrorNote error={single.error} />
        </div>
      );
    }
    return (
      <div className="stack">
        <PageHeader crumbs={<Crumbs />} title={t('users.edit.notFound')} />
        <Card>
          <p className="field__hint">{t('users.edit.notFound')}</p>
        </Card>
      </div>
    );
  }

  return (
    <div className="stack form-page">
      <PageHeader crumbs={<Crumbs trailing={user.display_name} />} title={user.display_name} />

      <IdentitySection user={user} />
      <ActivationSection user={user} />
      <PrivacyDsrSection user={user} />

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
