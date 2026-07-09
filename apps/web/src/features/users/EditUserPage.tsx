/**
 * Edit one user inside Configurações → Utilizadores (`?sec=utilizadores&user=:id`). The
 * legacy `/utilizadores/:id` route redirects there. This file keeps only the reusable panel.
 * The panel has three sections:
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
import { Link } from 'react-router-dom';
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
import { useT } from '../../i18n';
import {
  Badge,
  Button,
  Card,
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

function formatDateTime(value?: string): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat('pt-PT', { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

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
      title="Pedidos DSR / privacidade"
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
          Regista o ciclo de vida dos pedidos DSR do utilizador e descarrega o JSON não secreto para
          resposta. O conteúdo da exportação não é apresentado no ecrã.
        </p>

        <form className="form" onSubmit={create}>
          <Field label="Tipo de pedido" htmlFor="dsr-request-type">
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
          <EmptyState title="Sem pedidos DSR">
            <p>Ainda não há pedidos DSR registados para este utilizador.</p>
          </EmptyState>
        ) : (
          <Table
            head={
              <tr>
                <th>Tipo</th>
                <th>Estado</th>
                <th>Criado</th>
                <th>Criado por</th>
                <th>Concluído</th>
                <th>Ação</th>
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
                <td>{formatDateTime(request.created_at)}</td>
                <td>{request.created_by}</td>
                <td>{formatDateTime(request.completed_at)}</td>
                <td className="users-actions">
                  {request.status === 'pending' ? (
                    <GateButton
                      perm="user.manage"
                      variant="secondary"
                      icon={<Icon.Check />}
                      disabled={busy}
                      onClick={() => complete(request.id)}
                    >
                      Marcar concluído
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

export function EditUserPanel({ id, showHeader = false }: { id: string; showHeader?: boolean }) {
  const t = useT();
  const users = useUsers();
  const cached = users.data?.find((u) => u.id === id);
  // Cold deep link (empty list cache) → fetch the single user directly.
  const single = useUser(cached ? '' : id);
  const user = cached ?? single.data;

  if (!user) {
    if (single.isLoading || users.isLoading) {
      return (
        <div className="stack">
          {showHeader ? (
            <PageHeader
              crumbs={
                <Link to="/configuracoes?sec=utilizadores">{t('users.breadcrumb.self')}</Link>
              }
              title={<Skeleton width="16rem" height="1.6rem" />}
            />
          ) : null}
          <Card title={t('users.edit.identityCard')}>
            <SkeletonDeflist />
          </Card>
        </div>
      );
    }
    if (single.error) return <ErrorNote error={single.error} />;
    return (
      <div className="stack">
        {showHeader ? (
          <PageHeader
            crumbs={<Link to="/configuracoes?sec=utilizadores">{t('users.breadcrumb.self')}</Link>}
            title={t('users.edit.notFound')}
          />
        ) : (
          <Card title={t('users.edit.notFound')}>
            <p className="field__hint">{t('users.edit.notFound')}</p>
          </Card>
        )}
      </div>
    );
  }

  return (
    <div className="stack">
      {showHeader ? (
        <PageHeader
          crumbs={
            <>
              <Link to="/configuracoes?sec=utilizadores">{t('users.breadcrumb.self')}</Link> ·{' '}
              {user.display_name}
            </>
          }
          title={user.display_name}
        />
      ) : null}

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
