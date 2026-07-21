/**
 * Edit one user — a dedicated screen at `/users/:id` (t89).
 *
 * ## Why a screen, and why there is now exactly ONE of them
 * Editing used to happen inline, as a panel appended below the roster inside
 * Configurações → Utilizadores (`/settings/users?user=:id`), while `/users/:id`
 * redirected *into* that state. That is the same defect t71 removed at creation time: two
 * addresses for one action, one of which buries a credential-editing surface under a list.
 * It is resolved the same way — the screen is the route, `EditUserPanel` is **deleted**
 * rather than left as a second entry point, and `/settings/users?user=:id` now redirects
 * **out** to here so old bookmarks resolve instead of 404-ing. The roster stays in
 * Configurações; the `#acesso` fragment still lands on the access section.
 *
 * ## Layout
 * Grouped cards, each an ordinary `form settings-rows` of `Field` rows — the same shape as
 * the create screen, so the two halves of one job read alike. `.settings-rows`, NOT
 * `.settings-grid`: the latter tiles whole cards into columns and silently breaks a form.
 *
 * ## Sub-tabs (t103) — four, and their identity is in the PATH
 *
 * The screen was one long scroll of five cards mixing identity, privacy, authority and
 * credentials. It is now four tabs on the shared `<SubNav>`, addressed as `/users/:id/:sec`
 * through t97's `useSectionNav`:
 *
 *  1. **Geral** (`/users/:id`, no segment) — **Identidade**: the immutable audit username
 *     (read-only), display name and contact e-mail; and **Estado**: active/inactive. Users are
 *     never deleted, so deactivation is the mechanism and attribution history stays intact.
 *  2. **Pedidos DSR** (`/users/:id/dsr`) — the DSR lifecycle, gated `user.manage`. The tab is
 *     hidden without that permission, because the panel already renders nothing without it.
 *  3. **Funções** (`/users/:id/roles`) — scoped role assignment, gated `role.assign` at each
 *     scope; the refusal does not name the permission or the scope.
 *  4. **Acesso e auditoria** (`/users/:id/access`) — {@link UserAccessManager}: the sign-in
 *     password, the PKI audit-attestation key and the recovery phrase. Its cross-user
 *     credential-proof rules and the copy that explains them are **unchanged** and stay adjacent
 *     to the controls they gate: editing another user's credentials proves that user's current
 *     password OR a valid recovery phrase, and generating an audit key requires the password
 *     specifically.
 *
 * **Not a local tab strip.** The section is derived from the pathname on every render and never
 * mirrored into state, which is what makes each tab deep-linkable, identical after a reload, and
 * answerable by Back. Switching pushes rather than replaces, so Back returns to the previous tab
 * instead of leaving the screen. The route declares `navDepth: 2`, so a tab switch does not
 * remount the screen and discard the identity form's working copy.
 *
 * The retired `#acesso` fragment is promoted to the `access` tab (see the effect in
 * {@link EditUserScreen}) — with the section in the path there is nothing left to scroll to.
 *
 * The user is resolved from the `useUsers()` list cache for an instant paint; a cold deep
 * link (empty cache) falls back to `GET /v1/users/{id}` via {@link useUser}.
 */
import { useEffect, useState, type ReactNode } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom';
import { useSectionNav } from '../../app/navPath';
import { saveBlobAs, saveBlobResultMessage, type SaveBlobResult } from '../../desktop/saveFile';
import {
  useCompleteUserDsrRequest,
  useCreateUserDsrRequest,
  useExportUserDsr,
  useSession,
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
  Input,
  PageHeader,
  Select,
  Skeleton,
  SkeletonDeflist,
  SkeletonTable,
  SubNav,
  Table,
  useToast,
} from '../../ui';
import { UserAccessManager } from './UserAccessManager';
import { editUserSectionPath, USERS_LIST_PATH } from './paths';
import type { MessageKey } from '../../i18n/types';
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

/**
 * The screen's sub-tabs (t103). Slugs are **English**, like every other path segment in this
 * app (t97b): an address is an identifier, not copy, and pt-PT is reserved for what the operator
 * reads. `general` is the fallback and carries no segment, so `/users/:id` stays a valid address.
 */
type UserSection = 'general' | 'dsr' | 'roles' | 'security' | 'access';

/** The access tab's segment, named once so the legacy-fragment redirect cannot drift from it. */
const ACCESS_SECTION = 'access';
/** The pre-tab address of the access section, still live in bookmarks and the roster action. */
const LEGACY_ACCESS_HASH = '#acesso';

/**
 * Segurança sits directly before Acesso e auditoria (t103) because the two are the credential
 * surfaces and the ordering carries meaning: **Segurança** is the account holder's own view —
 * "the security of *my* account" — and **Acesso e auditoria** is the administrator's — "inspect
 * and reset *this* account". Same credentials, two verbs; adjacency is what makes the
 * "why does the fingerprint appear twice" copy legible.
 */
const USER_SECTIONS: { id: UserSection; label: MessageKey; icon: ReactNode }[] = [
  { id: 'general', label: 'users.edit.subnav.general', icon: <Icon.IdCard /> },
  { id: 'dsr', label: 'users.edit.subnav.dsr', icon: <Icon.FileText /> },
  { id: 'roles', label: 'users.edit.subnav.roles', icon: <Icon.Layers /> },
  { id: 'security', label: 'users.edit.subnav.security', icon: <Icon.Shield /> },
  { id: ACCESS_SECTION, label: 'users.edit.subnav.access', icon: <Icon.Wrench /> },
];

const isUserSection = (value: string | undefined): value is UserSection =>
  USER_SECTIONS.some((section) => section.id === value);

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

/**
 * Segurança — the account HOLDER's view of their own account security (t103).
 *
 * ## Why this tab exists, and the line between it and Acesso e auditoria
 *
 * The user asked for "a security tab … to help the user manage the user-facing security". The
 * distinction the lead ratified, and which the tab's own copy states so an operator understands
 * why the same fingerprint appears in two places:
 *
 *  - **Segurança** (this tab) is *my own account*: the second factor I enrol, the sessions I am
 *    signed in on, the state of my own credentials. On another user's screen it is **read-only
 *    state** — you cannot enrol someone else's authenticator — and the actions defer to…
 *  - **Acesso e auditoria**, which is the *administrator's* surface: resetting another account's
 *    credentials with proof-of-authority. That machinery lives there and is not duplicated here.
 *
 * `isSelf` is the whole switch: session user == edited user. When the session is unknown
 * (loading/signed out) we treat it as **not** self, so the tab never offers a self-service
 * affordance it cannot honour — the same fail-safe direction `UserAccessManager` uses.
 *
 * ## What ships now, and the two seams that do not
 *
 * Password, recovery-phrase and audit-key **state** are on `UserView` today and are shown here.
 * The management of those credentials is single-source in Acesso e auditoria — duplicating the
 * controls onto two tabs would recreate the "two addresses for one action" defect t71/t89 spent
 * effort removing — so this tab links there rather than re-mounting the manager.
 *
 * Two features the user named are backend work in flight, so they are **seams, not stubs**
 * (the lead was explicit: no fake list, no "pending" placeholder):
 *
 *  - **TOTP** (`t107-signup`) — per-user enrolment state does not exist yet. When its read shape
 *    and component land, they mount at {@link TOTP_SEAM}. Shipping without it beats stubbing an
 *    enrolment flow that would be deleted.
 *  - **Sessões ativas** (`t107-signup`, funded) — `DurableSessionRecord` carries no device/IP/
 *    last-seen and there is no per-user list or self-revoke route yet. Its panel mounts at
 *    {@link SESSIONS_SEAM} once the endpoint exists.
 *
 * ## Credential-safety rules that hold here as everywhere on this screen
 *
 * No key or password material reaches the DOM, a URL, a log or an error — this tab reads only the
 * booleans and the fingerprint `UserView` already publishes. The t92 key-rotation truth is stated
 * without regression: rotating makes a new key for future attestations and **past ones stay
 * verifiable**, because superseded public halves are retained.
 */
function SecuritySection({ user }: { user: UserView }) {
  const t = useT();
  const session = useSession();
  const navigate = useNavigate();

  // Self only when we KNOW the session user and it is this user. Unknown ⇒ not self, so no
  // self-service affordance is shown that the server would refuse anyway.
  const isSelf = !!session.data?.user && session.data.user.id === user.id;

  const accessPath = editUserSectionPath(user.id, ACCESS_SECTION);

  return (
    <div className="stack">
      <Card title={t('users.security.title')}>
        <p className="field__hint">
          {isSelf ? t('users.security.intro.self') : t('users.security.intro.other')}
        </p>

        {/* Credential posture — read-only state, the booleans + fingerprint UserView already
            publishes. Management is single-source in Acesso e auditoria; the row action points
            there rather than re-mounting the manager on a second tab. */}
        <div className="form settings-rows">
          <Field label={t('users.secret.label')} hint={t('users.security.password.hint')}>
            {user.has_secret ? (
              <Badge tone="ok">{t('users.secret.has')}</Badge>
            ) : (
              <Badge tone="neutral">{t('users.secret.none')}</Badge>
            )}
          </Field>
          <Field label={t('users.recovery.label')} hint={t('users.security.recovery.hint')}>
            {user.has_recovery_phrase ? (
              <Badge tone="accent">{t('users.recovery.has')}</Badge>
            ) : (
              <Badge tone="neutral">{t('users.recovery.none')}</Badge>
            )}
          </Field>
          <Field label={t('users.key.label')} hint={t('users.security.key.hint')}>
            {user.has_attestation_key ? (
              <span className="stack--tight">
                <Badge tone="ok">{t('users.key.has')}</Badge>
                {user.attestation_key_fingerprint ? (
                  <code className="mono">{user.attestation_key_fingerprint}</code>
                ) : null}
              </span>
            ) : (
              <Badge tone="neutral">{t('users.key.none')}</Badge>
            )}
          </Field>
          <div className="form__actions">
            <Button
              type="button"
              variant="secondary"
              icon={<Icon.Wrench />}
              onClick={() => navigate(accessPath)}
            >
              {t('users.security.manage')}
            </Button>
          </div>
        </div>
      </Card>

      {/*
        TOTP_SEAM (t103 → t107-signup). The two-factor block mounts here once t107 lands the
        per-user enrolment read shape and its self-enrolment component. On `isSelf` it is the
        enrolment/management flow; on another user's screen it is read-only "TOTP enrolled y/n".
        Deliberately renders NOTHING until then — a stubbed second factor is worse than an honest
        absence on a security surface. Do NOT add a placeholder here; add the real block.
      */}

      {/*
        SESSIONS_SEAM (t103 → t107-signup, funded). "Sessões ativas" — the sign-ins on this
        account with device/IP/last-seen and a self-service "terminar as outras sessões" — mounts
        here once t107 lands the enriched session record and the per-user list + revoke routes.
        `DurableSessionRecord` today carries none of that and there is no list/revoke endpoint, so
        there is nothing to render and no placeholder to draw. Add the real panel, not a promise.
      */}
    </div>
  );
}

/**
 * Estado da conta — what the account currently is, and the one action that changes it.
 *
 * ## What was actually wrong (t103), diagnosed before restyling
 *
 * The card was a bare `<div className="users-actions">` holding a `Badge` and an icon-only
 * `IconButton`. Four separate defects, only the first of which is cosmetic:
 *
 * 1. **It borrowed the roster's table-cell affordance.** `.users-actions` is the flex row that
 *    lays out per-row icon buttons inside `<td>`s. Dropped into a form page it produced a card
 *    with no label, no row grid and no alignment with the `settings-rows` cards above and below
 *    it — the visible "jank". An icon-only control is right in a table, where there are N rows
 *    and a tooltip carries the name; it is wrong as the sole control on a dedicated screen.
 * 2. **State and action were two adjacent glyphs with no words between them.** A badge reading
 *    "Ativo" beside a power icon does not say whether the icon *reports* the state or *changes*
 *    it, and the icon's only name was a tooltip. On the screen that decides whether an account
 *    can sign in, that is the wrong place to make someone hover to find out.
 * 3. **Nothing said what deactivating means.** Users are never deleted here — deactivation is
 *    the whole mechanism, and the reason is that attribution history must stay intact. That is
 *    the single most useful sentence on the card and it was absent.
 * 4. **The control was not permission-gated**, while the *identical* control on the roster one
 *    click away is a `GateIconButton perm="user.manage"`, and the DSR and Funções sections of
 *    this very screen are gated. Not a security hole — the server re-enforces and refuses — but
 *    it offered an operator a control that could only end in a 403.
 *
 * All four are fixed together: the shared `.settings-rows` grid, a labelled row whose hint states
 * the consequence, a **worded** button, and `GateButton perm="user.manage"` matching the roster.
 * The action's meaning now survives without a tooltip.
 */
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
      {/* Not a <form>: there is nothing to submit, only one immediate action. The row grid is
          shared with the sibling cards so the three read as one screen. */}
      <div className="form settings-rows">
        <Field
          label={t('users.edit.status.label')}
          hint={
            user.active ? t('users.edit.status.hint.active') : t('users.edit.status.hint.inactive')
          }
        >
          {user.active ? (
            <Badge tone="ok">{t('users.status.active')}</Badge>
          ) : (
            <Badge tone="neutral">{t('users.status.inactive')}</Badge>
          )}
        </Field>
        <div className="form__actions">
          <GateButton
            perm="user.manage"
            type="button"
            variant="secondary"
            icon={<Icon.Power />}
            disabled={update.isPending}
            onClick={toggleActive}
          >
            {update.isPending
              ? t('users.edit.status.pending')
              : user.active
                ? t('users.action.deactivate')
                : t('users.action.reactivate')}
          </GateButton>
        </div>
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

  return <EditUserScreen user={user} />;
}

/**
 * The tabbed body (t103). Split out from {@link EditUserPage} so the section hook runs only once
 * a user is resolved: the loading, error and not-found states return early and have no tabs to
 * show, and calling the hook above those returns would put it behind a conditional.
 */
function EditUserScreen({ user }: { user: UserView }) {
  const t = useT();
  const can = useCan();
  const navigate = useNavigate();
  const { hash } = useLocation();

  // Geral is the default and carries no segment, so `/users/:id` still lands on it. A PUSH, not
  // a replace: a tab is somewhere the operator navigated, so Back returns to the previous tab
  // rather than leaving the screen — the rule the other tabbed surfaces already follow.
  const { section, select: selectSection } = useSectionNav<UserSection>({
    depth: 2,
    parse: (raw) => (isUserSection(raw) ? raw : 'general'),
    fallback: 'general',
  });

  /**
   * The retired `#acesso` fragment, promoted to the tab it now names.
   *
   * Access used to be an anchor on one long page, and the roster's access row-action, the e2e
   * suites and any older bookmark still address it that way. With the section in the path there
   * is nothing to scroll to, so an untranslated `#acesso` would silently land on Geral — exactly
   * the failure this fragment was carried across two previous tasks to prevent. Translated once,
   * with `replace`, so Back does not bounce between the old address and the new one.
   */
  useEffect(() => {
    if (hash === LEGACY_ACCESS_HASH && section === 'general') {
      navigate(editUserSectionPath(user.id, ACCESS_SECTION), { replace: true });
    }
  }, [hash, section, user.id, navigate]);

  // The DSR panel self-gates on `user.manage` and renders nothing without it. Hiding the TAB on
  // the same predicate keeps the strip honest — an empty tab is worse than an absent one — and
  // it stays a read of the same permission rather than a second source of truth.
  const canManage = can('user.manage');
  const items = USER_SECTIONS.filter((s) => s.id !== 'dsr' || canManage);

  return (
    <div className="stack form-page">
      <PageHeader crumbs={<Crumbs trailing={user.display_name} />} title={user.display_name}>
        <SubNav
          items={items.map((s) => ({ id: s.id, label: t(s.label), icon: s.icon }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('users.edit.subnav.aria')}
        />
      </PageHeader>

      {/* One section at a time; the panel replays the route-enter fade on each switch. */}
      <div className="route-transition stack" key={section}>
        {section === 'general' ? (
          <>
            <IdentitySection user={user} />
            <ActivationSection user={user} />
          </>
        ) : section === 'dsr' ? (
          <PrivacyDsrSection user={user} />
        ) : section === 'roles' ? (
          /* Funções — scoped role assignment (t64-E6). Gated `role.assign` at each scope; the
             last-Owner-removal guard surfaces the server's honest 409. */
          <RoleAssignmentManager user={user} />
        ) : section === 'security' ? (
          <SecuritySection user={user} />
        ) : (
          /* `id="acesso"` is kept deliberately: the Playwright suites and the roster's access
             action address this section by it, and it costs nothing now that it is a tab too.
             The manager renders its own grouped cards, so there is no wrapping Card here —
             nesting a panel inside a panel is what gave this section its off-grid look. */
          <section id="acesso" className="stack">
            <UserAccessManager user={user} />
          </section>
        )}
      </div>
    </div>
  );
}
