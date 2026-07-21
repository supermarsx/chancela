/**
 * Delegações (t64-E6; role-shaped t44) — list the delegations touching you
 * (`GET /v1/delegations`), hand over a **função** (`POST /v1/delegations`), suspend/resume one
 * (`POST /v1/delegations/{id}/{suspend,resume}`) and revoke one (`DELETE /v1/delegations/{id}`).
 *
 * ## What a delegation is
 * A delegation assigns a **função**, not a hand-picked bag of permissions: you put someone in your
 * place as (say) Secretário, and they hold whatever that função grants — including any later edit
 * to it, since the server resolves the role live. The picker therefore offers funções by their
 * human name and shows the authority each one carries, so an operator can see what they are
 * handing over before they hand it over.
 *
 * ## Honest guards (server-enforced; the UI reflects, never widens)
 *  - **`delegation.grant` @ scope** gates the grant affordance (disable-with-explanation).
 *  - **Delegate only a função you fully hold via a ROLE** — the picker offers only funções whose
 *    every permission you hold via a role and which carry no meta-permission (mirroring
 *    `can_delegate_roles`); the server re-checks every permission inside every função at the chosen
 *    scope and 403s the WHOLE delegation, naming the offending verb. Nothing partial is ever
 *    granted, so the toast the operator sees is the server's honest message.
 *  - **Revoke** — allowed to the grantor OR a `delegation.revoke` holder; a non-grantor without the
 *    verb sees the control disabled-with-explanation. **Suspend/resume** takes the same authority.
 *
 * Status (pending / active / suspended / expired / revoked) is shown per row, and the filters below
 * are **display only**: a suspended or expired delegation conveys nothing because the server stops
 * it where authority resolves, never because a row is hidden here. Reused by t62.
 */
import { useMemo, useState } from 'react';
import {
  useDelegations,
  useGrantDelegation,
  usePermissionCatalog,
  useRevokeDelegation,
  useRoles,
  useSession,
  useSetDelegationSuspended,
  useUsers,
} from '../../api/hooks';
import { useT } from '../../i18n';
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
  InlineWarning,
  Input,
  Select,
  SkeletonTable,
  Table,
  TextArea,
  useToast,
} from '../../ui';
import { GateButton, GateIconButton, usePermissions, useCan } from '../session/permissions';
import type { DelegationView, PermissionScope, RoleView } from '../../api/types';
import { ScopePicker, useScopeLabel } from './ScopePicker';

const MAX_DELEGATION_LEGAL_BASIS_CHARS = 1024;

type DelegStatus = 'pending' | 'active' | 'suspended' | 'expired' | 'revoked';

/**
 * The funções a delegation hands over. Defensive against a server older than t44 (and against the
 * legacy permission-shaped records, which genuinely carry none).
 */
function rolesOf(d: DelegationView) {
  return d.roles ?? [];
}

/** Derive a delegation's status: revoked wins, then suspension, elapsed expiry, future start. */
function statusOf(d: DelegationView, now: number): DelegStatus {
  if (d.revoked) return 'revoked';
  if (d.suspended) return 'suspended';
  if (d.expires_at && Date.parse(d.expires_at) <= now) return 'expired';
  const startsAt = Date.parse(d.starts_at);
  if (!Number.isNaN(startsAt) && startsAt > now) return 'pending';
  return 'active';
}

/**
 * The funções the current user may delegate: those whose **every** permission they hold via a role
 * and which carry no meta-permission. This mirrors the server's `can_delegate_roles` exactly — it
 * is a reflection of the ceiling, not a second one; the server re-checks at the chosen scope.
 *
 * An empty função is excluded: it is technically delegable but conveys nothing, so offering it
 * would only produce a delegation that does nothing.
 */
function useDelegableRoles(): RoleView[] {
  const roles = useRoles();
  const catalog = usePermissionCatalog();
  const { grants } = usePermissions();

  return useMemo(() => {
    const meta = new Set(
      (catalog.data?.permissions ?? []).filter((p) => p.meta).map((p) => p.permission),
    );
    const heldViaRole = new Set(grants.filter((g) => g.source === 'role').map((g) => g.permission));
    return (roles.data ?? [])
      .filter(
        (r) =>
          r.permissions.length > 0 &&
          r.permissions.every((p) => !meta.has(p) && heldViaRole.has(p)),
      )
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [roles.data, catalog.data, grants]);
}

/** The grant form. Split out so its own hooks (scope/função drafts) stay local. */
function GrantForm({ onClose }: { onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const users = useUsers();
  const session = useSession();
  const grant = useGrantDelegation();
  const delegable = useDelegableRoles();

  const selfId = session.data?.user?.id;
  const [to, setTo] = useState('');
  // A delegation carries a set of FUNÇÕES sharing one scope, one lifetime and one legal basis.
  // The server re-validates every permission inside every função and refuses the whole grant if
  // any one is not delegable.
  const [roles, setRoles] = useState<ReadonlySet<string>>(new Set());
  const [scope, setScope] = useState<PermissionScope>({ kind: 'global' });
  const [startsAt, setStartsAt] = useState('');
  const [expiry, setExpiry] = useState('');
  const [legalBasis, setLegalBasis] = useState('');

  const granteeOptions = (users.data ?? [])
    .filter((u) => u.active && u.id !== selfId)
    .map((u) => ({ value: u.id, label: `${u.display_name} (${u.username})` }));

  const effectiveTo = to || granteeOptions[0]?.value || '';
  // Selection is kept in picker order so the request lists the funções as the operator sees them.
  const selected = delegable.filter((r) => roles.has(r.id));
  const scopeOk = scope.kind === 'global' || scope.id !== '';
  const trimmedLegalBasis = legalBasis.trim();
  const legalBasisOk =
    trimmedLegalBasis.length > 0 && trimmedLegalBasis.length <= MAX_DELEGATION_LEGAL_BASIS_CHARS;
  const canSubmit =
    !!effectiveTo && selected.length > 0 && scopeOk && legalBasisOk && !grant.isPending;

  function toggleRole(id: string) {
    setRoles((current) => {
      const next = new Set(current);
      if (!next.delete(id)) next.add(id);
      return next;
    });
  }

  function submit() {
    if (!canSubmit) return;
    // datetime-local (local wall-clock) → an RFC-3339 instant the server parses; omit if unset.
    const starts_at = startsAt ? new Date(startsAt).toISOString() : undefined;
    const expires_at = expiry ? new Date(expiry).toISOString() : undefined;
    grant.mutate(
      {
        to: effectiveTo,
        roles: selected.map((r) => r.id),
        scope,
        starts_at,
        expires_at,
        legal_basis: trimmedLegalBasis,
      },
      {
        onSuccess: () => {
          toast.success(t('rbac.toast.delegated'));
          onClose();
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  if (delegable.length === 0) {
    return (
      <Card title={t('rbac.deleg.grant')}>
        <InlineWarning tone="info">{t('rbac.deleg.permission.none')}</InlineWarning>
        <div className="form__actions">
          <Button type="button" variant="ghost" onClick={onClose}>
            {t('common.cancel')}
          </Button>
        </div>
      </Card>
    );
  }

  return (
    <Card title={t('rbac.deleg.grant')}>
      <form
        className="form settings-rows"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <p className="field__hint">{t('rbac.deleg.onlyHeldNote')}</p>

        <Field label={t('rbac.deleg.to.label')} htmlFor="rbac-deleg-to">
          <Select
            id="rbac-deleg-to"
            value={effectiveTo}
            onChange={(e) => setTo(e.target.value)}
            options={granteeOptions}
          />
        </Field>

        {/* Not a `Field`: this is a group of checkboxes, not one control, so it carries its own
            <legend> rather than a <label for=""> pointing at nothing. Each função is offered by its
            human name with the authority it carries spelled out underneath — handing over a role
            you cannot inspect is how an operator gives away more than they meant to. */}
        <fieldset className="rbac-matrix__group">
          <legend className="rbac-matrix__legend">{t('rbac.deleg.permission.label')}</legend>
          <div className="row-wrap">
            <Button
              type="button"
              variant="ghost"
              disabled={grant.isPending}
              onClick={() => setRoles(new Set(delegable.map((r) => r.id)))}
            >
              {t('rbac.matrix.selectAll')}
            </Button>
            <Button
              type="button"
              variant="ghost"
              disabled={grant.isPending}
              onClick={() => setRoles(new Set())}
            >
              {t('rbac.matrix.clear')}
            </Button>
          </div>
          <div className="stack">
            {delegable.map((r) => (
              <label className="rbac-matrix__perm" key={r.id}>
                <input
                  type="checkbox"
                  checked={roles.has(r.id)}
                  disabled={grant.isPending}
                  onChange={() => toggleRole(r.id)}
                />
                <span>
                  <strong>{r.name}</strong>
                  <span className="muted"> · {t('rbac.deleg.funcao.carries')}: </span>
                  <span className="rbac-matrix__perms">
                    {r.permissions.map((p) => (
                      <code className="mono" key={p}>
                        {p}
                      </code>
                    ))}
                  </span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <ScopePicker value={scope} onChange={setScope} idPrefix="rbac-deleg-scope" />

        <Field
          label={t('rbac.deleg.startsAt.label')}
          htmlFor="rbac-deleg-starts-at"
          hint={t('rbac.deleg.startsAt.hint')}
        >
          <Input
            id="rbac-deleg-starts-at"
            type="datetime-local"
            value={startsAt}
            onChange={(e) => setStartsAt(e.target.value)}
          />
        </Field>

        <Field
          label={t('rbac.deleg.expiry.label')}
          htmlFor="rbac-deleg-expiry"
          hint={t('rbac.deleg.expiry.hint')}
        >
          <Input
            id="rbac-deleg-expiry"
            type="datetime-local"
            value={expiry}
            onChange={(e) => setExpiry(e.target.value)}
          />
        </Field>

        <Field
          label={t('rbac.deleg.legalBasis.label')}
          htmlFor="rbac-deleg-legal-basis"
          hint={t('rbac.deleg.legalBasis.hint')}
        >
          <TextArea
            id="rbac-deleg-legal-basis"
            rows={3}
            maxLength={MAX_DELEGATION_LEGAL_BASIS_CHARS}
            required
            value={legalBasis}
            onChange={(e) => setLegalBasis(e.target.value)}
          />
        </Field>

        <div className="form__actions">
          <Button type="button" variant="ghost" disabled={grant.isPending} onClick={onClose}>
            {t('common.cancel')}
          </Button>
          <GateButton
            perm="delegation.grant"
            scope={scope}
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={!canSubmit}
          >
            {t('rbac.deleg.submit')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

/** One delegation row: the funções it hands over, its status, and the lifecycle controls. */
function DelegationRow({ d, now }: { d: DelegationView; now: number }) {
  const t = useT();
  const toast = useToast();
  const users = useUsers();
  const session = useSession();
  const can = useCan();
  const scopeLabel = useScopeLabel();
  const revoke = useRevokeDelegation();
  const setSuspended = useSetDelegationSuspended();

  const selfId = session.data?.user?.id;
  const status = statusOf(d, now);

  function userName(id: string): string {
    const u = (users.data ?? []).find((x) => x.id === id);
    const base = u ? u.display_name : id;
    return id === selfId ? `${base} ${t('rbac.deleg.user.self')}` : base;
  }

  function doRevoke() {
    revoke.mutate(d.id, {
      onSuccess: () => toast.success(t('rbac.toast.revoked')),
      onError: (e) => toast.error(e),
    });
  }

  function doSetSuspended(suspended: boolean) {
    setSuspended.mutate(
      { id: d.id, suspended },
      {
        onSuccess: () =>
          toast.success(t(suspended ? 'rbac.toast.suspended' : 'rbac.toast.resumed')),
        onError: (e) => toast.error(e),
      },
    );
  }

  const isGrantor = d.from === selfId;
  const mayManage = isGrantor || can('delegation.revoke', d.scope);
  const busy = revoke.isPending || setSuspended.isPending;
  const statusBadge =
    status === 'active' ? (
      <Badge tone="ok">{t('rbac.deleg.status.active')}</Badge>
    ) : status === 'pending' ? (
      <Badge tone="neutral">{t('rbac.deleg.status.pending')}</Badge>
    ) : status === 'suspended' ? (
      <Badge tone="warn">{t('rbac.deleg.status.suspended')}</Badge>
    ) : status === 'expired' ? (
      <Badge tone="neutral">{t('rbac.deleg.status.expired')}</Badge>
    ) : (
      <Badge tone="warn">{t('rbac.deleg.status.revoked')}</Badge>
    );
  const basis = d.legal_basis?.trim();

  return (
    <tr>
      <td>
        {/* The funções this delegation hands over, each with the authority it currently carries —
            resolved live by the server, so an edited função shows its new contents here. They are
            revoked together, as one unit. A legacy permission-shaped record has no função and
            renders its verbs directly. */}
        {rolesOf(d).length > 0 ? (
          <div className="stack">
            {rolesOf(d).map((r) => (
              <div key={r.id}>
                <strong>{r.known ? r.name : t('rbac.deleg.funcao.unknown')}</strong>
                <div className="rbac-matrix__perms">
                  {r.permissions.map((p) => (
                    <code className="mono" key={p}>
                      {p}
                    </code>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rbac-matrix__perms">
            {(d.permissions ?? []).map((p) => (
              <code className="mono" key={p}>
                {p}
              </code>
            ))}
          </div>
        )}
      </td>
      <td>{userName(d.from)}</td>
      <td>{userName(d.to)}</td>
      <td>
        <Badge tone="neutral">{scopeLabel(d.scope)}</Badge>
      </td>
      <td>{statusBadge}</td>
      <td>
        {d.starts_at ? (
          // A delegation of authority is an evidentiary record: when it began, to the second.
          <DateTime className="mono" value={d.starts_at} evidentiary />
        ) : (
          <span className="muted">{t('rbac.deleg.startsAt.missing')}</span>
        )}
      </td>
      <td>{basis ? basis : <span className="muted">{t('rbac.deleg.legalBasis.missing')}</span>}</td>
      <td>
        {d.expires_at ? (
          <DateTime className="mono" value={d.expires_at} evidentiary />
        ) : (
          <span className="muted">{t('rbac.deleg.noExpiry')}</span>
        )}
      </td>
      <td className="users-actions">
        {d.revoked ? (
          <span className="muted">—</span>
        ) : (
          <>
            {/* Suspend/resume is the reversible pause; revoke is terminal. Both take the same
                authority, so they are gated identically. */}
            <Button
              type="button"
              variant="ghost"
              disabled={busy || !mayManage}
              onClick={() => doSetSuspended(!d.suspended)}
            >
              {t(d.suspended ? 'rbac.deleg.resume' : 'rbac.deleg.suspend')}
            </Button>
            {isGrantor ? (
              // The grantor may always revoke their own grant (server allows the grantor bypass).
              <IconButton
                icon={<Icon.Trash />}
                label={t('rbac.deleg.revoke')}
                disabled={busy}
                onClick={doRevoke}
              />
            ) : (
              // Otherwise it needs `delegation.revoke` at the delegation's scope.
              <GateIconButton
                perm="delegation.revoke"
                scope={d.scope}
                icon={<Icon.Trash />}
                label={t('rbac.deleg.revoke')}
                disabled={busy || !can('delegation.revoke', d.scope)}
                onClick={doRevoke}
              />
            )}
          </>
        )}
      </td>
    </tr>
  );
}

export function DelegacoesSection() {
  const t = useT();
  const delegations = useDelegations();
  const users = useUsers();
  const scopeLabel = useScopeLabel();
  const [granting, setGranting] = useState(false);
  // Display-only filters. They never change what a delegation conveys — the server enforces
  // suspension/expiry/revocation where authority resolves, not by what this table shows.
  const [status, setStatus] = useState('');
  const [role, setRole] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [scope, setScope] = useState('');
  // A single "now" per render so every row's expiry compares against the same instant.
  const now = Date.now();

  const list = useMemo(() => delegations.data ?? [], [delegations.data]);

  const anyOption = { value: '', label: t('rbac.deleg.filter.all') };
  const userOptions = useMemo(() => {
    const named = new Map<string, string>();
    for (const u of users.data ?? []) named.set(u.id, u.display_name);
    const ids = new Set<string>();
    for (const d of list) {
      ids.add(d.from);
      ids.add(d.to);
    }
    return [...ids].map((id) => ({ value: id, label: named.get(id) ?? id }));
  }, [list, users.data]);
  const roleOptions = useMemo(() => {
    const named = new Map<string, string>();
    for (const d of list) {
      for (const r of rolesOf(d))
        named.set(r.id, r.known ? r.name : t('rbac.deleg.funcao.unknown'));
    }
    return [...named].map(([value, label]) => ({ value, label }));
  }, [list, t]);
  const scopeOptions = useMemo(() => {
    const named = new Map<string, string>();
    for (const d of list) named.set(JSON.stringify(d.scope), scopeLabel(d.scope));
    return [...named].map(([value, label]) => ({ value, label }));
  }, [list, scopeLabel]);

  const filtered = list.filter(
    (d) =>
      (!status || statusOf(d, now) === status) &&
      (!role || rolesOf(d).some((r) => r.id === role)) &&
      (!from || d.from === from) &&
      (!to || d.to === to) &&
      (!scope || JSON.stringify(d.scope) === scope),
  );

  if (delegations.isLoading) return <SkeletonTable rows={4} cols={9} />;
  if (delegations.error) return <ErrorNote error={delegations.error} />;

  return (
    <div className="stack">
      {granting ? (
        <GrantForm onClose={() => setGranting(false)} />
      ) : (
        <Card
          title={t('rbac.deleg.cardTitle')}
          actions={
            <GateButton
              perm="delegation.grant"
              anyScope
              variant="primary"
              icon={<Icon.Plus />}
              onClick={() => setGranting(true)}
            >
              {t('rbac.deleg.grant')}
            </GateButton>
          }
        >
          <p className="field__hint">{t('rbac.delegacoes.lede')}</p>
          {list.length === 0 ? (
            <EmptyState title={t('rbac.deleg.empty')}>
              <p>{t('rbac.deleg.emptyBody')}</p>
            </EmptyState>
          ) : (
            <>
              <div className="row-wrap">
                <Field label={t('rbac.deleg.table.status')} htmlFor="rbac-deleg-filter-status">
                  <Select
                    id="rbac-deleg-filter-status"
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    options={[
                      anyOption,
                      { value: 'active', label: t('rbac.deleg.status.active') },
                      { value: 'pending', label: t('rbac.deleg.status.pending') },
                      { value: 'suspended', label: t('rbac.deleg.status.suspended') },
                      { value: 'expired', label: t('rbac.deleg.status.expired') },
                      { value: 'revoked', label: t('rbac.deleg.status.revoked') },
                    ]}
                  />
                </Field>
                <Field label={t('rbac.deleg.table.permission')} htmlFor="rbac-deleg-filter-role">
                  <Select
                    id="rbac-deleg-filter-role"
                    value={role}
                    onChange={(e) => setRole(e.target.value)}
                    options={[anyOption, ...roleOptions]}
                  />
                </Field>
                <Field label={t('rbac.deleg.table.from')} htmlFor="rbac-deleg-filter-from">
                  <Select
                    id="rbac-deleg-filter-from"
                    value={from}
                    onChange={(e) => setFrom(e.target.value)}
                    options={[anyOption, ...userOptions]}
                  />
                </Field>
                <Field label={t('rbac.deleg.table.to')} htmlFor="rbac-deleg-filter-to">
                  <Select
                    id="rbac-deleg-filter-to"
                    value={to}
                    onChange={(e) => setTo(e.target.value)}
                    options={[anyOption, ...userOptions]}
                  />
                </Field>
                <Field label={t('rbac.deleg.table.scope')} htmlFor="rbac-deleg-filter-scope">
                  <Select
                    id="rbac-deleg-filter-scope"
                    value={scope}
                    onChange={(e) => setScope(e.target.value)}
                    options={[anyOption, ...scopeOptions]}
                  />
                </Field>
              </div>
              {filtered.length === 0 ? (
                <InlineWarning tone="info">{t('rbac.deleg.filter.none')}</InlineWarning>
              ) : (
                <Table
                  head={
                    <tr>
                      <th>{t('rbac.deleg.table.permission')}</th>
                      <th>{t('rbac.deleg.table.from')}</th>
                      <th>{t('rbac.deleg.table.to')}</th>
                      <th>{t('rbac.deleg.table.scope')}</th>
                      <th>{t('rbac.deleg.table.status')}</th>
                      <th>{t('rbac.deleg.table.startsAt')}</th>
                      <th>{t('rbac.deleg.table.legalBasis')}</th>
                      <th>{t('rbac.deleg.table.expiry')}</th>
                      <th>{t('rbac.deleg.table.action')}</th>
                    </tr>
                  }
                >
                  {filtered.map((d) => (
                    <DelegationRow key={d.id} d={d} now={now} />
                  ))}
                </Table>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  );
}
