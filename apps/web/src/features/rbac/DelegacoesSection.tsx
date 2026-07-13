/**
 * Delegações (t64-E6) — the scoped-delegation view: list the delegations touching you
 * (`GET /v1/delegations`), grant one (`POST /v1/delegations`) and revoke one
 * (`DELETE /v1/delegations/{id}`).
 *
 * ## Honest guards (server-enforced; the UI reflects, never widens)
 *  - **`delegation.grant` @ scope** gates the grant affordance (disable-with-explanation).
 *  - **Delegate only what you hold via a ROLE** — the permission picker offers only the
 *    non-meta permissions you hold via a role (mirrors `can_delegate`); the server re-checks
 *    hold-via-role at the scope and 403s otherwise (no escalation, no re-delegation).
 *  - **Meta-permissions are non-delegable** — excluded from the picker (the server hard-blocks
 *    them too).
 *  - **Revoke** — allowed to the grantor OR a `delegation.revoke` holder; a non-grantor
 *    without the verb sees the control disabled-with-explanation.
 *
 * Active vs expired/revoked is shown per row (an expired or revoked delegation contributes
 * nothing — the server re-checks; this is honest display only). Reused by t62.
 */
import { useMemo, useState } from 'react';
import {
  useDelegations,
  useGrantDelegation,
  usePermissionCatalog,
  useRevokeDelegation,
  useSession,
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
  InlineWarning,
  Input,
  Select,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { GateButton, usePermissions, useCan } from '../session/permissions';
import type { DelegationView, PermissionScope } from '../../api/types';
import { ScopePicker, useScopeLabel } from './ScopePicker';

type DelegStatus = 'active' | 'expired' | 'revoked';

/** Derive a delegation's status: revoked wins, then an elapsed expiry, else active. */
function statusOf(d: DelegationView, now: number): DelegStatus {
  if (d.revoked) return 'revoked';
  if (d.expires_at && Date.parse(d.expires_at) <= now) return 'expired';
  return 'active';
}

/** The grant form. Split out so its own hooks (scope/permission drafts) stay local. */
function GrantForm({ onClose }: { onClose: () => void }) {
  const t = useT();
  const toast = useToast();
  const users = useUsers();
  const session = useSession();
  const catalog = usePermissionCatalog();
  const { grants } = usePermissions();
  const grant = useGrantDelegation();

  const selfId = session.data?.user?.id;
  const [to, setTo] = useState('');
  const [permission, setPermission] = useState('');
  const [scope, setScope] = useState<PermissionScope>({ kind: 'global' });
  const [expiry, setExpiry] = useState('');

  // The non-meta permissions the current user holds VIA A ROLE — the only delegable set
  // (mirrors `can_delegate`; the server re-checks hold-via-role at the chosen scope).
  const metaSet = useMemo(
    () => new Set((catalog.data?.permissions ?? []).filter((p) => p.meta).map((p) => p.permission)),
    [catalog.data],
  );
  const delegable = useMemo(() => {
    const held = new Set<string>();
    for (const g of grants) {
      if (g.source === 'role' && !metaSet.has(g.permission)) held.add(g.permission);
    }
    return [...held].sort();
  }, [grants, metaSet]);

  const granteeOptions = (users.data ?? [])
    .filter((u) => u.active && u.id !== selfId)
    .map((u) => ({ value: u.id, label: `${u.display_name} (${u.username})` }));

  const effectiveTo = to || granteeOptions[0]?.value || '';
  const effectivePerm = permission || delegable[0] || '';
  const scopeOk = scope.kind === 'global' || scope.id !== '';
  const canSubmit =
    !!effectiveTo && !!effectivePerm && scopeOk && !grant.isPending && delegable.length > 0;

  function submit() {
    if (!canSubmit) return;
    // datetime-local (local wall-clock) → an RFC-3339 instant the server parses; omit if unset.
    const expires_at = expiry ? new Date(expiry).toISOString() : undefined;
    grant.mutate(
      { to: effectiveTo, permission: effectivePerm, scope, expires_at },
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
        className="form"
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

        <Field label={t('rbac.deleg.permission.label')} htmlFor="rbac-deleg-perm">
          <Select
            id="rbac-deleg-perm"
            value={effectivePerm}
            onChange={(e) => setPermission(e.target.value)}
            options={delegable.map((p) => ({ value: p, label: p }))}
          />
        </Field>

        <ScopePicker value={scope} onChange={setScope} idPrefix="rbac-deleg-scope" />

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

/** One delegation row with a status badge + a (grantor-or-`delegation.revoke`) revoke. */
function DelegationRow({ d, now }: { d: DelegationView; now: number }) {
  const t = useT();
  const toast = useToast();
  const users = useUsers();
  const session = useSession();
  const can = useCan();
  const scopeLabel = useScopeLabel();
  const revoke = useRevokeDelegation();

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

  const isGrantor = d.from === selfId;
  const statusBadge =
    status === 'active' ? (
      <Badge tone="ok">{t('rbac.deleg.status.active')}</Badge>
    ) : status === 'expired' ? (
      <Badge tone="neutral">{t('rbac.deleg.status.expired')}</Badge>
    ) : (
      <Badge tone="warn">{t('rbac.deleg.status.revoked')}</Badge>
    );

  return (
    <tr>
      <td>
        <code className="mono">{d.permission}</code>
      </td>
      <td>{userName(d.from)}</td>
      <td>{userName(d.to)}</td>
      <td>
        <Badge tone="neutral">{scopeLabel(d.scope)}</Badge>
      </td>
      <td>{statusBadge}</td>
      <td>
        {d.expires_at ? d.expires_at : <span className="muted">{t('rbac.deleg.noExpiry')}</span>}
      </td>
      <td className="users-actions">
        {d.revoked ? (
          <span className="muted">—</span>
        ) : isGrantor ? (
          // The grantor may always revoke their own grant (server allows the grantor bypass).
          <Button
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={revoke.isPending}
            onClick={doRevoke}
          >
            {t('rbac.deleg.revoke')}
          </Button>
        ) : (
          // Otherwise it needs `delegation.revoke` at the delegation's scope.
          <GateButton
            perm="delegation.revoke"
            scope={d.scope}
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={revoke.isPending || !can('delegation.revoke', d.scope)}
            onClick={doRevoke}
          >
            {t('rbac.deleg.revoke')}
          </GateButton>
        )}
      </td>
    </tr>
  );
}

export function DelegacoesSection() {
  const t = useT();
  const delegations = useDelegations();
  const [granting, setGranting] = useState(false);
  // A single "now" per render so every row's expiry compares against the same instant.
  const now = Date.now();

  if (delegations.isLoading) return <SkeletonTable rows={4} cols={7} />;
  if (delegations.error) return <ErrorNote error={delegations.error} />;

  const list = delegations.data ?? [];

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
            <Table
              head={
                <tr>
                  <th>{t('rbac.deleg.table.permission')}</th>
                  <th>{t('rbac.deleg.table.from')}</th>
                  <th>{t('rbac.deleg.table.to')}</th>
                  <th>{t('rbac.deleg.table.scope')}</th>
                  <th>{t('rbac.deleg.table.status')}</th>
                  <th>{t('rbac.deleg.table.expiry')}</th>
                  <th>{t('rbac.deleg.table.action')}</th>
                </tr>
              }
            >
              {list.map((d) => (
                <DelegationRow key={d.id} d={d} now={now} />
              ))}
            </Table>
          )}
        </Card>
      )}
    </div>
  );
}
