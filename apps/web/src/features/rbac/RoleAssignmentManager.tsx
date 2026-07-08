/**
 * Scoped role assignment (t64-E6) — assign/unassign roles to one user at a scope
 * (Global / a specific entity / a specific book), surfaced on the user edit screen.
 *
 * ## Honest guards (server-enforced; the UI reflects, never widens)
 *  - **`role.assign` @ scope** gates the assign + per-row remove affordances
 *    (disable-with-explanation). The subset invariant (`role ⊆ your authority @ scope`) is
 *    re-checked server-side — a role carrying a permission you lack is refused (403).
 *  - **Last-Owner guard** — removing the final Owner\@Global assignment is refused by the
 *    server (409); we surface the server's honest message via the toast + an inline note.
 *
 * ## Reading current assignments
 * There is no read endpoint for ANOTHER user's assignments (the assign/unassign responses
 * are the source of truth). For the CURRENT user we seed from `GET /v1/session/permissions`;
 * for others the list is honestly empty until the operator makes a change (an explanatory
 * note says so), after which the server's echoed list is authoritative.
 */
import { useEffect, useState } from 'react';
import {
  useAssignRole,
  useRoles,
  useSession,
  useSessionPermissions,
  useUnassignRole,
} from '../../api/hooks';
import { useT } from '../../i18n';
import {
  Badge,
  Card,
  EmptyState,
  Field,
  Icon,
  InlineWarning,
  Select,
  Table,
  useToast,
} from '../../ui';
import { GateButton } from '../session/permissions';
import type { PermissionScope, RoleAssignmentView, UserView } from '../../api/types';
import { ScopePicker, useScopeLabel } from './ScopePicker';

/** Whether a scope carries a concrete target (an entity/book scope needs a chosen id). */
function scopeReady(scope: PermissionScope): boolean {
  return scope.kind === 'global' || scope.id !== '';
}

/** Stable identity key for a `(role, scope)` assignment (for de-dup + row keys). */
function assignmentKey(a: RoleAssignmentView): string {
  return `${a.role_id}@${a.scope.kind}:${a.scope.kind === 'global' ? '' : a.scope.id}`;
}

export function RoleAssignmentManager({ user }: { user: UserView }) {
  const t = useT();
  const toast = useToast();
  const roles = useRoles();
  const session = useSession();
  const scopeLabel = useScopeLabel();

  const isSelf = session.data?.user?.id === user.id;
  const sessionPerms = useSessionPermissions();
  const assign = useAssignRole(user.id);
  const unassign = useUnassignRole(user.id);

  // The shown assignment list. Seeded from the session view for one's own account; kept
  // authoritative from the assign/unassign responses afterwards. `null` = not-yet-known.
  const [assignments, setAssignments] = useState<RoleAssignmentView[] | null>(null);
  useEffect(() => {
    if (isSelf && assignments === null && sessionPerms.data) {
      setAssignments(sessionPerms.data.role_assignments);
    }
  }, [isSelf, assignments, sessionPerms.data]);

  // The assign form.
  const [roleId, setRoleId] = useState('');
  const [scope, setScope] = useState<PermissionScope>({ kind: 'global' });

  const roleList = roles.data ?? [];
  const effectiveRoleId = roleId || roleList[0]?.id || '';

  function roleName(id: string): string {
    return roleList.find((r) => r.id === id)?.name ?? id;
  }

  function submitAssign() {
    if (!effectiveRoleId || !scopeReady(scope)) return;
    assign.mutate(
      { role_id: effectiveRoleId, scope },
      {
        onSuccess: (list) => {
          setAssignments(list);
          toast.success(t('rbac.toast.assigned'));
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  function remove(a: RoleAssignmentView) {
    unassign.mutate(
      { role_id: a.role_id, scope: a.scope },
      {
        onSuccess: (list) => {
          setAssignments(list);
          toast.success(t('rbac.toast.unassigned'));
        },
        // A 409 (last-Owner guard) carries the server's honest PT message.
        onError: (e) => toast.error(e),
      },
    );
  }

  const busy = assign.isPending || unassign.isPending;
  const rows = assignments ?? [];

  return (
    <Card title={t('rbac.assign.title')}>
      <div className="stack">
        <p className="field__hint">{t('rbac.assign.lede')}</p>

        {/* Assign form -------------------------------------------------------- */}
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            submitAssign();
          }}
        >
          <Field label={t('rbac.assign.role.label')} htmlFor="rbac-assign-role">
            <Select
              id="rbac-assign-role"
              value={effectiveRoleId}
              onChange={(e) => setRoleId(e.target.value)}
              options={roleList.map((r) => ({ value: r.id, label: r.name }))}
            />
          </Field>

          <ScopePicker value={scope} onChange={setScope} idPrefix="rbac-assign-scope" />

          <div className="form__actions">
            <GateButton
              perm="role.assign"
              scope={scope}
              type="submit"
              variant="primary"
              icon={<Icon.Plus />}
              disabled={busy || !effectiveRoleId || !scopeReady(scope)}
            >
              {t('rbac.assign.submit')}
            </GateButton>
          </div>
        </form>

        {/* Current assignments ------------------------------------------------ */}
        {assignments === null && !isSelf ? (
          <InlineWarning tone="info">{t('rbac.assign.selfOnlyNote')}</InlineWarning>
        ) : rows.length === 0 ? (
          <EmptyState title={t('rbac.assign.empty')} />
        ) : (
          <Table
            head={
              <tr>
                <th>{t('rbac.assign.table.role')}</th>
                <th>{t('rbac.assign.table.scope')}</th>
                <th>{t('rbac.assign.table.action')}</th>
              </tr>
            }
          >
            {rows.map((a) => (
              <tr key={assignmentKey(a)}>
                <td>{roleName(a.role_id)}</td>
                <td>
                  <Badge tone="neutral">{scopeLabel(a.scope)}</Badge>
                </td>
                <td className="users-actions">
                  <GateButton
                    perm="role.assign"
                    scope={a.scope}
                    variant="ghost"
                    icon={<Icon.Trash />}
                    disabled={busy}
                    onClick={() => remove(a)}
                  >
                    {t('rbac.assign.remove')}
                  </GateButton>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </div>
    </Card>
  );
}
