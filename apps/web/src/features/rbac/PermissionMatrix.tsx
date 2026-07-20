/**
 * The permission-matrix editor (t64-E6) — checkboxes over the frozen verb catalog
 * (`GET /v1/permissions`), grouped by verb family, for authoring a role's `permission_set`.
 *
 * ## Subset honesty (plan §2.2/§2.3, mirrored client-side; server is the real guard)
 * A user may only author a role whose permissions are a SUBSET of their OWN effective
 * permissions AT GLOBAL SCOPE (the basis the server uses for a role write). So a permission
 * the current user does not hold at Global is rendered **disabled-with-explanation** — a
 * checkbox they cannot tick, with an honest tooltip — never a tickable box that would imply
 * they can grant beyond themselves. The server re-checks and 403s regardless. An Owner (all
 * permissions) can tick everything.
 *
 * Meta-permissions (`role.*`/`delegation.*`) are flagged with a small "meta" badge (they are
 * non-delegable and administrative) but are otherwise ordinary selectable verbs subject to
 * the same subset rule.
 */
import { useMemo } from 'react';
import type { PermissionInfo } from '../../api/types';
import { useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { Badge, Button, Tooltip } from '../../ui';
import { scopeGlobal, useCan } from '../session/permissions';

/** Map a verb's family prefix (before the first dot) to a localized group header. */
const GROUP_LABEL: Record<string, MessageKey> = {
  entity: 'rbac.group.entity',
  book: 'rbac.group.book',
  act: 'rbac.group.act',
  signing: 'rbac.group.signing',
  document: 'rbac.group.document',
  ledger: 'rbac.group.ledger',
  data: 'rbac.group.data',
  settings: 'rbac.group.settings',
  cae: 'rbac.group.cae',
  law: 'rbac.group.law',
  user: 'rbac.group.user',
  role: 'rbac.group.role',
  delegation: 'rbac.group.delegation',
};

interface Group {
  prefix: string;
  labelKey: MessageKey;
  perms: PermissionInfo[];
}

/** Group the catalog by family prefix, preserving the catalog's declaration order both for
 *  the groups and within each group. */
function groupCatalog(catalog: PermissionInfo[]): Group[] {
  const order: string[] = [];
  const byPrefix = new Map<string, PermissionInfo[]>();
  for (const info of catalog) {
    const prefix = info.permission.split('.')[0] ?? info.permission;
    if (!byPrefix.has(prefix)) {
      byPrefix.set(prefix, []);
      order.push(prefix);
    }
    byPrefix.get(prefix)!.push(info);
  }
  return order.map((prefix) => ({
    prefix,
    labelKey: GROUP_LABEL[prefix] ?? 'rbac.group.other',
    perms: byPrefix.get(prefix)!,
  }));
}

export function PermissionMatrix({
  catalog,
  selected,
  onChange,
  disabled,
}: {
  catalog: PermissionInfo[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  disabled?: boolean;
}) {
  const t = useT();
  const can = useCan();
  const groups = useMemo(() => groupCatalog(catalog), [catalog]);

  // The subset basis: a permission is selectable iff the actor holds it at Global scope
  // (fail-closed — an unheld verb can never be ticked). Mirrors the server's role-write basis.
  const held = (permission: string) => can(permission, scopeGlobal);

  // Only the perms the actor actually holds can be bulk-selected/cleared.
  const selectableAll = catalog.filter((p) => held(p.permission)).map((p) => p.permission);

  function toggle(permission: string) {
    if (disabled || !held(permission)) return;
    const next = new Set(selected);
    if (next.has(permission)) next.delete(permission);
    else next.add(permission);
    onChange(next);
  }

  return (
    <div className="rbac-matrix">
      <div className="rbac-matrix__toolbar">
        <p className="field__hint">{t('rbac.role.subsetNote')}</p>
        <div className="row-wrap">
          <Button
            type="button"
            variant="ghost"
            disabled={disabled}
            onClick={() => onChange(new Set(selectableAll))}
          >
            {t('rbac.matrix.selectAll')}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={disabled}
            onClick={() => onChange(new Set())}
          >
            {t('rbac.matrix.clear')}
          </Button>
        </div>
      </div>

      {groups.map((group) => (
        <fieldset key={group.prefix} className="rbac-matrix__group">
          <legend className="rbac-matrix__legend">{t(group.labelKey)}</legend>
          <div className="rbac-matrix__perms">
            {group.perms.map((info) => {
              const canHold = held(info.permission);
              const checkbox = (
                <label
                  className={`rbac-matrix__perm${canHold ? '' : ' is-disabled'}`}
                  key={info.permission}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(info.permission)}
                    disabled={disabled || !canHold}
                    aria-disabled={!canHold}
                    onChange={() => toggle(info.permission)}
                  />
                  <code className="mono">{info.permission}</code>
                  {info.meta ? <Badge tone="warn">{t('rbac.matrix.meta')}</Badge> : null}
                </label>
              );
              // A verb the actor lacks is wrapped in an honest tooltip so the disabled box
              // is explained (hover + keyboard reachable via the label).
              return canHold ? (
                checkbox
              ) : (
                <Tooltip key={info.permission} label={t('rbac.matrix.notHeld')}>
                  {checkbox}
                </Tooltip>
              );
            })}
          </div>
        </fieldset>
      ))}
    </div>
  );
}
