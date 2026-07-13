/**
 * Funções e permissões (t64-E6) — the roles view: list the custom + seeded roles
 * (`GET /v1/roles`) with the permission catalog (`GET /v1/permissions`), create a custom role
 * and edit its name + permission_set through the {@link PermissionMatrix}, and delete
 * non-protected roles.
 *
 * ## Honest guards (the server is the real gate; this UI reflects it, never widens it)
 *  - **Protected-Owner** — the Owner (and any `protected`) role is read-only: its permission
 *    set is shown but Edit/Delete are not offered (the server 403s any such write anyway).
 *  - **Subset invariant** — the matrix only lets you tick permissions you yourself hold at
 *    Global scope; the server re-enforces `role.permission_set ⊆ your own perms` and 403s
 *    otherwise (surfaced honestly via the shared 403 handling).
 *  - **`role.manage`** gates every mutating affordance (create / edit / delete) as
 *    disable-with-explanation.
 *
 * Reused by t62 (admin UI) — kept a self-contained section with its own Card chrome so it
 * drops into either the Configurações sub-tab host or the admin host.
 */
import { useMemo, useState } from 'react';
import {
  useApplySeededRoleReconciliation,
  useCreateRole,
  useDeleteRole,
  usePatchRole,
  usePermissionCatalog,
  useRoles,
  useSeededRoleReconciliationProposal,
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
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { GateButton, useCan } from '../session/permissions';
import type { PermissionInfo, RoleView, SeededRoleReconciliationView } from '../../api/types';
import { PermissionMatrix } from './PermissionMatrix';

/** The role editor form (shared by create + edit). Owns the name + selected-permission draft. */
function RoleEditor({
  catalog,
  initial,
  onCancel,
  onDone,
}: {
  catalog: PermissionInfo[];
  /** The role being edited, or `null` for a fresh create. */
  initial: RoleView | null;
  onCancel: () => void;
  onDone: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const create = useCreateRole();
  const patch = usePatchRole(initial?.id ?? '');
  const [name, setName] = useState(initial?.name ?? '');
  const [selected, setSelected] = useState<Set<string>>(() => new Set(initial?.permissions ?? []));

  const busy = create.isPending || patch.isPending;
  const trimmed = name.trim();
  const canSubmit = trimmed.length > 0 && !busy;

  function submit() {
    const permissions = [...selected];
    if (initial) {
      patch.mutate(
        { name: trimmed, permissions },
        {
          onSuccess: () => {
            toast.success(t('rbac.toast.roleUpdated'));
            onDone();
          },
          onError: (e) => toast.error(e),
        },
      );
    } else {
      create.mutate(
        { name: trimmed, permissions },
        {
          onSuccess: () => {
            toast.success(t('rbac.toast.roleCreated'));
            onDone();
          },
          onError: (e) => toast.error(e),
        },
      );
    }
  }

  return (
    <Card title={initial ? t('rbac.role.edit.title') : t('rbac.role.create.title')}>
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label={t('rbac.role.name.label')} htmlFor="rbac-role-name">
          <Input
            id="rbac-role-name"
            value={name}
            placeholder={t('rbac.role.name.placeholder')}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
          />
        </Field>

        <Field label={t('rbac.role.permissions.label')} htmlFor="">
          <PermissionMatrix catalog={catalog} selected={selected} onChange={setSelected} />
        </Field>

        <div className="form__actions">
          <Button type="button" variant="ghost" disabled={busy} onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" disabled={!canSubmit}>
            {busy ? t('common.saving') : initial ? t('common.save') : t('rbac.role.create.submit')}
          </Button>
        </div>
      </form>
    </Card>
  );
}

function RoleDriftStatus({ role }: { role: RoleView }) {
  const drift = role.seeded_role_drift;
  if (!drift) return <span className="muted">-</span>;
  if (!drift.requires_manual_review || drift.missing_default_permissions.length === 0) {
    return <span className="muted">Atual</span>;
  }
  return (
    <span className="row-wrap">
      <Badge tone="warn">Revisão manual</Badge>
      <span className="muted">
        Defaults em falta: {drift.missing_default_permissions.join(', ')}. A reconciliação é
        guiada por admin e só adiciona estes defaults semeados.
      </span>
    </span>
  );
}

/** One role row: name, protected badge, permission count, and (for non-protected roles)
 *  gated Edit + Delete affordances. Delete uses an inline two-step confirm. */
function RoleRow({ role, onEdit }: { role: RoleView; onEdit: (role: RoleView) => void }) {
  const t = useT();
  const toast = useToast();
  const del = useDeleteRole();
  const reconciliationProposal = useSeededRoleReconciliationProposal();
  const reconcile = useApplySeededRoleReconciliation();
  const [confirming, setConfirming] = useState(false);
  const [reviewedReconciliation, setReviewedReconciliation] =
    useState<SeededRoleReconciliationView | null>(null);
  const missingSeededDefaults = role.seeded_role_drift?.missing_default_permissions ?? [];
  const hasSeededDrift =
    !role.protected &&
    role.seeded_role_drift?.requires_manual_review &&
    missingSeededDefaults.length > 0;

  function remove() {
    del.mutate(role.id, {
      onSuccess: () => {
        toast.success(t('rbac.toast.roleDeleted'));
        setConfirming(false);
      },
      onError: (e) => {
        toast.error(e);
        setConfirming(false);
      },
    });
  }

  function applyReconciliation() {
    reconcile.mutate(role.id, {
      onSuccess: (result) => {
        toast.success(
          result.applied
            ? `Reconciliação aplicada: ${result.applied_permissions.join(', ')}`
            : 'A função já não tem defaults semeados em falta',
        );
        setReviewedReconciliation(null);
      },
      onError: (e) => {
        toast.error(e);
        setReviewedReconciliation(null);
      },
    });
  }

  function reviewReconciliation() {
    reconciliationProposal.mutate(role.id, {
      onSuccess: (proposal) => {
        if (!proposal.requires_manual_review || proposal.missing_default_permissions.length === 0) {
          toast.success('A função já não tem defaults semeados em falta');
          return;
        }
        setConfirming(false);
        setReviewedReconciliation(proposal);
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <tr>
      <td>
        {role.name}
        {role.protected ? (
          <>
            {' '}
            <Badge tone="accent">{t('rbac.roles.protected')}</Badge>
          </>
        ) : null}
      </td>
      <td>{t('rbac.roles.permissionsCount', { count: role.permissions.length })}</td>
      <td>
        <RoleDriftStatus role={role} />
      </td>
      <td className="users-actions">
        {role.protected ? (
          <span className="muted">{t('rbac.roles.readonly')}</span>
        ) : confirming ? (
          <span className="row-wrap">
            <Button
              type="button"
              variant="ghost"
              disabled={del.isPending}
              onClick={() => setConfirming(false)}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="role.manage"
              variant="primary"
              icon={<Icon.Trash />}
              disabled={del.isPending}
              onClick={remove}
            >
              {t('rbac.roles.deleteConfirm')}
            </GateButton>
          </span>
        ) : reviewedReconciliation ? (
          <span className="row-wrap">
            <span className="muted">
              Adicionar só: {reviewedReconciliation.missing_default_permissions.join(', ')}
            </span>
            <Button
              type="button"
              variant="ghost"
              disabled={reconcile.isPending}
              onClick={() => setReviewedReconciliation(null)}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="role.manage"
              variant="primary"
              icon={<Icon.Refresh />}
              disabled={reconcile.isPending}
              onClick={applyReconciliation}
            >
              Aplicar defaults em falta
            </GateButton>
          </span>
        ) : (
          <span className="row-wrap">
            <GateButton
              perm="role.manage"
              variant="secondary"
              icon={<Icon.Pencil />}
              onClick={() => onEdit(role)}
            >
              {t('rbac.roles.edit')}
            </GateButton>
            <GateButton
              perm="role.manage"
              variant="ghost"
              icon={<Icon.Trash />}
              onClick={() => setConfirming(true)}
            >
              {t('rbac.roles.delete')}
            </GateButton>
            {hasSeededDrift ? (
              <GateButton
                perm="role.manage"
                variant="secondary"
                icon={<Icon.Refresh />}
                disabled={reconciliationProposal.isPending || reconcile.isPending}
                onClick={reviewReconciliation}
              >
                Rever defaults
              </GateButton>
            ) : null}
          </span>
        )}
      </td>
    </tr>
  );
}

type EditorState = { mode: 'create' } | { mode: 'edit'; role: RoleView } | null;

export function FuncoesSection() {
  const t = useT();
  const roles = useRoles();
  const catalog = usePermissionCatalog();
  const can = useCan();
  const [editor, setEditor] = useState<EditorState>(null);

  const perms = useMemo(() => catalog.data?.permissions ?? [], [catalog.data]);
  const canManage = can('role.manage');

  if (roles.isLoading || catalog.isLoading) return <SkeletonTable rows={4} cols={4} />;
  if (roles.error) return <ErrorNote error={roles.error} />;
  if (catalog.error) return <ErrorNote error={catalog.error} />;

  const list = roles.data ?? [];

  return (
    <div className="stack">
      {!canManage ? (
        <InlineWarning tone="info" title={t('perm.denied.title')}>
          {t('rbac.roles.readonlyNote')}
        </InlineWarning>
      ) : null}

      {editor ? (
        <RoleEditor
          catalog={perms}
          initial={editor.mode === 'edit' ? editor.role : null}
          onCancel={() => setEditor(null)}
          onDone={() => setEditor(null)}
        />
      ) : (
        <Card
          title={t('rbac.roles.cardTitle')}
          actions={
            <GateButton
              perm="role.manage"
              variant="primary"
              icon={<Icon.Plus />}
              onClick={() => setEditor({ mode: 'create' })}
            >
              {t('rbac.roles.new')}
            </GateButton>
          }
        >
          <p className="field__hint">{t('rbac.roles.protectedNote')}</p>
          {list.length === 0 ? (
            <EmptyState title={t('rbac.roles.empty')}>
              <p>{t('rbac.roles.emptyBody')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('rbac.roles.table.name')}</th>
                  <th>{t('rbac.roles.table.permissions')}</th>
                  <th>Estado</th>
                  <th>{t('rbac.roles.table.action')}</th>
                </tr>
              }
            >
              {list.map((role) => (
                <RoleRow
                  key={role.id}
                  role={role}
                  onEdit={(r) => setEditor({ mode: 'edit', role: r })}
                />
              ))}
            </Table>
          )}
        </Card>
      )}
    </div>
  );
}
