/**
 * API keys — settings-hosted lifecycle UI for integration clients.
 *
 * The create/rotate endpoints return the plaintext secret once; this section copies it into
 * local component state only, shows it in an explicit "save now" panel, and clears mutation state
 * immediately after success so the metadata query cache never receives secret material.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import type {
  ApiKeyCreated,
  ApiKeyGrantView,
  ApiKeyRateLimit,
  ApiKeyView,
  PermissionInfo,
  PermissionScope,
} from '../../api/types';
import {
  useApiKeys,
  useCreateApiKey,
  usePermissionCatalog,
  useRevokeApiKey,
  useRotateApiKey,
} from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import {
  Badge,
  Button,
  Card,
  DateTime,
  EmptyState,
  ErrorNote,
  Field,
  Icon,
  InlineWarning,
  Input,
  SkeletonForm,
  SkeletonRegion,
  SkeletonTable,
  Table,
  useToast,
} from '../../ui';
import { GateButton, useCan } from '../session/permissions';
import { ScopePicker, scopeKindLabel } from '../rbac/ScopePicker';

const initialScope: PermissionScope = { kind: 'global' };

/** How long a once-shown secret may sit on the clipboard before we best-effort wipe it. */
const CLIPBOARD_CLEAR_MS = 60_000;

/**
 * Best-effort defense-in-depth: after {@link CLIPBOARD_CLEAR_MS}, wipe the clipboard IFF it still
 * holds exactly `secret`, so a once-shown secret does not linger indefinitely. Never throws, never
 * blocks, and never clears unrelated content — if clipboard read-back is unavailable or denied it
 * silently does nothing. The pending timer lives in `ref` so a new copy or an unmount can cancel it.
 */
function scheduleClipboardClear(
  ref: { current: ReturnType<typeof setTimeout> | null },
  secret: string,
): void {
  if (ref.current) clearTimeout(ref.current);
  ref.current = setTimeout(() => {
    ref.current = null;
    void (async () => {
      try {
        if (typeof navigator === 'undefined' || !navigator.clipboard?.readText) return;
        const current = await navigator.clipboard.readText();
        if (current === secret) await navigator.clipboard.writeText('');
      } catch {
        /* read-back unavailable or denied — leave the clipboard untouched */
      }
    })();
  }, CLIPBOARD_CLEAR_MS);
}

function scopeText(t: TFunction, scope: PermissionScope): string {
  if (scope.kind === 'global') return t('rbac.scope.global');
  return `${scopeKindLabel(t, scope.kind)}: ${scope.id}`;
}

function grantText(t: TFunction, grant: ApiKeyGrantView): string {
  if (grant.kind === 'role') {
    return `${t('settings.apiKeys.grant.role')} ${grant.role_id} @ ${scopeText(t, grant.scope)}`;
  }
  return `${t('settings.apiKeys.grant.permissions', {
    count: grant.permissions.length,
  })} @ ${scopeText(t, grant.scope)}`;
}

function rateLimitText(t: TFunction, rateLimit?: ApiKeyRateLimit): string {
  if (!rateLimit) return t('settings.apiKeys.rateLimit.default');
  return t('settings.apiKeys.rateLimit.value', {
    rpm: rateLimit.rpm,
    burst: rateLimit.burst,
  });
}

function scopeReady(scope: PermissionScope): boolean {
  return scope.kind === 'global' || scope.id.trim().length > 0;
}

function groupPermissions(catalog: PermissionInfo[]): { prefix: string; permissions: string[] }[] {
  const groups = new Map<string, string[]>();
  for (const info of catalog) {
    if (info.meta) continue;
    const prefix = info.permission.split('.')[0] ?? info.permission;
    const group = groups.get(prefix) ?? [];
    group.push(info.permission);
    groups.set(prefix, group);
  }
  return [...groups.entries()].map(([prefix, permissions]) => ({ prefix, permissions }));
}

function PermissionChecklist({
  catalog,
  scope,
  selected,
  onChange,
  disabled,
}: {
  catalog: PermissionInfo[];
  scope: PermissionScope;
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  disabled?: boolean;
}) {
  const t = useT();
  const can = useCan();
  const groups = useMemo(() => groupPermissions(catalog), [catalog]);
  const selectable = catalog
    .filter((p) => !p.meta && can(p.permission, scope))
    .map((p) => p.permission);

  function toggle(permission: string) {
    if (disabled || !can(permission, scope)) return;
    const next = new Set(selected);
    if (next.has(permission)) next.delete(permission);
    else next.add(permission);
    onChange(next);
  }

  if (groups.length === 0) {
    return <InlineWarning tone="info">{t('settings.apiKeys.permissions.empty')}</InlineWarning>;
  }

  return (
    <div className="api-key-permissions">
      <div className="api-key-permissions__toolbar">
        <p className="field__hint">{t('settings.apiKeys.permissions.hint')}</p>
        <div className="row-wrap">
          <Button
            type="button"
            variant="ghost"
            disabled={disabled || selectable.length === 0}
            onClick={() => onChange(new Set(selectable))}
          >
            {t('rbac.matrix.selectAll')}
          </Button>
          <Button
            type="button"
            variant="ghost"
            disabled={disabled || selected.size === 0}
            onClick={() => onChange(new Set())}
          >
            {t('rbac.matrix.clear')}
          </Button>
        </div>
      </div>

      {groups.map((group) => (
        <fieldset className="api-key-permissions__group" key={group.prefix}>
          <legend className="api-key-permissions__legend">{group.prefix}</legend>
          <div className="api-key-permissions__items">
            {group.permissions.map((permission) => {
              const allowed = can(permission, scope);
              return (
                <label
                  className={`api-key-permission${allowed ? '' : ' is-disabled'}`}
                  key={permission}
                >
                  <input
                    type="checkbox"
                    checked={selected.has(permission)}
                    disabled={disabled || !allowed}
                    onChange={() => toggle(permission)}
                  />
                  <code className="mono">{permission}</code>
                </label>
              );
            })}
          </div>
        </fieldset>
      ))}
    </div>
  );
}

function CreateApiKeyForm({
  onCreated,
  onCancel,
}: {
  onCreated: (created: ApiKeyCreated) => void;
  onCancel: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const catalog = usePermissionCatalog();
  const create = useCreateApiKey();
  const can = useCan();

  const [name, setName] = useState('');
  const [scope, setScope] = useState<PermissionScope>(initialScope);
  const [permissions, setPermissions] = useState<Set<string>>(() => new Set());
  const [expiresAt, setExpiresAt] = useState('');
  const [rpm, setRpm] = useState('');
  const [burst, setBurst] = useState('');

  const trimmed = name.trim();
  const selected = [...permissions];
  const rateLimitComplete = (rpm === '' && burst === '') || (rpm !== '' && burst !== '');
  const rateLimitValid =
    rateLimitComplete &&
    (rpm === '' ||
      (Number.isInteger(Number(rpm)) &&
        Number.isInteger(Number(burst)) &&
        Number(rpm) >= 0 &&
        Number(burst) >= 0));
  const selectedAllowed = selected.every((permission) => can(permission, scope));
  const canSubmit =
    trimmed.length > 0 &&
    selected.length > 0 &&
    selectedAllowed &&
    scopeReady(scope) &&
    rateLimitValid &&
    !create.isPending;

  function rateLimitBody(): ApiKeyRateLimit | undefined {
    if (rpm === '' && burst === '') return undefined;
    return { rpm: Number(rpm), burst: Number(burst) };
  }

  function submit() {
    if (!canSubmit) return;
    create.mutate(
      {
        name: trimmed,
        grant: { kind: 'permissions', permissions: selected, scope },
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
        rate_limit: rateLimitBody(),
      },
      {
        onSuccess: (created) => {
          onCreated(created);
          create.reset();
          toast.success(t('settings.apiKeys.createdToast'));
          onCancel();
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  // The permission catalog only gates the create form, so the placeholder is that form.
  if (catalog.isLoading)
    return (
      <Card title={t('settings.apiKeys.new')}>
        <SkeletonRegion>
          <SkeletonForm fields={4} className="settings-rows" />
        </SkeletonRegion>
      </Card>
    );
  if (catalog.error) return <ErrorNote error={catalog.error} />;

  return (
    <Card title={t('settings.apiKeys.new')}>
      <form
        className="form settings-rows"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <Field label={t('settings.apiKeys.name.label')} htmlFor="api-key-name">
          <Input
            id="api-key-name"
            value={name}
            placeholder={t('settings.apiKeys.name.placeholder')}
            onChange={(e) => setName(e.target.value)}
            autoComplete="off"
          />
        </Field>

        <ScopePicker value={scope} onChange={setScope} idPrefix="api-key-scope" />

        {/* Not a `Field`: the checklist is a group of checkboxes, not one control, so a
            `<label for>` has nothing to point at. Name the group with `aria-labelledby`
            instead, so the label is actually announced with it. */}
        <div className="field" role="group" aria-labelledby="api-key-permissions-label">
          <span className="field__label" id="api-key-permissions-label">
            {t('settings.apiKeys.permissions.label')}
          </span>
          <PermissionChecklist
            catalog={catalog.data?.permissions ?? []}
            scope={scope}
            selected={permissions}
            onChange={setPermissions}
            disabled={create.isPending}
          />
        </div>

        <Field
          label={t('settings.apiKeys.expiry.label')}
          htmlFor="api-key-expiry"
          hint={t('settings.apiKeys.expiry.hint')}
        >
          <Input
            id="api-key-expiry"
            type="datetime-local"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        </Field>

        <div className="api-key-rate-grid">
          <Field
            label={t('settings.apiKeys.rateLimit.rpm')}
            htmlFor="api-key-rpm"
            hint={t('settings.apiKeys.rateLimit.hint')}
            error={!rateLimitComplete ? t('settings.apiKeys.rateLimit.incomplete') : undefined}
          >
            <Input
              id="api-key-rpm"
              type="number"
              min={0}
              step={1}
              value={rpm}
              onChange={(e) => setRpm(e.target.value)}
            />
          </Field>
          <Field label={t('settings.apiKeys.rateLimit.burst')} htmlFor="api-key-burst">
            <Input
              id="api-key-burst"
              type="number"
              min={0}
              step={1}
              value={burst}
              onChange={(e) => setBurst(e.target.value)}
            />
          </Field>
        </div>

        <div className="form__actions">
          <Button type="button" variant="ghost" disabled={create.isPending} onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <GateButton
            perm="user.manage"
            type="submit"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={!canSubmit}
          >
            {create.isPending ? t('settings.apiKeys.creating') : t('settings.apiKeys.submit')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

function SecretPanel({ apiKey, onDone }: { apiKey: ApiKeyCreated; onDone: () => void }) {
  const t = useT();
  const toast = useToast();
  const clearTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Cancel any pending clipboard wipe when the panel unmounts.
  useEffect(() => {
    const timerRef = clearTimerRef;
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  async function copySecret() {
    try {
      await navigator.clipboard.writeText(apiKey.secret);
      toast.success(t('settings.apiKeys.secret.copied'));
      scheduleClipboardClear(clearTimerRef, apiKey.secret);
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <InlineWarning tone="warn" title={t('settings.apiKeys.secret.title')}>
      <div className="api-key-secret">
        <p>{t('settings.apiKeys.secret.body')}</p>
        <div className="api-key-secret__value">
          <code className="mono">{apiKey.secret}</code>
          <Button type="button" variant="secondary" icon={<Icon.Copy />} onClick={copySecret}>
            {t('ui.digest.copy')}
          </Button>
        </div>
        <dl className="deflist">
          <div>
            <dt>{t('settings.apiKeys.table.name')}</dt>
            <dd>{apiKey.name}</dd>
          </div>
          <div>
            <dt>{t('settings.apiKeys.table.prefix')}</dt>
            <dd className="mono">{apiKey.prefix}</dd>
          </div>
          <div>
            <dt>{t('settings.apiKeys.table.rateLimit')}</dt>
            <dd>{rateLimitText(t, apiKey.rate_limit)}</dd>
          </div>
        </dl>
        <div className="form__actions">
          <Button type="button" variant="primary" icon={<Icon.Check />} onClick={onDone}>
            {t('settings.apiKeys.secret.done')}
          </Button>
        </div>
      </div>
    </InlineWarning>
  );
}

function ApiKeyRow({
  keyView,
  onSecretIssued,
}: {
  keyView: ApiKeyView;
  onSecretIssued: (apiKey: ApiKeyCreated) => void;
}) {
  const t = useT();
  const toast = useToast();
  const revoke = useRevokeApiKey();
  const rotate = useRotateApiKey();
  const [confirming, setConfirming] = useState(false);

  const status = keyView.revoked ? 'revoked' : keyView.active ? 'active' : 'inactive';
  const statusBadge =
    status === 'active' ? (
      <Badge tone="ok">{t('settings.apiKeys.status.active')}</Badge>
    ) : status === 'revoked' ? (
      <Badge tone="warn">{t('settings.apiKeys.status.revoked')}</Badge>
    ) : (
      <Badge tone="neutral">{t('settings.apiKeys.status.inactive')}</Badge>
    );

  function doRevoke() {
    revoke.mutate(keyView.id, {
      onSuccess: () => {
        toast.success(t('settings.apiKeys.revokedToast'));
        setConfirming(false);
      },
      onError: (e) => {
        toast.error(e);
        setConfirming(false);
      },
    });
  }

  function doRotate() {
    rotate.mutate(keyView.id, {
      onSuccess: (rotated) => {
        onSecretIssued(rotated);
        rotate.reset();
        toast.success(t('settings.apiKeys.rotatedToast'));
      },
      onError: (e) => toast.error(e),
    });
  }

  return (
    <tr>
      <td>{keyView.name}</td>
      <td>
        <code className="mono">{keyView.prefix}</code>
      </td>
      <td>{grantText(t, keyView.grant)}</td>
      <td>
        <DateTime value={keyView.created_at} />
      </td>
      {/* A key with no expiry is not a missing date — it never expires — so it keeps its own
          wording instead of falling through to the em-dash placeholder. */}
      <td>
        {keyView.expires_at ? (
          <DateTime value={keyView.expires_at} />
        ) : (
          t('settings.apiKeys.expires.never')
        )}
      </td>
      <td>{statusBadge}</td>
      <td>{rateLimitText(t, keyView.rate_limit)}</td>
      <td className="users-actions">
        {keyView.revoked ? (
          <span className="muted">—</span>
        ) : confirming ? (
          <span className="row-wrap">
            <Button
              type="button"
              variant="ghost"
              disabled={revoke.isPending}
              onClick={() => setConfirming(false)}
            >
              {t('common.cancel')}
            </Button>
            <GateButton
              perm="user.manage"
              variant="primary"
              icon={<Icon.Trash />}
              disabled={revoke.isPending}
              onClick={doRevoke}
            >
              {revoke.isPending
                ? t('settings.apiKeys.revoking')
                : t('settings.apiKeys.revokeConfirm')}
            </GateButton>
          </span>
        ) : (
          <span className="row-wrap">
            <GateButton
              perm="user.manage"
              type="button"
              variant="ghost"
              icon={<Icon.Refresh />}
              disabled={rotate.isPending || revoke.isPending}
              onClick={doRotate}
            >
              {rotate.isPending ? t('settings.apiKeys.rotating') : t('settings.apiKeys.rotate')}
            </GateButton>
            <GateButton
              perm="user.manage"
              type="button"
              variant="ghost"
              icon={<Icon.Trash />}
              disabled={revoke.isPending || rotate.isPending}
              onClick={() => setConfirming(true)}
            >
              {t('settings.apiKeys.revoke')}
            </GateButton>
          </span>
        )}
      </td>
    </tr>
  );
}

export function ApiKeysSection() {
  const t = useT();
  const keys = useApiKeys();
  const [creating, setCreating] = useState(false);
  const [issuedSecret, setIssuedSecret] = useState<ApiKeyCreated | null>(null);

  // Eight columns: name, prefix, grant, created, expires, status, rate limit, action.
  if (keys.isLoading)
    return (
      <div className="stack">
        <Card title={t('settings.apiKeys.cardTitle')}>
          <SkeletonRegion>
            <SkeletonTable cols={8} />
          </SkeletonRegion>
        </Card>
      </div>
    );
  if (keys.error) return <ErrorNote error={keys.error} />;

  const list = keys.data ?? [];

  return (
    <div className="stack">
      {issuedSecret ? (
        <SecretPanel apiKey={issuedSecret} onDone={() => setIssuedSecret(null)} />
      ) : null}

      {creating ? (
        <CreateApiKeyForm onCreated={setIssuedSecret} onCancel={() => setCreating(false)} />
      ) : (
        <Card
          title={t('settings.apiKeys.cardTitle')}
          actions={
            <GateButton
              perm="user.manage"
              variant="primary"
              icon={<Icon.Plus />}
              onClick={() => setCreating(true)}
            >
              {t('settings.apiKeys.new')}
            </GateButton>
          }
        >
          <p className="field__hint">{t('settings.apiKeys.lede')}</p>
          {list.length === 0 ? (
            <EmptyState title={t('settings.apiKeys.empty')}>
              <p>{t('settings.apiKeys.emptyBody')}</p>
            </EmptyState>
          ) : (
            <Table
              head={
                <tr>
                  <th>{t('settings.apiKeys.table.name')}</th>
                  <th>{t('settings.apiKeys.table.prefix')}</th>
                  <th>{t('settings.apiKeys.table.grant')}</th>
                  <th>{t('settings.apiKeys.table.created')}</th>
                  <th>{t('settings.apiKeys.table.expires')}</th>
                  <th>{t('settings.apiKeys.table.status')}</th>
                  <th>{t('settings.apiKeys.table.rateLimit')}</th>
                  <th>{t('settings.apiKeys.table.action')}</th>
                </tr>
              }
            >
              {list.map((key) => (
                <ApiKeyRow key={key.id} keyView={key} onSecretIssued={setIssuedSecret} />
              ))}
            </Table>
          )}
        </Card>
      )}
    </div>
  );
}
