/**
 * Fornecedores de assinatura — operator management of the encrypted provider-credential
 * store (wp13 Phase D). It drives the multi-key / priority-failover / per-provider
 * endpoint + HTTP-auth / configurable-PKCS#12 backend
 * (`/v1/signature/provider-credentials`).
 *
 * Security posture mirrors the backend (plan §3/§6): secrets are WRITE-ONLY. Every secret
 * input is `type="password"`, `autoComplete="off"`, never pre-filled (the API never returns
 * a value — only a per-field `configured` flag), lives solely in component-local `useState`,
 * and is cleared on submit so it is never written into the react-query cache. The protection
 * level is surfaced honestly (obfuscation vs confidential); a strict + non-confidential store
 * disables the secret-writing controls with the same remedy the server would answer with.
 *
 * Mirrors the `ApiKeysSection` idioms: `Card`/`Field`/`Input`/`GateButton`, disabled+pending
 * mutating controls (CONVENTIONS §5), inline error + toast (§2), `EmptyState` when empty, and
 * RBAC-gated on `settings.manage` (the same permission the backend writes require).
 */
import { useMemo, useState } from 'react';
import type {
  CredentialMode,
  CreateProviderCredentialEntryBody,
  ProviderCredentialEntryView,
  ProviderCredentialGroupView,
  UpdateProviderCredentialEntryBody,
} from '../../api/types';
import {
  useProviderCredentials,
  useCreateProviderCredentialEntry,
  useUpdateProviderCredentialEntry,
  useDeleteProviderCredentialEntry,
  useReorderProviderCredentialEntries,
} from '../../api/hooks';
import { useT, type TFunction } from '../../i18n';
import type { MessageKey } from '../../i18n';
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
  Loading,
  Select,
  Toggle,
  useToast,
} from '../../ui';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { GateButton, GateIconButton, useCan } from '../session/permissions';

/** The modes an operator can configure, in display order. */
const MODES: CredentialMode[] = ['cmd', 'csc', 'scap', 'pkcs12'];

/** Modes that carry a per-entry endpoint / base_url override. */
const ENDPOINT_MODES: readonly CredentialMode[] = ['csc', 'scap'];

/** Modes that require a real (non-empty) provider id; the rest are single-instance. */
const MULTI_INSTANCE_MODES: readonly CredentialMode[] = ['csc', 'pkcs12'];

interface SecretFieldSpec {
  name: string;
  labelKey: MessageKey;
  /** `type="password"` for a genuinely secret value; ids/usernames are text but still write-only. */
  password: boolean;
}

type SelectorKind = 'text' | 'env' | 'authorization' | 'toggle';

interface SelectorFieldSpec {
  name: string;
  labelKey: MessageKey;
  kind: SelectorKind;
}

/** Per-mode encrypted (write-only) secret fields. `pfx_der` is handled separately (file → base64). */
const SECRET_FIELDS: Record<CredentialMode, SecretFieldSpec[]> = {
  cmd: [
    { name: 'application_id', labelKey: 'settings.providerCredentials.field.applicationId', password: false },
    { name: 'http_basic_username', labelKey: 'settings.providerCredentials.field.httpBasicUsername', password: false },
    { name: 'http_basic_password', labelKey: 'settings.providerCredentials.field.httpBasicPassword', password: true },
    { name: 'ama_cert_pem', labelKey: 'settings.providerCredentials.field.amaCertPem', password: true },
  ],
  csc: [
    { name: 'client_id', labelKey: 'settings.providerCredentials.field.clientId', password: false },
    { name: 'client_secret', labelKey: 'settings.providerCredentials.field.clientSecret', password: true },
    { name: 'access_token', labelKey: 'settings.providerCredentials.field.accessToken', password: true },
    { name: 'http_basic_username', labelKey: 'settings.providerCredentials.field.httpBasicUsername', password: false },
    { name: 'http_basic_password', labelKey: 'settings.providerCredentials.field.httpBasicPassword', password: true },
  ],
  scap: [
    { name: 'application_id', labelKey: 'settings.providerCredentials.field.applicationId', password: false },
    { name: 'secret', labelKey: 'settings.providerCredentials.field.secret', password: true },
    { name: 'http_basic_username', labelKey: 'settings.providerCredentials.field.httpBasicUsername', password: false },
    { name: 'http_basic_password', labelKey: 'settings.providerCredentials.field.httpBasicPassword', password: true },
  ],
  pkcs12: [{ name: 'passphrase', labelKey: 'settings.providerCredentials.field.passphrase', password: true }],
};

/** Per-mode NON-secret selectors, persisted plainly and returned in responses. */
const SELECTOR_FIELDS: Record<CredentialMode, SelectorFieldSpec[]> = {
  cmd: [{ name: 'env', labelKey: 'settings.providerCredentials.field.env', kind: 'env' }],
  csc: [
    { name: 'authorization', labelKey: 'settings.providerCredentials.field.authorization', kind: 'authorization' },
    { name: 'credential_id', labelKey: 'settings.providerCredentials.field.credentialId', kind: 'text' },
    { name: 'scope', labelKey: 'settings.providerCredentials.field.scope', kind: 'text' },
    { name: 'sandbox', labelKey: 'settings.providerCredentials.field.sandbox', kind: 'toggle' },
  ],
  scap: [{ name: 'environment', labelKey: 'settings.providerCredentials.field.environment', kind: 'env' }],
  pkcs12: [
    { name: 'friendly_name', labelKey: 'settings.providerCredentials.field.friendlyName', kind: 'text' },
    { name: 'local_key_id_hex', labelKey: 'settings.providerCredentials.field.localKeyId', kind: 'text' },
  ],
};

function modeLabel(t: TFunction, mode: CredentialMode): string {
  return t(`settings.providerCredentials.mode.${mode}` as MessageKey);
}

/** Read a File as a base64 string (no data: prefix) for the PKCS#12 upload. */
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error('file read failed'));
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== 'string') {
        reject(new Error('unexpected file read result'));
        return;
      }
      // `data:...;base64,<payload>` → keep only the payload.
      const comma = result.indexOf(',');
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.readAsDataURL(file);
  });
}

function ProtectionBanner({
  strict,
  level,
}: {
  strict: boolean;
  level: 'confidential' | 'obfuscation' | undefined;
}) {
  const t = useT();
  const blocked = strict && level !== 'confidential';
  if (level === 'confidential') {
    return (
      <InlineWarning tone="info" title={t('settings.providerCredentials.protection.confidential.title')}>
        {t('settings.providerCredentials.protection.confidential.body')}
      </InlineWarning>
    );
  }
  return (
    <InlineWarning
      tone={blocked ? 'error' : 'warn'}
      title={t('settings.providerCredentials.protection.obfuscation.title')}
    >
      <p>{t('settings.providerCredentials.protection.obfuscation.body')}</p>
      {blocked ? <p>{t('settings.providerCredentials.protection.strictBlocked')}</p> : null}
    </InlineWarning>
  );
}

interface EntryFormState {
  mode: CredentialMode;
  providerId: string;
  label: string;
  enabled: boolean;
  endpoint: string;
  selectors: Record<string, string>;
  secrets: Record<string, string>;
  pfxBase64: string;
  pfxName: string;
}

function emptyForm(mode: CredentialMode): EntryFormState {
  return {
    mode,
    providerId: '',
    label: '',
    enabled: true,
    endpoint: '',
    selectors: {},
    secrets: {},
    pfxBase64: '',
    pfxName: '',
  };
}

function EntryForm({
  mode,
  providerId,
  existing,
  disabled,
  onDone,
  onCancel,
}: {
  mode: CredentialMode;
  /** Fixed provider id when adding to an existing group or editing; undefined = choose. */
  providerId?: string;
  existing?: ProviderCredentialEntryView;
  disabled: boolean;
  onDone: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const create = useCreateProviderCredentialEntry();
  const update = useUpdateProviderCredentialEntry();
  const isEdit = !!existing;

  const [form, setForm] = useState<EntryFormState>(() => {
    const base = emptyForm(mode);
    if (existing) {
      base.label = existing.label;
      base.enabled = existing.enabled;
      base.endpoint = existing.endpoint ?? '';
      base.selectors = { ...existing.selectors };
    }
    if (providerId !== undefined) base.providerId = providerId;
    return base;
  });

  const needsProviderId = MULTI_INSTANCE_MODES.includes(mode);
  const resolvedProviderId = providerId ?? (needsProviderId ? form.providerId.trim() : '');
  const pending = create.isPending || update.isPending;

  const setSelector = (name: string, value: string) =>
    setForm((f) => ({ ...f, selectors: { ...f.selectors, [name]: value } }));
  const setSecret = (name: string, value: string) =>
    setForm((f) => ({ ...f, secrets: { ...f.secrets, [name]: value } }));

  /** The write-only `set` payload from non-empty secret inputs (+ PKCS#12 file). */
  const buildSet = (): Record<string, string> => {
    const set: Record<string, string> = {};
    for (const spec of SECRET_FIELDS[mode]) {
      const value = form.secrets[spec.name];
      if (value && value.length > 0) set[spec.name] = value;
    }
    if (mode === 'pkcs12' && form.pfxBase64) set.pfx_der = form.pfxBase64;
    return set;
  };

  /** Non-secret selectors, dropping empty values so an unset selector is not persisted blank. */
  const buildSelectors = (): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const spec of SELECTOR_FIELDS[mode]) {
      const value = form.selectors[spec.name];
      if (value !== undefined && value !== '') out[spec.name] = value;
    }
    return out;
  };

  const providerIdReady = !needsProviderId || resolvedProviderId.length > 0;
  const set = buildSet();
  // A NEW entry must carry at least one secret; an edit may be metadata-only.
  const canSubmit = providerIdReady && (isEdit || Object.keys(set).length > 0) && !pending && !disabled;

  function clearSecrets() {
    setForm((f) => ({ ...f, secrets: {}, pfxBase64: '', pfxName: '' }));
  }

  function submit() {
    if (!canSubmit) return;
    const selectors = buildSelectors();
    const endpoint = ENDPOINT_MODES.includes(mode) && form.endpoint.trim() ? form.endpoint.trim() : undefined;
    if (isEdit && existing) {
      const body: UpdateProviderCredentialEntryBody = {
        label: form.label.trim() || undefined,
        enabled: form.enabled,
        endpoint,
        selectors,
        set: Object.keys(set).length > 0 ? set : undefined,
      };
      update.mutate(
        { mode, providerId: resolvedProviderId, entryId: existing.entry_id, body },
        {
          onSuccess: () => {
            clearSecrets();
            update.reset();
            toast.success(t('settings.providerCredentials.updatedToast'));
            onDone();
          },
          onError: (e) => toast.error(e),
        },
      );
      return;
    }
    const body: CreateProviderCredentialEntryBody = {
      label: form.label.trim() || undefined,
      enabled: form.enabled,
      endpoint,
      selectors,
      set,
    };
    create.mutate(
      { mode, providerId: resolvedProviderId, body },
      {
        onSuccess: () => {
          clearSecrets();
          create.reset();
          toast.success(t('settings.providerCredentials.createdToast'));
          onDone();
        },
        onError: (e) => toast.error(e),
      },
    );
  }

  const idBase = `pc-${mode}-${existing?.entry_id ?? 'new'}`;
  const mutation = isEdit ? update : create;

  return (
    <Card
      title={
        isEdit
          ? t('settings.providerCredentials.form.editEntry')
          : t('settings.providerCredentials.form.newEntry')
      }
    >
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        {!isEdit && providerId === undefined ? (
          <Field label={t('settings.providerCredentials.form.mode')} htmlFor={`${idBase}-mode`}>
            <Select
              id={`${idBase}-mode`}
              value={form.mode}
              options={MODES.map((m) => ({ value: m, label: modeLabel(t, m) }))}
              onChange={(e) => setForm(() => emptyForm(e.target.value as CredentialMode))}
            />
          </Field>
        ) : null}

        {needsProviderId && providerId === undefined ? (
          <Field
            label={t('settings.providerCredentials.form.providerId')}
            htmlFor={`${idBase}-provider`}
            hint={t('settings.providerCredentials.form.providerIdHint')}
          >
            <Input
              id={`${idBase}-provider`}
              value={form.providerId}
              autoComplete="off"
              onChange={(e) => setForm((f) => ({ ...f, providerId: e.target.value }))}
            />
          </Field>
        ) : null}

        <Field label={t('settings.providerCredentials.form.label')} htmlFor={`${idBase}-label`}>
          <Input
            id={`${idBase}-label`}
            value={form.label}
            placeholder={t('settings.providerCredentials.form.labelPlaceholder')}
            autoComplete="off"
            onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
          />
        </Field>

        <Toggle
          label={t('settings.providerCredentials.form.enabled')}
          checked={form.enabled}
          onChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
        />

        {ENDPOINT_MODES.includes(mode) ? (
          <Field
            label={t('settings.providerCredentials.form.endpoint')}
            htmlFor={`${idBase}-endpoint`}
            hint={t('settings.providerCredentials.form.endpointHint')}
          >
            <Input
              id={`${idBase}-endpoint`}
              type="url"
              value={form.endpoint}
              autoComplete="off"
              onChange={(e) => setForm((f) => ({ ...f, endpoint: e.target.value }))}
            />
          </Field>
        ) : null}

        {SELECTOR_FIELDS[mode].map((spec) => {
          const id = `${idBase}-sel-${spec.name}`;
          const value = form.selectors[spec.name] ?? '';
          if (spec.kind === 'toggle') {
            return (
              <Toggle
                key={spec.name}
                label={t(spec.labelKey)}
                checked={value === 'true'}
                onChange={(on) => setSelector(spec.name, on ? 'true' : 'false')}
              />
            );
          }
          if (spec.kind === 'env' || spec.kind === 'authorization') {
            const options =
              spec.kind === 'env'
                ? [
                    { value: '', label: t('settings.providerCredentials.field.env.unset') },
                    { value: 'preprod', label: t('settings.providerCredentials.field.env.preprod') },
                    { value: 'prod', label: t('settings.providerCredentials.field.env.prod') },
                  ]
                : [
                    { value: '', label: t('settings.providerCredentials.field.authorization.unset') },
                    { value: 'service', label: t('settings.providerCredentials.field.authorization.service') },
                    { value: 'user', label: t('settings.providerCredentials.field.authorization.user') },
                  ];
            return (
              <Field key={spec.name} label={t(spec.labelKey)} htmlFor={id}>
                <Select
                  id={id}
                  value={value}
                  options={options}
                  onChange={(e) => setSelector(spec.name, e.target.value)}
                />
              </Field>
            );
          }
          return (
            <Field key={spec.name} label={t(spec.labelKey)} htmlFor={id}>
              <Input
                id={id}
                value={value}
                autoComplete="off"
                onChange={(e) => setSelector(spec.name, e.target.value)}
              />
            </Field>
          );
        })}

        {mode === 'pkcs12' ? (
          <>
            <InlineWarning tone="warn" title={t('settings.providerCredentials.form.pfxWarning.title')}>
              {t('settings.providerCredentials.form.pfxWarning.body')}
            </InlineWarning>
            <Field
              label={t('settings.providerCredentials.field.pfx')}
              htmlFor={`${idBase}-pfx`}
              hint={
                isEdit
                  ? t('settings.providerCredentials.form.pfxReplaceHint')
                  : t('settings.providerCredentials.form.pfxHint')
              }
            >
              <input
                id={`${idBase}-pfx`}
                type="file"
                accept=".pfx,.p12,application/x-pkcs12"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (!file) {
                    setForm((f) => ({ ...f, pfxBase64: '', pfxName: '' }));
                    return;
                  }
                  void fileToBase64(file)
                    .then((b64) => setForm((f) => ({ ...f, pfxBase64: b64, pfxName: file.name })))
                    .catch((err) => toast.error(err));
                }}
              />
            </Field>
          </>
        ) : null}

        <p className="field__hint">{t('settings.providerCredentials.form.secretHint')}</p>
        {SECRET_FIELDS[mode].map((spec) => {
          const id = `${idBase}-secret-${spec.name}`;
          return (
            <Field
              key={spec.name}
              label={t(spec.labelKey)}
              htmlFor={id}
              hint={isEdit ? t('settings.providerCredentials.form.keepFieldHint') : undefined}
            >
              <Input
                id={id}
                type={spec.password ? 'password' : 'text'}
                value={form.secrets[spec.name] ?? ''}
                autoComplete="off"
                onChange={(e) => setSecret(spec.name, e.target.value)}
              />
            </Field>
          );
        })}

        {mutation.error ? <ErrorNote error={mutation.error} /> : null}

        <div className="form__actions">
          <Button type="button" variant="ghost" disabled={pending} onClick={onCancel}>
            {t('common.cancel')}
          </Button>
          <GateButton
            perm="settings.manage"
            type="submit"
            variant="primary"
            icon={<Icon.Check />}
            disabled={!canSubmit}
          >
            {pending
              ? t('settings.providerCredentials.form.submitting')
              : t('settings.providerCredentials.form.submit')}
          </GateButton>
        </div>
      </form>
    </Card>
  );
}

function EntryRow({
  group,
  entry,
  index,
  count,
  onEdit,
}: {
  group: ProviderCredentialGroupView;
  entry: ProviderCredentialEntryView;
  index: number;
  count: number;
  onEdit: () => void;
}) {
  const t = useT();
  const toast = useToast();
  const reorder = useReorderProviderCredentialEntries();
  const update = useUpdateProviderCredentialEntry();
  const del = useDeleteProviderCredentialEntry();
  const [confirming, setConfirming] = useState(false);

  const providerId = group.provider_id;

  function toggleEnabled(enabled: boolean) {
    update.mutate(
      { mode: group.mode, providerId, entryId: entry.entry_id, body: { enabled } },
      {
        onSuccess: () => toast.success(t('settings.providerCredentials.updatedToast')),
        onError: (e) => toast.error(e),
      },
    );
  }
  const orderedIds = [...group.entries].sort((a, b) => a.priority - b.priority).map((e) => e.entry_id);

  function move(direction: -1 | 1) {
    const from = orderedIds.indexOf(entry.entry_id);
    const to = from + direction;
    if (from < 0 || to < 0 || to >= orderedIds.length) return;
    const next = [...orderedIds];
    [next[from], next[to]] = [next[to], next[from]];
    reorder.mutate(
      { mode: group.mode, providerId, body: { order: next } },
      {
        onSuccess: () => toast.success(t('settings.providerCredentials.reorderedToast')),
        onError: (e) => toast.error(e),
      },
    );
  }

  const busy = reorder.isPending || del.isPending || update.isPending;

  return (
    <div className="stack--tight" role="group" aria-label={entry.label || entry.entry_id}>
      <div className="section-head">
        <div>
          <p className="card__label">
            {entry.label || t('settings.providerCredentials.entry.unlabeled')}{' '}
            <Badge tone="neutral">
              {t('settings.providerCredentials.entry.priority', { priority: entry.priority })}
            </Badge>
          </p>
          {entry.endpoint ? <p className="field__hint mono">{entry.endpoint}</p> : null}
          <Toggle
            label={
              entry.enabled
                ? t('settings.providerCredentials.entry.enabled')
                : t('settings.providerCredentials.entry.disabled')
            }
            checked={entry.enabled}
            disabled={busy}
            onChange={toggleEnabled}
          />
        </div>
        <span className="row-wrap">
          <GateIconButton
            perm="settings.manage"
            icon={<Icon.ArrowUp />}
            label={t('settings.providerCredentials.entry.moveUp')}
            disabled={busy || index === 0}
            onClick={() => move(-1)}
          />
          <GateIconButton
            perm="settings.manage"
            icon={<Icon.ArrowDown />}
            label={t('settings.providerCredentials.entry.moveDown')}
            disabled={busy || index === count - 1}
            onClick={() => move(1)}
          />
          <GateButton
            perm="settings.manage"
            type="button"
            variant="ghost"
            icon={<Icon.Pencil />}
            disabled={busy}
            onClick={onEdit}
          >
            {t('settings.providerCredentials.entry.edit')}
          </GateButton>
          <GateButton
            perm="settings.manage"
            type="button"
            variant="ghost"
            icon={<Icon.Trash />}
            disabled={busy}
            onClick={() => setConfirming(true)}
          >
            {t('common.remove')}
          </GateButton>
        </span>
      </div>

      <div className="row-wrap">
        {entry.fields.length === 0 ? (
          <span className="muted">{t('settings.providerCredentials.entry.noFields')}</span>
        ) : (
          entry.fields.map((f) => (
            <Badge key={f.field_name} tone={f.configured ? 'ok' : 'neutral'}>
              {f.field_name} · {t('settings.providerCredentials.entry.configured')}
            </Badge>
          ))
        )}
      </div>

      <ConfirmActionModal
        open={confirming}
        onClose={() => setConfirming(false)}
        title={t('settings.providerCredentials.entry.deleteConfirm.title')}
        intro={t('settings.providerCredentials.entry.deleteConfirm.intro', {
          label: entry.label || entry.entry_id,
        })}
        confirmLabel={t('settings.providerCredentials.entry.deleteConfirm.confirm')}
        pendingLabel={t('settings.providerCredentials.entry.deleteConfirm.pending')}
        danger
        pending={del.isPending}
        onConfirm={async () => {
          await del.mutateAsync({ mode: group.mode, providerId, entryId: entry.entry_id });
          toast.success(t('settings.providerCredentials.deletedToast'));
          setConfirming(false);
        }}
      />
    </div>
  );
}

function ProviderGroupCard({ group }: { group: ProviderCredentialGroupView }) {
  const t = useT();
  const [adding, setAdding] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const entries = useMemo(
    () => [...group.entries].sort((a, b) => a.priority - b.priority),
    [group.entries],
  );

  const title =
    group.provider_id === ''
      ? modeLabel(t, group.mode)
      : `${modeLabel(t, group.mode)} · ${group.provider_id}`;

  return (
    <Card
      title={title}
      actions={
        <GateButton
          perm="settings.manage"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() => {
            setEditingId(null);
            setAdding((v) => !v);
          }}
        >
          {t('settings.providerCredentials.provider.addEntry')}
        </GateButton>
      }
    >
      <p className="field__hint">{t('settings.providerCredentials.failoverHint')}</p>

      {adding ? (
        <EntryForm
          mode={group.mode}
          providerId={group.provider_id}
          disabled={false}
          onDone={() => setAdding(false)}
          onCancel={() => setAdding(false)}
        />
      ) : null}

      {entries.length === 0 ? (
        <EmptyState title={t('settings.providerCredentials.provider.noEntries')} />
      ) : (
        <div className="stack--tight">
          {entries.map((entry, index) =>
            editingId === entry.entry_id ? (
              <EntryForm
                key={entry.entry_id}
                mode={group.mode}
                providerId={group.provider_id}
                existing={entry}
                disabled={false}
                onDone={() => setEditingId(null)}
                onCancel={() => setEditingId(null)}
              />
            ) : (
              <EntryRow
                key={entry.entry_id}
                group={group}
                entry={entry}
                index={index}
                count={entries.length}
                onEdit={() => {
                  setAdding(false);
                  setEditingId(entry.entry_id);
                }}
              />
            ),
          )}
        </div>
      )}
    </Card>
  );
}

export function ProviderCredentialsSection() {
  const t = useT();
  const can = useCan();
  const credentials = useProviderCredentials();
  const [creating, setCreating] = useState(false);

  if (credentials.isLoading) return <Loading />;
  if (credentials.error) return <ErrorNote error={credentials.error} />;

  const data = credentials.data;
  const providers = data?.providers ?? [];

  return (
    <div className="stack">
      <ProtectionBanner strict={data?.strict ?? false} level={data?.protection_level} />

      {creating ? (
        <EntryForm
          mode="csc"
          disabled={!can('settings.manage')}
          onDone={() => setCreating(false)}
          onCancel={() => setCreating(false)}
        />
      ) : (
        <Card
          title={t('settings.providerCredentials.cardTitle')}
          actions={
            <GateButton
              perm="settings.manage"
              variant="primary"
              icon={<Icon.Plus />}
              onClick={() => setCreating(true)}
            >
              {t('settings.providerCredentials.newEntry')}
            </GateButton>
          }
        >
          <p className="field__hint">{t('settings.providerCredentials.lede')}</p>
          {providers.length === 0 ? (
            <EmptyState title={t('settings.providerCredentials.empty')}>
              <p>{t('settings.providerCredentials.emptyBody')}</p>
            </EmptyState>
          ) : null}
        </Card>
      )}

      {providers.map((group) => (
        <ProviderGroupCard key={`${group.mode}:${group.provider_id}`} group={group} />
      ))}
    </div>
  );
}
