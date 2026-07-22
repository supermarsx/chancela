/**
 * Fornecedores de assinatura — operator management of the encrypted provider-credential
 * store (wp13 Phase D). It drives the multi-key / priority-failover / per-provider
 * endpoint + HTTP-auth / configurable-PKCS#12 backend
 * (`/v1/signature/provider-credentials`).
 *
 * Security posture mirrors the backend (plan §3/§6): secrets are WRITE-ONLY. Every secret
 * input is `type="password"`, `autoComplete="off"`, never pre-filled (the API never returns
 * a value — only a per-field `configured` flag), lives solely in component-local `useState`,
 * and is cleared on submit so it is never written into the react-query cache.
 *
 * ## Honest storage state (t36)
 *
 * The banner has THREE states, not two: confidential, obfuscation, and **cannot store at all**.
 * It used to have two, so a store with no resolvable key source — where saving a credential is
 * impossible — fell through to the obfuscation warning and told the operator their secrets were
 * being kept with weaker protection. They were not being kept at all. {@link canStoreSecrets}
 * decides, and `settings.providerCredentials.protection.reason.*` names the operator's next step.
 *
 * Entries render as a scannable grid (`Table`) rather than a stack of per-entry blocks: every
 * entry answers the same six questions (which entry, what priority, active?, which endpoint,
 * which fields are configured, what can I do to it), so they belong in aligned columns.
 *
 * Mirrors the `ApiKeysSection` idioms: `Card`/`Field`/`Input`/`GateButton`, disabled+pending
 * mutating controls (CONVENTIONS §5), inline error + toast (§2), `EmptyState` when empty, and
 * RBAC-gated on `settings.manage` (the same permission the backend writes require).
 */
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import type {
  CredentialMode,
  CredentialProtectionLevel,
  CredentialStorageFailure,
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
  FieldHelp,
  Icon,
  InlineWarning,
  Input,
  SkeletonRegion,
  SkeletonTable,
  Select,
  Table,
  Toggle,
  TooltipText,
  useToast,
} from '../../ui';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { GateButton, GateIconButton, useCan } from '../session/permissions';
import { providerCredentialsFieldHelp, providerCredentialFieldHelp } from './fieldHelp';

/** The modes an operator can configure, in display order. */
const MODES: CredentialMode[] = ['cmd', 'csc', 'scap', 'pkcs12'];

/**
 * Credential modes reachable by the trust-services Actions deep-link (`?configure=<mode>`),
 * the frozen URL contract with the "Modos de prestador" table (t12). Only these three have a
 * provider-modes table row that routes here: `scap` has no table row and Cartão de Cidadão has
 * no web configuration at all, so neither is a deep-link target. Any other value is ignored.
 */
const DEEP_LINK_MODES: readonly CredentialMode[] = ['cmd', 'csc', 'pkcs12'];

/** The query-param key the trust-services Actions column navigates with. */
const CONFIGURE_PARAM = 'configure';

function isDeepLinkMode(value: string | null): value is CredentialMode {
  return value !== null && (DEEP_LINK_MODES as readonly string[]).includes(value);
}

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
    {
      name: 'application_id',
      labelKey: 'settings.providerCredentials.field.applicationId',
      password: false,
    },
    {
      name: 'http_basic_username',
      labelKey: 'settings.providerCredentials.field.httpBasicUsername',
      password: false,
    },
    {
      name: 'http_basic_password',
      labelKey: 'settings.providerCredentials.field.httpBasicPassword',
      password: true,
    },
    {
      name: 'ama_cert_pem',
      labelKey: 'settings.providerCredentials.field.amaCertPem',
      password: true,
    },
  ],
  csc: [
    { name: 'client_id', labelKey: 'settings.providerCredentials.field.clientId', password: false },
    {
      name: 'client_secret',
      labelKey: 'settings.providerCredentials.field.clientSecret',
      password: true,
    },
    {
      name: 'access_token',
      labelKey: 'settings.providerCredentials.field.accessToken',
      password: true,
    },
    {
      name: 'http_basic_username',
      labelKey: 'settings.providerCredentials.field.httpBasicUsername',
      password: false,
    },
    {
      name: 'http_basic_password',
      labelKey: 'settings.providerCredentials.field.httpBasicPassword',
      password: true,
    },
  ],
  scap: [
    {
      name: 'application_id',
      labelKey: 'settings.providerCredentials.field.applicationId',
      password: false,
    },
    { name: 'secret', labelKey: 'settings.providerCredentials.field.secret', password: true },
    {
      name: 'http_basic_username',
      labelKey: 'settings.providerCredentials.field.httpBasicUsername',
      password: false,
    },
    {
      name: 'http_basic_password',
      labelKey: 'settings.providerCredentials.field.httpBasicPassword',
      password: true,
    },
  ],
  pkcs12: [
    {
      name: 'passphrase',
      labelKey: 'settings.providerCredentials.field.passphrase',
      password: true,
    },
  ],
};

/** Per-mode NON-secret selectors, persisted plainly and returned in responses. */
const SELECTOR_FIELDS: Record<CredentialMode, SelectorFieldSpec[]> = {
  cmd: [{ name: 'env', labelKey: 'settings.providerCredentials.field.env', kind: 'env' }],
  csc: [
    {
      name: 'authorization',
      labelKey: 'settings.providerCredentials.field.authorization',
      kind: 'authorization',
    },
    {
      name: 'credential_id',
      labelKey: 'settings.providerCredentials.field.credentialId',
      kind: 'text',
    },
    { name: 'scope', labelKey: 'settings.providerCredentials.field.scope', kind: 'text' },
    { name: 'sandbox', labelKey: 'settings.providerCredentials.field.sandbox', kind: 'toggle' },
  ],
  scap: [
    {
      name: 'environment',
      labelKey: 'settings.providerCredentials.field.environment',
      kind: 'env',
    },
  ],
  pkcs12: [
    {
      name: 'friendly_name',
      labelKey: 'settings.providerCredentials.field.friendlyName',
      kind: 'text',
    },
    {
      name: 'local_key_id_hex',
      labelKey: 'settings.providerCredentials.field.localKeyId',
      kind: 'text',
    },
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

/**
 * Why the store cannot hold a secret. Several distinct failures share one operator remedy, so
 * they share one sentence — the point is to name the next step, not to enumerate the enum.
 */
const STORAGE_FAILURE_KEYS: Record<CredentialStorageFailure, MessageKey> = {
  not_persistent: 'settings.providerCredentials.protection.reason.notPersistent',
  missing_key_source: 'settings.providerCredentials.protection.reason.noKeySource',
  ambiguous_operator_key: 'settings.providerCredentials.protection.reason.operatorKey',
  invalid_operator_key: 'settings.providerCredentials.protection.reason.operatorKey',
  missing_root_envelope: 'settings.providerCredentials.protection.reason.rootEnvelope',
  invalid_root_envelope: 'settings.providerCredentials.protection.reason.rootEnvelope',
  store_unavailable: 'settings.providerCredentials.protection.reason.storeUnavailable',
};

/**
 * Whether the store can hold a secret at all, from the two fields the server may send.
 *
 * A server predating t36 sends no `can_store`, but it already omitted `protection_level` in
 * exactly the cases where no key could be resolved — so an absent level is the old server's own
 * (slightly coarser) way of saying the same thing, and reading it that way is what closes the
 * defect: the banner used to fall through to "obfuscation" here and tell operators their secrets
 * were kept with weaker protection when in truth none could be stored.
 */
export function canStoreSecrets(view: {
  can_store?: boolean;
  protection_level?: CredentialProtectionLevel;
}): boolean {
  return view.can_store ?? view.protection_level !== undefined;
}

function ProtectionBanner({
  strict,
  level,
  storable,
  failure,
}: {
  strict: boolean;
  level: CredentialProtectionLevel | undefined;
  storable: boolean;
  failure: CredentialStorageFailure | undefined;
}) {
  const t = useT();
  if (!storable) {
    return (
      <InlineWarning
        tone="error"
        title={t('settings.providerCredentials.protection.unavailable.title')}
      >
        <p>{t('settings.providerCredentials.protection.unavailable.body')}</p>
        <p>
          {t(
            failure
              ? STORAGE_FAILURE_KEYS[failure]
              : 'settings.providerCredentials.protection.reason.noKeySource',
          )}
        </p>
      </InlineWarning>
    );
  }
  if (level === 'confidential') {
    return (
      <InlineWarning
        tone="info"
        title={t('settings.providerCredentials.protection.confidential.title')}
      >
        {t('settings.providerCredentials.protection.confidential.body')}
      </InlineWarning>
    );
  }
  return (
    <InlineWarning
      tone={strict ? 'error' : 'warn'}
      title={t('settings.providerCredentials.protection.obfuscation.title')}
    >
      <p>{t('settings.providerCredentials.protection.obfuscation.body')}</p>
      {strict ? <p>{t('settings.providerCredentials.protection.strictBlocked')}</p> : null}
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

  // A top-level create form may switch credential modes. Existing groups and
  // entries remain pinned to the mode supplied by their parent card.
  const effectiveMode = providerId === undefined && !existing ? form.mode : mode;
  const needsProviderId = MULTI_INSTANCE_MODES.includes(effectiveMode);
  const resolvedProviderId = providerId ?? (needsProviderId ? form.providerId.trim() : '');
  const pending = create.isPending || update.isPending;

  const setSelector = (name: string, value: string) =>
    setForm((f) => ({ ...f, selectors: { ...f.selectors, [name]: value } }));
  const setSecret = (name: string, value: string) =>
    setForm((f) => ({ ...f, secrets: { ...f.secrets, [name]: value } }));

  /** The write-only `set` payload from non-empty secret inputs (+ PKCS#12 file). */
  const buildSet = (): Record<string, string> => {
    const set: Record<string, string> = {};
    for (const spec of SECRET_FIELDS[effectiveMode]) {
      const value = form.secrets[spec.name];
      if (value && value.length > 0) set[spec.name] = value;
    }
    if (effectiveMode === 'pkcs12' && form.pfxBase64) set.pfx_der = form.pfxBase64;
    return set;
  };

  /** Non-secret selectors, dropping empty values so an unset selector is not persisted blank. */
  const buildSelectors = (): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const spec of SELECTOR_FIELDS[effectiveMode]) {
      const value = form.selectors[spec.name];
      if (value !== undefined && value !== '') out[spec.name] = value;
    }
    return out;
  };

  const providerIdReady = !needsProviderId || resolvedProviderId.length > 0;
  const set = buildSet();
  // A NEW entry must carry at least one secret; an edit may be metadata-only.
  const canSubmit =
    providerIdReady && (isEdit || Object.keys(set).length > 0) && !pending && !disabled;

  function clearSecrets() {
    setForm((f) => ({ ...f, secrets: {}, pfxBase64: '', pfxName: '' }));
  }

  function submit() {
    if (!canSubmit) return;
    const selectors = buildSelectors();
    const endpoint =
      ENDPOINT_MODES.includes(effectiveMode) && form.endpoint.trim()
        ? form.endpoint.trim()
        : undefined;
    if (isEdit && existing) {
      const body: UpdateProviderCredentialEntryBody = {
        label: form.label.trim() || undefined,
        enabled: form.enabled,
        endpoint,
        selectors,
        set: Object.keys(set).length > 0 ? set : undefined,
      };
      update.mutate(
        { mode: effectiveMode, providerId: resolvedProviderId, entryId: existing.entry_id, body },
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
      { mode: effectiveMode, providerId: resolvedProviderId, body },
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

  const idBase = `pc-${effectiveMode}-${existing?.entry_id ?? 'new'}`;
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
        className="form settings-rows"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        {!isEdit && providerId === undefined ? (
          <Field
            label={t('settings.providerCredentials.form.mode')}
            htmlFor={`${idBase}-mode`}
            help={providerCredentialsFieldHelp.mode}
          >
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
            help={providerCredentialsFieldHelp.providerId}
          >
            <Input
              id={`${idBase}-provider`}
              value={form.providerId}
              autoComplete="off"
              onChange={(e) => setForm((f) => ({ ...f, providerId: e.target.value }))}
            />
          </Field>
        ) : null}

        <Field
          label={t('settings.providerCredentials.form.label')}
          htmlFor={`${idBase}-label`}
          help={providerCredentialsFieldHelp.label}
        >
          <Input
            id={`${idBase}-label`}
            value={form.label}
            placeholder={t('settings.providerCredentials.form.labelPlaceholder')}
            autoComplete="off"
            onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
          />
        </Field>

        <Toggle
          label={
            <>
              {t('settings.providerCredentials.form.enabled')}{' '}
              <FieldHelp text={providerCredentialsFieldHelp.enabled} />
            </>
          }
          checked={form.enabled}
          onChange={(enabled) => setForm((f) => ({ ...f, enabled }))}
        />

        {ENDPOINT_MODES.includes(effectiveMode) ? (
          <Field
            label={t('settings.providerCredentials.form.endpoint')}
            htmlFor={`${idBase}-endpoint`}
            hint={t('settings.providerCredentials.form.endpointHint')}
            help={providerCredentialsFieldHelp.endpoint}
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

        {SELECTOR_FIELDS[effectiveMode].map((spec) => {
          const id = `${idBase}-sel-${spec.name}`;
          const value = form.selectors[spec.name] ?? '';
          const help = providerCredentialFieldHelp(spec.name);
          if (spec.kind === 'toggle') {
            return (
              <Toggle
                key={spec.name}
                label={
                  <>
                    {t(spec.labelKey)}
                    {help ? (
                      <>
                        {' '}
                        <FieldHelp text={help} />
                      </>
                    ) : null}
                  </>
                }
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
                    {
                      value: 'preprod',
                      label: t('settings.providerCredentials.field.env.preprod'),
                    },
                    { value: 'prod', label: t('settings.providerCredentials.field.env.prod') },
                  ]
                : [
                    {
                      value: '',
                      label: t('settings.providerCredentials.field.authorization.unset'),
                    },
                    {
                      value: 'service',
                      label: t('settings.providerCredentials.field.authorization.service'),
                    },
                    {
                      value: 'user',
                      label: t('settings.providerCredentials.field.authorization.user'),
                    },
                  ];
            return (
              <Field key={spec.name} label={t(spec.labelKey)} htmlFor={id} help={help}>
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
            <Field key={spec.name} label={t(spec.labelKey)} htmlFor={id} help={help}>
              <Input
                id={id}
                value={value}
                autoComplete="off"
                onChange={(e) => setSelector(spec.name, e.target.value)}
              />
            </Field>
          );
        })}

        {effectiveMode === 'pkcs12' ? (
          <>
            <InlineWarning
              tone="warn"
              title={t('settings.providerCredentials.form.pfxWarning.title')}
            >
              {t('settings.providerCredentials.form.pfxWarning.body')}
            </InlineWarning>
            <Field
              label={t('settings.providerCredentials.field.pfx')}
              htmlFor={`${idBase}-pfx`}
              help={providerCredentialsFieldHelp.pfx}
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
        {SECRET_FIELDS[effectiveMode].map((spec) => {
          const id = `${idBase}-secret-${spec.name}`;
          return (
            <Field
              key={spec.name}
              label={t(spec.labelKey)}
              htmlFor={id}
              help={providerCredentialFieldHelp(spec.name)}
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
  const orderedIds = [...group.entries]
    .sort((a, b) => a.priority - b.priority)
    .map((e) => e.entry_id);

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
  const label = entry.label || t('settings.providerCredentials.entry.unlabeled');

  return (
    <tr role="group" aria-label={entry.label || entry.entry_id}>
      <td data-label={t('settings.providerCredentials.table.entry')}>
        <p className="card__label">{label}</p>
        <TooltipText label={entry.entry_id} as="code" className="field__hint mono">
          {entry.entry_id}
        </TooltipText>
      </td>
      <td data-label={t('settings.providerCredentials.table.priority')}>
        <Badge tone="neutral">
          {t('settings.providerCredentials.entry.priority', { priority: entry.priority })}
        </Badge>
      </td>
      <td data-label={t('settings.providerCredentials.table.state')}>
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
      </td>
      <td className="mono" data-label={t('settings.providerCredentials.table.endpoint')}>
        {entry.endpoint ? (
          <TooltipText label={entry.endpoint} onlyWhenClipped className="truncate">
            {entry.endpoint}
          </TooltipText>
        ) : (
          <span className="muted">{t('settings.providerCredentials.table.endpointDefault')}</span>
        )}
      </td>
      {/* Configured vs not-configured is the whole point of this column: the server sends a
          per-field `configured` flag and never a value, so the badge must say WHICH it is. It
          previously read "configurado" for every field and only varied its colour, which made an
          unset field look set to anyone not reading the palette. */}
      <td data-label={t('settings.providerCredentials.table.fields')}>
        <span className="row-wrap">
          {entry.fields.length === 0 ? (
            <span className="muted">{t('settings.providerCredentials.entry.noFields')}</span>
          ) : (
            entry.fields.map((f) => (
              <Badge key={f.field_name} tone={f.configured ? 'ok' : 'neutral'}>
                {f.field_name} ·{' '}
                {f.configured
                  ? t('settings.providerCredentials.entry.configured')
                  : t('settings.providerCredentials.entry.notConfigured')}
              </Badge>
            ))
          )}
        </span>
      </td>
      <td data-label={t('settings.providerCredentials.table.actions')}>
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
      </td>
    </tr>
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
  const editing = entries.find((entry) => entry.entry_id === editingId);

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

      {/* The add/edit form sits ABOVE the grid rather than replacing a row: a form is a column of
          labelled inputs and a row is a scanline, and swapping one for the other made the table
          jump. The row being edited stays visible for comparison. */}
      {adding ? (
        <EntryForm
          mode={group.mode}
          providerId={group.provider_id}
          disabled={false}
          onDone={() => setAdding(false)}
          onCancel={() => setAdding(false)}
        />
      ) : null}
      {editing ? (
        <EntryForm
          key={editing.entry_id}
          mode={group.mode}
          providerId={group.provider_id}
          existing={editing}
          disabled={false}
          onDone={() => setEditingId(null)}
          onCancel={() => setEditingId(null)}
        />
      ) : null}

      {entries.length === 0 ? (
        <EmptyState title={t('settings.providerCredentials.provider.noEntries')} />
      ) : (
        <Table
          caption={t('settings.providerCredentials.table.caption', { provider: title })}
          head={
            <tr>
              <th>{t('settings.providerCredentials.table.entry')}</th>
              <th>{t('settings.providerCredentials.table.priority')}</th>
              <th>{t('settings.providerCredentials.table.state')}</th>
              <th>{t('settings.providerCredentials.table.endpoint')}</th>
              <th>{t('settings.providerCredentials.table.fields')}</th>
              <th>{t('settings.providerCredentials.table.actions')}</th>
            </tr>
          }
        >
          {entries.map((entry, index) => (
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
          ))}
        </Table>
      )}
    </Card>
  );
}

export function ProviderCredentialsSection() {
  const t = useT();
  const can = useCan();
  const credentials = useProviderCredentials();
  const [searchParams, setSearchParams] = useSearchParams();
  const [creating, setCreating] = useState(false);
  // The mode the top-level create form opens on. Defaults to 'csc' (the historical default);
  // a deep-link may preselect another mode before the form is shown.
  const [createMode, setCreateMode] = useState<CredentialMode>('csc');

  // Deep-link target: the trust-services "Configurar" action routes here with
  // `?configure=<mode>` so an operator lands on the create form for the mode they picked. We
  // consume the param once — preselecting the mode when it names one we can configure in the
  // web app — then strip it (replace) so a refresh or Back does not reopen the form. An unknown
  // or absent value leaves the section in its normal state; the param is still cleared so no
  // stale `?configure=` lingers in the address bar.
  useEffect(() => {
    const requested = searchParams.get(CONFIGURE_PARAM);
    if (requested === null) return;
    if (isDeepLinkMode(requested)) {
      setCreateMode(requested);
      setCreating(true);
    }
    const next = new URLSearchParams(searchParams);
    next.delete(CONFIGURE_PARAM);
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  // Six columns per provider group: entry, priority, state, endpoint, fields, actions.
  if (credentials.isLoading)
    return (
      <div className="stack">
        <Card title={t('settings.providerCredentials.cardTitle')}>
          <SkeletonRegion>
            <SkeletonTable cols={6} />
          </SkeletonRegion>
        </Card>
      </div>
    );
  if (credentials.error) return <ErrorNote error={credentials.error} />;

  const data = credentials.data;
  const providers = data?.providers ?? [];
  // Nothing can be stored → creating an entry can only end in a server refusal, so the control is
  // inert and the banner above carries the reason. Editing existing rows stays available: label,
  // priority and enabled are plain metadata and do not touch the secret store.
  const storable = data ? canStoreSecrets(data) : true;

  return (
    <div className="stack">
      <ProtectionBanner
        strict={data?.strict ?? false}
        level={data?.protection_level}
        storable={storable}
        failure={data?.storage_failure}
      />

      {creating ? (
        <EntryForm
          key={createMode}
          mode={createMode}
          disabled={!can('settings.manage') || !storable}
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
              disabled={!storable}
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
