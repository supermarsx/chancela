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
 * RBAC-gated on `signing.configure` — the dedicated signing-configuration verb the backend writes
 * now require since the cluster moved into Administração and was re-permissioned (t50). It is
 * grandfathered to every prior `settings.manage` holder, so no current operator loses the pane.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useNavigate, useSearchParams } from 'react-router-dom';
import type {
  AmaCertificateInspectResponse,
  CredentialMode,
  CredentialProtectionLevel,
  CredentialStorageFailure,
  CreateProviderCredentialEntryBody,
  ProviderCredentialEntryView,
  ProviderCredentialGroupView,
  ProviderCredentialProbeCheck,
  ProviderCredentialProbeResponse,
  UpdateProviderCredentialEntryBody,
} from '../../api/types';
import {
  useProviderCredentials,
  useCreateProviderCredentialEntry,
  useUpdateProviderCredentialEntry,
  useDeleteProviderCredentialEntry,
  useReorderProviderCredentialEntries,
  useProbeProviderCredentialEntry,
  useInspectAmaCertificate,
} from '../../api/hooks';
import { useActiveLocale, useT, type TFunction } from '../../i18n';
import { formatDateTime } from '../../format';
import type { MessageKey } from '../../i18n';
import { useProviderCredentialsT } from '../../i18n/providerCredentialsFallback';
import { resolveProbeCheckName, resolveProbeDetail } from '../../i18n/providerProbeDiagnostics';
import { allowNextNavigation, useUnsavedChanges } from '../../hooks/useUnsavedChanges';
import {
  Badge,
  Button,
  Card,
  ColumnHead,
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
  TextArea,
  Toggle,
  TooltipText,
  useToast,
} from '../../ui';
import { ConfirmActionModal } from '../../ui/ConfirmActionModal';
import { useFocusTrap } from '../../ui/useFocusTrap';
import { isTauri } from '../../desktop/tauri';
import {
  acceptAttribute,
  openTextFileNative,
  readClipboardText,
  readPickedTextFile,
  type OpenTextFileResult,
} from '../../desktop/openTextFile';
import { GateButton, GateIconButton, useCan } from '../session/permissions';
import { CmdTestSignatureAction } from './CmdTestSignatureAction';
import { providerCredentialsFieldHelp, providerCredentialFieldHelp } from './fieldHelp';
import {
  providerCredentialCreatePath,
  providerCredentialEditPath,
} from './providerCredentialRoutes';

/** The modes an operator can configure, in display order. */
const MODES: CredentialMode[] = ['cmd', 'csc', 'scap', 'pkcs12'];
const LEGACY_CONFIGURE_MODES: readonly CredentialMode[] = ['cmd', 'csc', 'pkcs12'];

/** Modes that carry a per-entry endpoint / base_url override. */
const ENDPOINT_MODES: readonly CredentialMode[] = ['csc', 'scap'];

/** Modes that require a real (non-empty) provider id; the rest are single-instance. */
const MULTI_INSTANCE_MODES: readonly CredentialMode[] = ['csc', 'pkcs12'];

/**
 * The six columns of a provider group's entry table, each paired with the sentence that says what
 * the column *means operationally* (t101's `ColumnHead` contract). They are declared here rather
 * than inline so the header row and any future consumer cannot drift apart, and so the count is
 * one thing to keep in step with the `SkeletonTable cols` below.
 */
const ENTRY_COLUMNS: readonly { labelKey: MessageKey; helpKey: MessageKey }[] = [
  {
    labelKey: 'settings.providerCredentials.table.entry',
    helpKey: 'settings.providerCredentials.table.entry.help',
  },
  {
    labelKey: 'settings.providerCredentials.table.priority',
    helpKey: 'settings.providerCredentials.table.priority.help',
  },
  {
    labelKey: 'settings.providerCredentials.table.state',
    helpKey: 'settings.providerCredentials.table.state.help',
  },
  {
    labelKey: 'settings.providerCredentials.table.endpoint',
    helpKey: 'settings.providerCredentials.table.endpoint.help',
  },
  {
    labelKey: 'settings.providerCredentials.table.fields',
    helpKey: 'settings.providerCredentials.table.fields.help',
  },
  {
    labelKey: 'settings.providerCredentials.table.actions',
    helpKey: 'settings.providerCredentials.table.actions.help',
  },
];

/** The five columns of the modes overview table (see {@link ProviderModesCard}). */
const MODE_COLUMNS: readonly { labelKey: MessageKey; helpKey: MessageKey }[] = [
  {
    labelKey: 'settings.providerCredentials.modes.column.mode',
    helpKey: 'settings.providerCredentials.modes.column.mode.help',
  },
  {
    labelKey: 'settings.providerCredentials.modes.column.purpose',
    helpKey: 'settings.providerCredentials.modes.column.purpose.help',
  },
  {
    labelKey: 'settings.providerCredentials.modes.column.setup',
    helpKey: 'settings.providerCredentials.modes.column.setup.help',
  },
  {
    labelKey: 'settings.providerCredentials.modes.column.entries',
    helpKey: 'settings.providerCredentials.modes.column.entries.help',
  },
  {
    labelKey: 'settings.providerCredentials.modes.column.actions',
    helpKey: 'settings.providerCredentials.modes.column.actions.help',
  },
];

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
  /**
   * For `kind: 'toggle'` — what the SERVER assumes when the selector is absent.
   *
   * Not cosmetic. An entry created without this selector — through the API, or through this form
   * before {@link newEntryOn} existed — has the key missing, and the server then applies its own
   * default. Rendering such a toggle as off would show the operator the opposite of the state
   * actually in force. See {@link selectorBool}.
   */
  defaultOn?: boolean;
  /**
   * For `kind: 'toggle'` — what a NEWLY CREATED entry starts as, written to `selectors`
   * **explicitly** so the server's absent-key default never decides it.
   *
   * A different question from {@link defaultOn}, and deliberately allowed to disagree with it:
   * `defaultOn` reads existing data ("what is in force for an entry that has no value"), this one
   * writes new data ("what should an entry the operator just created be"). For `sandbox` they do
   * disagree — absence means ON at the server, and a new entry must not be sandboxed unless the
   * operator says so — which is exactly why one field could not serve both.
   *
   * Only seeded by {@link emptyForm}, never by the edit path: an entry whose selector is absent
   * keeps it absent. See {@link initialSelectors}.
   */
  newEntryOn?: boolean;
  /**
   * For a `kind: 'env'` selector that is REQUIRED — the value the server resolves an absent
   * selector to, and the value a new entry is created with.
   *
   * One field rather than the `defaultOn`/`newEntryOn` pair, because for the selector that has it
   * the two answers are the same, and that identity is the whole point: writing the value an
   * absent selector already resolves to cannot change what any stored credential does, which is
   * what makes it safe to write it unconditionally and thereby retire the fallback.
   *
   * Declaring this also removes the "not set" option from the control. That third state used to
   * mean "take the deployment default", and there is no longer a deployment default anybody can
   * see or change from the UI — so offering it would be offering a choice whose outcome is
   * invisible. See {@link SELECTOR_FIELDS}.`cmd`.
   */
  requiredDefault?: string;
}

/**
 * Mirror of the server's `selector_bool` (`provider_credentials_write.rs`): it accepts several
 * spellings on each side and treats anything else — **including an absent selector** — as the
 * field's default. Reproduced rather than simplified to `value === 'true'` because both halves
 * matter: an API-created entry may legitimately carry `on`/`1`, and absence is not falsehood.
 */
function selectorBool(value: string | undefined, defaultOn: boolean): boolean {
  switch (value?.trim()) {
    case 'true':
    case '1':
    case 'yes':
    case 'on':
      return true;
    case 'false':
    case '0':
    case 'no':
    case 'off':
      return false;
    default:
      return defaultOn;
  }
}

/**
 * What an EMPTY endpoint cell means, per mode — they genuinely disagree, and one label for all four
 * reassures the operator in the one case that is actually broken.
 *
 * - `cmd` — the SCMD endpoint is a compiled-in constant per environment (`CmdEnv::endpoint`).
 * - `csc` — there is no default: `probe_csc` fails the entry `configuration_incomplete` without one.
 * - `scap` — falls back to `ScapEnvironment::default_base_url` for the selected environment.
 * - `pkcs12` — a local keystore has no address at all, so there is no default to fall back to.
 */
const EMPTY_ENDPOINT_KEYS: Record<CredentialMode, MessageKey> = {
  cmd: 'settings.providerCredentials.table.endpointDefault',
  csc: 'settings.providerCredentials.table.endpointRequired',
  scap: 'settings.providerCredentials.table.endpointDefault',
  pkcs12: 'settings.providerCredentials.table.endpointNotApplicable',
};

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

/**
 * Compact per-field labels for the CMD `Campos` column badges.
 *
 * The shared fields column renders each field's stored name verbatim (`client_secret`,
 * `ama_cert_pem`, …). For CMD that meant four long snake_case tokens an operator has to read in full
 * to scan a row; these give the four CMD fields a short, machine-ish label instead. They are
 * identifiers, not copy — the SAME in every locale, like the `CHANCELA_*` environment variables and
 * the no-claims flags the app renders verbatim — so they live here rather than in the translation
 * catalog. Only the ok / não-ok STATE beside them, and the badge's full accessible name, are
 * translated.
 *
 * Scoped to CMD deliberately: CSC/SCAP/PKCS#12 keep their descriptive field names, which are short
 * enough to read and would only turn cryptic if abbreviated. A CMD field not listed here (an unknown
 * future one) falls back to its verbatim name, so nothing is silently dropped.
 */
const CMD_FIELD_ABBREVIATIONS: Record<string, string> = {
  ama_cert_pem: 'PEM',
  application_id: 'APPID',
  http_basic_password: 'PWD',
  http_basic_username: 'USER',
};

/** Per-mode NON-secret selectors, persisted plainly and returned in responses. */
const SELECTOR_FIELDS: Record<CredentialMode, SelectorFieldSpec[]> = {
  // CMD's environment is decided HERE and nowhere else. The settings card used to carry a
  // deployment-wide default for an entry that declared none; that is gone, because prod/preprod
  // expressible in two places is one place too many and a single switch cannot describe an
  // installation holding a preprod and a production credential side by side.
  //
  // `requiredDefault: 'preprod'` is what makes the removal safe rather than merely tidy. Before
  // this, an entry with no `env` selector resolved through `settings.signing.cmd.env`, which ships
  // as `preprod` and had no editor at all until very recently — so `preprod` is what such an entry
  // resolves to today, in every deployment that did not reach past the UI to change it. Writing it
  // explicitly therefore changes no credential's behaviour, and it moves nothing to production:
  // promotion stays an act the operator performs on this control, which is the only place it can
  // now be performed.
  cmd: [
    {
      name: 'env',
      labelKey: 'settings.providerCredentials.field.env',
      kind: 'env',
      requiredDefault: 'preprod',
    },
  ],
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
    {
      name: 'sandbox',
      labelKey: 'settings.providerCredentials.field.sandbox',
      kind: 'toggle',
      // `selector_bool(&entry, "sandbox", true)` — absent means ON at the server, so that is what
      // a stored entry without the key is showing.
      defaultOn: true,
      // …but a new entry is not created sandboxed. Sandbox relaxes `CscConfig::validate` to accept
      // `http://localhost` in place of required HTTPS, and inheriting that silently from an omitted
      // key is not a choice the operator made. Written explicitly so the server default cannot
      // apply, and freely switchable back on for a genuine test endpoint.
      newEntryOn: false,
    },
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

export function ProtectionBanner({
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

/**
 * The selectors a NEW entry starts with — the toggles that declare a {@link
 * SelectorFieldSpec.newEntryOn} and the selectors that declare a {@link
 * SelectorFieldSpec.requiredDefault}.
 *
 * Seeding a value here is what stops the server's absent-key default from deciding a security
 * posture nobody chose: `buildSelectors` keeps any non-empty value, so `'false'` survives to the
 * request body and `selector_bool` reads a real answer rather than falling back. Selectors with
 * neither stay absent, which is still the right shape for the ones whose "unset" is a genuine third
 * state (`authorization`, SCAP's `environment`) rather than a boolean.
 */
function initialSelectors(mode: CredentialMode): Record<string, string> {
  const out: Record<string, string> = {};
  for (const spec of SELECTOR_FIELDS[mode]) {
    if (spec.kind === 'toggle' && spec.newEntryOn !== undefined)
      out[spec.name] = spec.newEntryOn ? 'true' : 'false';
    if (spec.requiredDefault !== undefined) out[spec.name] = spec.requiredDefault;
  }
  return out;
}

/**
 * Fill in the {@link SelectorFieldSpec.requiredDefault} of any selector an EXISTING entry does not
 * carry, so the form shows — and resubmits — the value already in force.
 *
 * This is the one deliberate exception to the rule stated where the edit form loads its state (an
 * entry's absent selector stays absent). It is allowed here, and only here, because
 * `requiredDefault` is defined as *the value the server already resolves an absent selector to*:
 * putting it in the form displays what is in force rather than a create-time preference, and
 * resubmitting it writes the same outcome the entry already had. That is what lets the deployment
 * fallback be retired without any stored credential changing environment.
 *
 * It never applies to `newEntryOn`, which genuinely is a create-time preference and would rewrite a
 * stored posture on an unrelated edit.
 */
function withRequiredSelectorDefaults(
  mode: CredentialMode,
  selectors: Record<string, string>,
): Record<string, string> {
  const out = { ...selectors };
  for (const spec of SELECTOR_FIELDS[mode]) {
    if (spec.requiredDefault === undefined) continue;
    if (!out[spec.name]?.trim()) out[spec.name] = spec.requiredDefault;
  }
  return out;
}

function emptyForm(mode: CredentialMode): EntryFormState {
  return {
    mode,
    providerId: '',
    label: '',
    enabled: true,
    endpoint: '',
    selectors: initialSelectors(mode),
    secrets: {},
    pfxBase64: '',
    pfxName: '',
  };
}

export function ProviderCredentialEntryForm({
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

  const baselineRef = useRef<EntryFormState | null>(null);
  const savedRef = useRef(false);
  const [form, setForm] = useState<EntryFormState>(() => {
    const base = emptyForm(mode);
    if (existing) {
      base.label = existing.label;
      base.enabled = existing.enabled;
      base.endpoint = existing.endpoint ?? '';
      // REPLACES the seed from `initialSelectors`, rather than merging over it. An edit must show
      // and resubmit the entry as stored: `update_entry` swaps the whole selector map for whatever
      // the form sends, so merging a create-time default in here would silently rewrite a stored
      // entry's sandbox posture on any unrelated edit — a label change flipping HTTPS enforcement.
      // An entry whose selector is absent therefore keeps it absent, and the server keeps applying
      // the same default it applies today.
      //
      // `withRequiredSelectorDefaults` is the single, narrow exception, and it does not break that
      // rule so much as satisfy it by another route: a `requiredDefault` IS the value the server
      // applies today, so filling it in shows and resubmits the same outcome the entry already has.
      // See its doc comment for why that distinction is load-bearing.
      base.selectors = withRequiredSelectorDefaults(mode, existing.selectors);
    }
    if (providerId !== undefined) base.providerId = providerId;
    baselineRef.current = base;
    return base;
  });
  const dirty = JSON.stringify(form) !== JSON.stringify(baselineRef.current);
  useUnsavedChanges(dirty && !savedRef.current);

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
      if (!value || value.length === 0) continue;
      // The AMA certificate is the one field here that cannot legitimately be whitespace, and the
      // server now refuses a candidate that is nothing but whitespace. Treating it as untouched
      // keeps a stray newline in the textarea from blocking a metadata-only edit; a password of
      // all spaces is a different matter and is still submitted verbatim.
      if (spec.name === AMA_CERT_PEM_FIELD && value.trim().length === 0) continue;
      set[spec.name] = value;
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
            savedRef.current = true;
            allowNextNavigation();
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
          savedRef.current = true;
          allowNextNavigation();
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
          // The two endpoint-bearing modes disagree about what this field IS, so they cannot share
          // one sentence. SCAP defaults the address per environment and this overrides it
          // (`AmaScapConfig` falls back to `ScapEnvironment::default_base_url`). CSC has no default
          // at all: `probe_csc` fails the entry `configuration_incomplete` without one, and
          // `CscConfig::validate` additionally requires https unless the sandbox flag is on and the
          // host is localhost. Calling it an "override" is true for SCAP and false for CSC.
          <Field
            label={t('settings.providerCredentials.form.endpoint')}
            htmlFor={`${idBase}-endpoint`}
            hint={
              effectiveMode === 'csc'
                ? t('settings.providerCredentials.form.endpointHint.csc')
                : t('settings.providerCredentials.form.endpointHint')
            }
            help={
              effectiveMode === 'csc'
                ? providerCredentialsFieldHelp.endpointCsc
                : providerCredentialsFieldHelp.endpoint
            }
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
                checked={selectorBool(form.selectors[spec.name], spec.defaultOn ?? false)}
                onChange={(on) => setSelector(spec.name, on ? 'true' : 'false')}
              />
            );
          }
          if (spec.kind === 'env' || spec.kind === 'authorization') {
            const options =
              spec.kind === 'env'
                ? [
                    // "Not set" means "fall back to the deployment default". CMD no longer has one
                    // an operator can see or change, so for CMD the option is not offered: a
                    // choice whose outcome is invisible is worse than no choice. SCAP keeps it —
                    // its absent selector is a genuine third state with its own documented default.
                    ...(spec.requiredDefault === undefined
                      ? [{ value: '', label: t('settings.providerCredentials.field.env.unset') }]
                      : []),
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
          // The AMA certificate is the one field here that is not a secret at all — it is a public
          // certificate, and it is multi-line. It gets its own control (t112) so it can be pasted,
          // loaded from a file, read back, and inspected; see {@link AmaCertPemField}.
          if (spec.name === AMA_CERT_PEM_FIELD) {
            return (
              <AmaCertPemField
                key={spec.name}
                id={id}
                labelKey={spec.labelKey}
                isEdit={isEdit}
                value={form.secrets[spec.name] ?? ''}
                onChange={(value) => setSecret(spec.name, value)}
              />
            );
          }
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
            perm="signing.configure"
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

/** The credential field this section gives its own control to. */
const AMA_CERT_PEM_FIELD = 'ama_cert_pem';

/**
 * Extensions offered by both the browser `accept` and the Tauri dialog filter.
 *
 * `.pub` is here because the field takes a bare `PUBLIC KEY` block as well as a certificate, and a
 * picker that hides the file an operator was actually sent is the same dead end in a different
 * place. Notably absent is `.key`, which conventionally names a PRIVATE key: offering it would
 * invite the one paste this field must never accept. The filter is a convenience either way — the
 * server reads the content and refuses anything that is not one of the two accepted armours.
 */
const CERT_FILE_EXTENSIONS = ['pem', 'crt', 'cer', 'pub'];

/**
 * The client-side ceiling, in bytes, on a file loaded into the field.
 *
 * Deliberately the same 64 KiB the server refuses at, so the two agree and an operator does not
 * pass one gate only to be turned away by the other. Checked BEFORE the bytes are read: a picker
 * will hand back a multi-gigabyte file, and reading it into a string freezes the tab before any
 * validation runs.
 */
const CERT_FILE_MAX_BYTES = 64 * 1024;

/** A one-line, in-place outcome for a file/clipboard action. Never a toast that scrolls away. */
interface FieldNotice {
  tone: 'ok' | 'error';
  text: string;
}

/**
 * What the server established about candidate key material, and the four things it did not.
 *
 * The negatives are a grid of explicit "No" values rather than an omitted disclaimer — the same
 * construction the probe panel uses, and for the same reason. There is deliberately no "valid"
 * badge anywhere in here: parsing, carrying an RSA key and being in date are the three things the
 * server actually checked, and none of them establishes that this is AMA's key.
 *
 * # Two armours, and why the panel must not blur them
 *
 * The field takes a `CERTIFICATE` block or the bare `PUBLIC KEY` inside one. The two carry the same
 * key and a different amount of surrounding fact, so this panel states which arrived, and for a
 * public key it renders the *absence* of subject, issuer and dates as a finding rather than as four
 * empty rows. Blank rows on what an operator believes is a certificate read as a damaged file.
 *
 * # Two fingerprints, and why both are labelled
 *
 * The SHA-256 of a certificate's DER and the SHA-256 of the public key inside it are different
 * numbers for the same key. The public-key one is shown for both armours — it is the material
 * actually used to encrypt, and the only value that matches across the two input forms. The
 * certificate one is shown as well when there is a certificate, because that is the number
 * `openssl x509 -fingerprint -sha256` prints. Neither is ever shown unlabelled: an operator
 * comparing against a published value has to know which they are looking at.
 */
function AmaCertInspectPanel({ report }: { report: AmaCertificateInspectResponse }) {
  const t = useT();
  const pt = useProviderCredentialsT();
  const locale = useActiveLocale();
  const no = pt('providerCredentials.probe.no');
  const formatMoment = (value: string | undefined) => (value ? formatDateTime(value, locale) : '—');
  const isCertificate = report.input_kind === 'certificate';

  return (
    <section className="stack stack--tight" data-testid="ama-cert-inspect-result">
      <h4 className="card__label">
        {t('settings.providerCredentials.field.amaCertPem.inspect.resultTitle')}
      </h4>
      <ul className="stack">
        {report.checks.map((probeCheck, index) => (
          <li key={`${probeCheck.name}:${index}`} data-check={probeCheck.name}>
            <Badge
              tone={
                probeCheck.status === 'passed'
                  ? 'ok'
                  : probeCheck.status === 'failed'
                    ? 'error'
                    : 'neutral'
              }
            >
              {pt(`providerCredentials.probe.check.${probeCheck.status}`)}
            </Badge>{' '}
            <ProbeDetailText check={probeCheck} />
          </li>
        ))}
      </ul>
      {/* Which artefact this is, stated before anything is said about it. Everything below reads
          differently depending on the answer, and an operator who pasted the wrong one of the two
          finds out here rather than from a row that is mysteriously empty. */}
      {report.input_kind ? (
        <dl className="detail-grid">
          <div>
            <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.inputKind')}</dt>
            <dd data-testid="ama-cert-input-kind">
              {t(
                isCertificate
                  ? 'settings.providerCredentials.field.amaCertPem.inspect.inputKind.certificate'
                  : 'settings.providerCredentials.field.amaCertPem.inspect.inputKind.publicKey',
              )}
            </dd>
          </div>
        </dl>
      ) : null}
      {/* The fingerprints lead, and sit outside the subject/issuer grid on purpose. They are the
          only values on this panel an operator can CHECK — everything below is copied out of the
          input itself and would read the same on a substituted one. Each is labelled with what it
          covers, because the two are different numbers for the same key and comparing the wrong one
          against a published value fails for no reason. The sentence beneath says who has to do the
          comparing, because the server does not and must not look like it did. */}
      {report.public_key_sha256_fingerprint ? (
        <div className="stack stack--tight">
          <dl className="detail-grid">
            <div>
              <dt>
                {t('settings.providerCredentials.field.amaCertPem.inspect.publicKeyFingerprint')}
              </dt>
              <dd className="mono" data-testid="ama-cert-public-key-fingerprint">
                {report.public_key_sha256_fingerprint}
              </dd>
            </div>
            {report.certificate_sha256_fingerprint ? (
              <div>
                <dt>
                  {t(
                    'settings.providerCredentials.field.amaCertPem.inspect.certificateFingerprint',
                  )}
                </dt>
                <dd className="mono" data-testid="ama-cert-certificate-fingerprint">
                  {report.certificate_sha256_fingerprint}
                </dd>
              </div>
            ) : null}
          </dl>
          <p className="field__hint">
            {t('settings.providerCredentials.field.amaCertPem.inspect.fingerprintHint')}
          </p>
        </div>
      ) : null}
      {/* Subject, issuer and dates exist only inside a certificate. For a bare public key the grid
          is not rendered at all, and the `certificate_fields` finding above says why — an empty
          grid would claim those fields were there and could not be read. */}
      {report.parsed && isCertificate ? (
        <dl className="detail-grid">
          <div>
            <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.subject')}</dt>
            <dd className="mono">{report.subject ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.issuer')}</dt>
            <dd className="mono">{report.issuer ?? '—'}</dd>
          </div>
          <div>
            <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.notBefore')}</dt>
            <dd>{formatMoment(report.not_before)}</dd>
          </div>
          <div>
            <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.notAfter')}</dt>
            <dd>{formatMoment(report.not_after)}</dd>
          </div>
        </dl>
      ) : null}
      <h4 className="card__label">
        {t('settings.providerCredentials.field.amaCertPem.inspect.notCheckedTitle')}
      </h4>
      <dl className="detail-grid">
        <div>
          <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.chainValidated')}</dt>
          <dd>{report.chain_validated ? pt('providerCredentials.probe.yes') : no}</dd>
        </div>
        <div>
          <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.trustedListChecked')}</dt>
          <dd>{report.trusted_list_checked ? pt('providerCredentials.probe.yes') : no}</dd>
        </div>
        <div>
          <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.issuerAuthenticated')}</dt>
          <dd>{report.issuer_authenticated ? pt('providerCredentials.probe.yes') : no}</dd>
        </div>
        <div>
          <dt>{t('settings.providerCredentials.field.amaCertPem.inspect.legalValidityClaimed')}</dt>
          <dd>{report.legal_validity_claimed ? pt('providerCredentials.probe.yes') : no}</dd>
        </div>
      </dl>
    </section>
  );
}

/**
 * The `ama_cert_pem` control (t112): paste, load from a file, or inspect what you pasted.
 *
 * Takes either armour AMA's field-encryption key arrives in — a `CERTIFICATE` block or the bare
 * `PUBLIC KEY` inside one. The stored field name is unchanged and still says `cert`: it is a stored
 * credential key and a documented environment variable, and renaming it would break every existing
 * installation to fix a word. The label, the hint and the help text say what is actually accepted.
 *
 * # Why this field is not the generic secret `<Input type="password">`
 *
 * It is the only entry in `SECRET_FIELDS` that is **not a secret**. A certificate and a public key
 * are both public material; they ride the encrypted credential store because everything in that
 * store does, not because their contents need hiding. Masking it made the one field an operator most
 * needs to *look at* — to check they pasted the right thing, and the whole point of the inspect
 * action — unreadable, and PEM is multi-line, which a single-line masked input mangles. So it is a
 * visible `<TextArea>`. The write-only posture is unchanged: the value still only ever travels
 * inwards, the API still never returns it, and it is still cleared from component state on submit.
 *
 * # Content, never a path
 *
 * Everything here produces the key material's TEXT. `ama_cert_pem` stores that text itself;
 * `CHANCELA_CMD_AMA_CERT_PEM` is the environment route and names a *file* for the server to read.
 * The hint says so, and {@link ../../desktop/openTextFile} does not return a path at all, so the
 * confusion is hard to write by accident.
 *
 * # The three affordances, and their failure paths
 *
 * - **File.** Under Tauri, the native dialog via the same `isTauri()` + dynamic-`import()` idiom
 *   `saveFile.ts` established; in a browser, an ordinary `<input type="file">` with an `accept` for
 *   `.pem`/`.crt`/`.cer`. Both bound the size *before* reading.
 * - **Clipboard.** `navigator.clipboard.readText()`, with insecure-context, permission-denied and
 *   empty reported as three distinct visible notices — the rule `DiagnosticsSection.copyReport`
 *   set for the write direction, applied to the read direction. Never a silent no-op.
 * - **Inspect.** A server round-trip, because the parser that matters is the Rust one the signing
 *   path uses. See {@link AmaCertInspectPanel} for what it may and may not say.
 */
function AmaCertPemField({
  id,
  labelKey,
  isEdit,
  value,
  onChange,
}: {
  id: string;
  labelKey: MessageKey;
  isEdit: boolean;
  value: string;
  onChange: (value: string) => void;
}) {
  const t = useT();
  const inspect = useInspectAmaCertificate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [notice, setNotice] = useState<FieldNotice | null>(null);
  const noticeId = `${id}-notice`;

  /** Map an {@link OpenTextFileResult} onto the field, saying WHY nothing happened when nothing did. */
  function applyFileResult(result: OpenTextFileResult) {
    switch (result.kind) {
      case 'opened':
        onChange(result.text);
        inspect.reset();
        setNotice({
          tone: 'ok',
          text: t('settings.providerCredentials.field.amaCertPem.fileLoaded', {
            name: result.name,
          }),
        });
        return;
      case 'too-large':
        setNotice({
          tone: 'error',
          text: t('settings.providerCredentials.field.amaCertPem.fileTooLarge', {
            max: Math.floor(CERT_FILE_MAX_BYTES / 1024),
          }),
        });
        return;
      case 'unreadable':
      case 'unavailable':
        setNotice({
          tone: 'error',
          text: t('settings.providerCredentials.field.amaCertPem.fileReadFailed'),
        });
        return;
      // A cancelled dialog is not a failure and gets no notice.
      case 'cancelled':
        return;
    }
  }

  async function chooseFile() {
    if (isTauri()) {
      const result = await openTextFileNative({
        filterName: t('settings.providerCredentials.field.amaCertPem.fileFilter'),
        extensions: CERT_FILE_EXTENSIONS,
        maxBytes: CERT_FILE_MAX_BYTES,
      });
      // `unavailable` under Tauri means the plugins would not load; fall through to the browser
      // input rather than leaving the operator with a button that does nothing.
      if (result.kind !== 'unavailable') {
        applyFileResult(result);
        return;
      }
    }
    fileInputRef.current?.click();
  }

  async function pasteFromClipboard() {
    const result = await readClipboardText();
    if (result.kind === 'read') {
      onChange(result.text);
      inspect.reset();
      setNotice({
        tone: 'ok',
        text: t('settings.providerCredentials.field.amaCertPem.clipboardPasted'),
      });
      return;
    }
    const key =
      result.kind === 'unavailable'
        ? 'settings.providerCredentials.field.amaCertPem.clipboardUnavailable'
        : result.kind === 'denied'
          ? 'settings.providerCredentials.field.amaCertPem.clipboardDenied'
          : 'settings.providerCredentials.field.amaCertPem.clipboardEmpty';
    setNotice({ tone: 'error', text: t(key) });
  }

  function runInspection() {
    const candidate = value.trim();
    if (candidate.length === 0) {
      setNotice({
        tone: 'error',
        text: t('settings.providerCredentials.field.amaCertPem.empty'),
      });
      return;
    }
    setNotice(null);
    inspect.mutate(candidate);
  }

  return (
    <Field
      label={t(labelKey)}
      htmlFor={id}
      help={providerCredentialFieldHelp(AMA_CERT_PEM_FIELD)}
      hint={
        isEdit
          ? t('settings.providerCredentials.form.keepFieldHint')
          : t('settings.providerCredentials.field.amaCertPem.hint')
      }
    >
      <div className="stack stack--tight">
        <TextArea
          id={id}
          rows={6}
          className="mono"
          value={value}
          autoComplete="off"
          spellCheck={false}
          aria-describedby={notice ? noticeId : undefined}
          onChange={(e) => {
            onChange(e.target.value);
            // A finding describes the text it was run against; editing invalidates it, and leaving
            // a stale verdict beside changed input is worse than showing none.
            inspect.reset();
            setNotice(null);
          }}
        />
        {/* Kept mounted rather than created on demand: an `<input type="file">` that is in the
            DOM is reachable by keyboard and by assistive tech, and `.click()` on it is the same
            gesture a browser trusts. Under Tauri it is the fallback the native path degrades to. */}
        <input
          ref={fileInputRef}
          type="file"
          className="sr-only"
          accept={acceptAttribute(CERT_FILE_EXTENSIONS)}
          data-testid="ama-cert-file-input"
          onChange={(e) => {
            const file = e.target.files?.[0];
            // Reset the input so choosing the SAME file twice fires `change` again.
            e.target.value = '';
            if (!file) return;
            void readPickedTextFile(file, CERT_FILE_MAX_BYTES).then(applyFileResult);
          }}
        />
        <span className="row-wrap">
          <Button
            type="button"
            variant="secondary"
            data-testid="ama-cert-from-file"
            onClick={() => void chooseFile()}
          >
            {t('settings.providerCredentials.field.amaCertPem.fromFile')}
          </Button>
          <Button
            type="button"
            variant="secondary"
            data-testid="ama-cert-from-clipboard"
            onClick={() => void pasteFromClipboard()}
          >
            {t('settings.providerCredentials.field.amaCertPem.fromClipboard')}
          </Button>
          <GateButton
            perm="signing.configure"
            type="button"
            variant="secondary"
            disabled={inspect.isPending}
            data-testid="ama-cert-inspect"
            onClick={runInspection}
          >
            {inspect.isPending
              ? t('settings.providerCredentials.field.amaCertPem.inspecting')
              : t('settings.providerCredentials.field.amaCertPem.inspect')}
          </GateButton>
        </span>
        {notice ? (
          <p
            id={noticeId}
            className={notice.tone === 'error' ? 'field__error' : 'field__hint'}
            role={notice.tone === 'error' ? 'alert' : 'status'}
          >
            {notice.text}
          </p>
        ) : null}
        {/* A failed request is shown where a result would be, never swallowed. */}
        {inspect.error ? <ErrorNote error={inspect.error} /> : null}
        {inspect.data ? <AmaCertInspectPanel report={inspect.data} /> : null}
      </div>
    </Field>
  );
}

/**
 * One check's sentence, in the operator's language when the server named it with a code.
 *
 * When it did NOT — an unrecognised code, or a server older than the code vocabulary — the raw
 * English is shown with a visible `In English` badge and `lang="en"` (so a screen reader
 * pronounces it as English rather than mangling it in the page language). That marking is the
 * point: a silent fallback would pass the server's English off as localized copy and make the
 * next backend-added code invisible instead of loud.
 */
function ProbeDetailText({ check }: { check: ProviderCredentialProbeCheck }) {
  const t = useT();
  const detail = resolveProbeDetail(check, t);
  if (!detail.untranslated) return <>{detail.text}</>;
  return (
    <>
      <span lang="en">{detail.text}</span>{' '}
      {/* The badge is a real tab stop carrying the explanation on `aria-describedby` (the
          `ColumnHead`/`FieldHelp` arrangement), so the marking is keyboard-reachable and not
          hover-only. */}
      <Badge tone="neutral">
        <TooltipText
          label={t('settings.providerCredentials.probe.untranslatedHint')}
          onlyWhenClipped={false}
        >
          {t('settings.providerCredentials.probe.untranslatedBadge')}
        </TooltipText>
      </Badge>
    </>
  );
}

/**
 * One check's ROW LABEL, in the operator's language.
 *
 * This is the half the first pass at these diagnostics missed. The label rendered as the server's
 * raw `name` — `trusted_list_anchors`, `stored_credential_fields` — in `mono`, directly above a
 * fully translated sentence, in every locale. The `mono` made it look deliberate, which is exactly
 * what made it survive: this codebase does render some identifiers verbatim on purpose, and an
 * accidentally-untranslated one dressed the same way is indistinguishable from those.
 *
 * So a known name is ordinary prose in the page language, with no `mono`. A name this build does
 * not know keeps the identifier, keeps the `mono` — because at that point it genuinely IS a raw
 * identifier — and gets the same `In English` badge and `lang="en"` the unknown-code path uses.
 * The marking is the point: a silent fallback would make the next backend-added name invisible.
 */
function ProbeCheckLabel({ check }: { check: ProviderCredentialProbeCheck }) {
  const t = useT();
  const label = resolveProbeCheckName(check, t);
  if (!label.untranslated) return <strong>{label.text}</strong>;
  return (
    <>
      <strong className="mono" lang="en">
        {label.text}
      </strong>{' '}
      <Badge tone="neutral">
        <TooltipText
          label={t('settings.providerCredentials.probe.untranslatedHint')}
          onlyWhenClipped={false}
        >
          {t('settings.providerCredentials.probe.untranslatedBadge')}
        </TooltipText>
      </Badge>
    </>
  );
}

/**
 * The per-check log and the honest legal-status grid. Rendered inside
 * {@link ProviderCredentialProbeModal}; kept a separate component so the panel and the dialog
 * chrome stay independently readable.
 */
export function ProviderCredentialProbeResult({
  result,
}: {
  result: ProviderCredentialProbeResponse;
}) {
  const t = useT();
  const pt = useProviderCredentialsT();
  const yesNo = (value: boolean) =>
    pt(value ? 'providerCredentials.probe.yes' : 'providerCredentials.probe.no');
  return (
    <div className="stack" data-testid="provider-probe-result">
      <p className="field__hint">{pt('providerCredentials.probe.disclaimer')}</p>
      <dl className="detail-grid">
        <div>
          <dt>{pt('providerCredentials.probe.contacted')}</dt>
          <dd>{yesNo(result.provider_contacted)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.probe.keyOperation')}</dt>
          <dd>{yesNo(result.private_key_operation_performed)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.probe.signerAuthorization')}</dt>
          <dd>{yesNo(result.signer_authorization_requested)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.probe.documentSigned')}</dt>
          <dd>{yesNo(result.document_signed)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.probe.legalValidity')}</dt>
          <dd>{yesNo(result.legal_validity_claimed)}</dd>
        </div>
        <div>
          <dt>{pt('providerCredentials.probe.qualifiedStatus')}</dt>
          <dd>{yesNo(result.qualified_status_determined)}</dd>
        </div>
      </dl>
      <h3 className="card__label">{t('settings.providerCredentials.probe.modal.checksTitle')}</h3>
      <ul className="stack">
        {result.checks.map((probeCheck, index) => (
          <li key={`${probeCheck.name}:${index}`} data-check={probeCheck.name}>
            <Badge
              tone={
                probeCheck.status === 'passed'
                  ? 'ok'
                  : probeCheck.status === 'failed'
                    ? 'error'
                    : 'neutral'
              }
            >
              {pt(`providerCredentials.probe.check.${probeCheck.status}`)}
            </Badge>{' '}
            <ProbeCheckLabel check={probeCheck} /> — <ProbeDetailText check={probeCheck} />
          </li>
        ))}
      </ul>
      <p className="field__hint">
        {pt('providerCredentials.probe.duration', {
          duration: result.duration_ms,
          timestamp: result.tested_at,
        })}
      </p>
    </div>
  );
}

/**
 * Progress and the per-check log for one credential test, in a dialog (t112).
 *
 * Before this the pending state and the whole result panel rendered *inside the table cell* the
 * action button sits in, which reflowed the grid mid-run and buried a seven-line diagnostic in a
 * column. The dialog is the same chrome `ConfirmActionModal` uses, for the same reasons:
 *
 * - `useFocusTrap(open)` moves focus into the dialog and **restores it to the trigger** on close;
 * - Escape closes, but never mid-request — a probe that performs a private-key operation must not
 *   be abandoned in an unknown state, exactly as the destructive-confirm dialog treats its submit;
 * - it is portaled to `document.body`, so the fixed backdrop escapes the routed content's
 *   transformed ancestor.
 *
 * **It does not soften a failure.** A failed check keeps its `error` badge and its own sentence, a
 * failed request renders `ErrorNote` in the same place a result would, and the honest
 * `document_signed` / `legal_validity_claimed` / `qualified_status_determined` negatives are shown
 * whatever the outcome. Nothing here converts a negative verdict into a neutral one.
 */
export function ProviderCredentialProbeModal({
  open,
  onClose,
  pending,
  result,
  error,
  onRerun,
}: {
  open: boolean;
  onClose: () => void;
  pending: boolean;
  result: ProviderCredentialProbeResponse | undefined;
  error: unknown;
  /** Omitted when the operator may not re-run (permission, or a disabled entry). */
  onRerun?: () => void;
}) {
  const t = useT();
  const pt = useProviderCredentialsT();
  const trapRef = useFocusTrap<HTMLDivElement>(open);
  const titleId = useRef(`probe-${Math.random().toString(36).slice(2)}`).current;

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !pending) onClose();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, pending, onClose]);

  if (!open) return null;

  const statusLabel = !result
    ? null
    : result.status === 'ok'
      ? pt('providerCredentials.probe.ok')
      : result.status === 'interactive_required'
        ? pt('providerCredentials.probe.interactive')
        : pt('providerCredentials.probe.failed');

  return createPortal(
    <div
      className="modal-backdrop"
      onClick={() => {
        if (!pending) onClose();
      }}
    >
      <div
        ref={trapRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-testid="provider-probe-modal"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="modal__head">
          <h2 className="modal__title" id={titleId}>
            {t('settings.providerCredentials.probe.modal.title')}
          </h2>
          {statusLabel ? (
            <Badge
              tone={result?.status === 'ok' ? 'ok' : result?.status === 'failed' ? 'error' : 'warn'}
            >
              {statusLabel}
            </Badge>
          ) : null}
        </header>
        <div className="modal__body">
          {pending ? (
            <div className="stack stack--tight" role="status" aria-live="polite">
              <p className="card__label">
                {t('settings.providerCredentials.probe.modal.runningTitle')}
              </p>
              <p className="field__hint">
                {t('settings.providerCredentials.probe.modal.runningBody')}
              </p>
            </div>
          ) : null}
          {/* A request that never produced a result is as visible as one that did, in the same
              place — never a toast the dialog swallows. */}
          {!pending && error ? <ErrorNote error={error} /> : null}
          {!pending && result ? <ProviderCredentialProbeResult result={result} /> : null}
        </div>
        <div className="modal__foot">
          <Button type="button" variant="ghost" disabled={pending} onClick={onClose}>
            {t('settings.providerCredentials.probe.modal.close')}
          </Button>
          {onRerun ? (
            <Button type="button" variant="secondary" disabled={pending} onClick={onRerun}>
              {t('settings.providerCredentials.probe.modal.rerun')}
            </Button>
          ) : null}
        </div>
      </div>
    </div>,
    document.body,
  );
}

export function Pkcs12ProbeConfirmModal({
  open,
  pending,
  onClose,
  onConfirm,
}: {
  open: boolean;
  pending: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
}) {
  const pt = useProviderCredentialsT();
  return (
    <ConfirmActionModal
      open={open}
      onClose={onClose}
      title={pt('providerCredentials.probe.pkcs12.confirmTitle')}
      intro={pt('providerCredentials.probe.pkcs12.confirmIntro')}
      confirmLabel={pt('providerCredentials.probe.pkcs12.confirm')}
      pendingLabel={pt('providerCredentials.probe.pkcs12.pending')}
      pending={pending}
      onConfirm={onConfirm}
    />
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
  const probe = useProbeProviderCredentialEntry();
  const pt = useProviderCredentialsT();
  const can = useCan();
  const [confirming, setConfirming] = useState(false);
  const [confirmingProbe, setConfirmingProbe] = useState(false);
  const [probeOpen, setProbeOpen] = useState(false);

  const providerId = group.provider_id;
  const canPerformProbe = group.mode !== 'pkcs12' || can('signing.perform');

  // The dialog owns progress and the log; the mutation's own error is rendered INSIDE it rather
  // than toasted away, so a request that never produced a result is as visible as one that did.
  function runProbe() {
    setProbeOpen(true);
    probe.mutate({ mode: group.mode, providerId, entryId: entry.entry_id });
  }

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

  const busy = reorder.isPending || del.isPending || update.isPending || probe.isPending;
  const label = entry.label || t('settings.providerCredentials.entry.unlabeled');

  return (
    <tr role="group" aria-label={entry.label || entry.entry_id}>
      {/* The id is clipped to a fixed character count by CSS, never sliced: the full GUID stays in
          the DOM (selectable, copyable, findable by find-in-page, announced whole by a screen
          reader) while the row stops being dominated by it. `TooltipText` auto-detects that the
          label merely repeats the rendered string, so it reveals the full value on hover exactly
          when the cap engages and renders bare when it does not. */}
      <td
        className="provider-entries-table__cell--id"
        data-label={t('settings.providerCredentials.table.entry')}
      >
        <p className="card__label">{label}</p>
        <TooltipText label={entry.entry_id} as="code" className="field__hint mono truncate">
          {entry.entry_id}
        </TooltipText>
      </td>
      {/* The badge shows the bare rank: the column header and the responsive `data-label` both
          already say "prioridade", so repeating the word inside every badge of the column was
          duplication that cost the row width and said nothing. The full statement stays in the
          accessibility tree — same split as the CMD field badges below, because a badge read as a
          context-free "1" out of the column's visual context is worse than a long one. */}
      <td data-label={t('settings.providerCredentials.table.priority')}>
        <Badge tone="neutral">
          <span aria-hidden="true">{entry.priority}</span>
          <span className="sr-only">
            {t('settings.providerCredentials.entry.priority', { priority: entry.priority })}
          </span>
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
          <span className="muted">{t(EMPTY_ENDPOINT_KEYS[group.mode])}</span>
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
            entry.fields.map((f) => {
              const stateWord = f.configured
                ? t('settings.providerCredentials.entry.configured')
                : t('settings.providerCredentials.entry.notConfigured');
              // CMD fields carry a compact `LABEL · ok / não ok` badge. The abbreviation is a
              // verbatim identifier (the same token in every locale), so only the state word is
              // translated. The visible text stays terse; the badge's accessible name spells the
              // field and its state out in full so a screen reader and a colour-blind operator both
              // get more than a colour and a four-letter token. Other modes keep the descriptive
              // field name unchanged.
              const abbr = group.mode === 'cmd' ? CMD_FIELD_ABBREVIATIONS[f.field_name] : undefined;
              if (abbr) {
                return (
                  <Badge key={f.field_name} tone={f.configured ? 'ok' : 'neutral'}>
                    <span aria-hidden="true">
                      {abbr} ·{' '}
                      {f.configured
                        ? t('settings.providerCredentials.entry.ok')
                        : t('settings.providerCredentials.entry.notOk')}
                    </span>
                    <span className="sr-only">{`${abbr}: ${stateWord}`}</span>
                  </Badge>
                );
              }
              return (
                <Badge key={f.field_name} tone={f.configured ? 'ok' : 'neutral'}>
                  {f.field_name} · {stateWord}
                </Badge>
              );
            })
          )}
        </span>
      </td>
      <td data-label={t('settings.providerCredentials.table.actions')}>
        <span className="row-wrap">
          <GateIconButton
            perm="signing.configure"
            icon={<Icon.ArrowUp />}
            label={t('settings.providerCredentials.entry.moveUp')}
            disabled={busy || index === 0}
            onClick={() => move(-1)}
          />
          <GateIconButton
            perm="signing.configure"
            icon={<Icon.ArrowDown />}
            label={t('settings.providerCredentials.entry.moveDown')}
            disabled={busy || index === count - 1}
            onClick={() => move(1)}
          />
          <GateIconButton
            perm="signing.configure"
            icon={<Icon.Pencil />}
            label={t('settings.providerCredentials.entry.edit')}
            disabled={busy}
            onClick={onEdit}
          />
          {/* Distinct glyph per meaning, per the icon-only rule: the safe configuration test is a
              diagnostic (wrench); the CMD control below produces a REAL signature (pen nib). */}
          <GateIconButton
            perm="signing.configure"
            icon={<Icon.Wrench />}
            label={
              canPerformProbe
                ? t('settings.providerCredentials.entry.test')
                : pt('providerCredentials.probe.pkcs12.permission')
            }
            disabled={busy || !canPerformProbe}
            data-testid="provider-probe-run"
            onClick={() => (group.mode === 'pkcs12' ? setConfirmingProbe(true) : runProbe())}
          />
          <GateIconButton
            perm="signing.configure"
            icon={<Icon.Trash />}
            label={t('common.remove')}
            disabled={busy}
            data-testid="provider-entry-remove"
            onClick={() => setConfirming(true)}
          />
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
        {/* The PKCS#12 gate is unchanged: the key operation is still confirmed BEFORE anything
            runs. Only once it is granted does the progress dialog take over, so the two never
            stack on top of one another. */}
        <Pkcs12ProbeConfirmModal
          open={group.mode === 'pkcs12' && confirmingProbe}
          pending={probe.isPending}
          onClose={() => setConfirmingProbe(false)}
          onConfirm={async () => {
            setConfirmingProbe(false);
            runProbe();
          }}
        />
        <ProviderCredentialProbeModal
          open={probeOpen}
          onClose={() => setProbeOpen(false)}
          pending={probe.isPending}
          result={probe.data}
          error={probe.error}
          onRerun={
            canPerformProbe && group.mode !== 'pkcs12'
              ? () => probe.mutate({ mode: group.mode, providerId, entryId: entry.entry_id })
              : undefined
          }
        />
        {/* The CMD PRODUCTION test signature (t51-e3/t69) is deliberately its own control, never
            folded into the safe probe button above: a completed run costs one real qualified
            signature against AMA's live service, so it needs its own gate and its own space. */}
        {group.mode === 'cmd' ? (
          <CmdTestSignatureAction entry={entry} canPerform={can('signing.perform')} />
        ) : null}
      </td>
    </tr>
  );
}

function ProviderGroupCard({ group }: { group: ProviderCredentialGroupView }) {
  const t = useT();
  const navigate = useNavigate();
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
          perm="signing.configure"
          variant="secondary"
          icon={<Icon.Plus />}
          onClick={() => navigate(providerCredentialCreatePath(group.mode, group.provider_id))}
        >
          {t('settings.providerCredentials.provider.addEntry')}
        </GateButton>
      }
    >
      <p className="field__hint">{t('settings.providerCredentials.failoverHint')}</p>

      {entries.length === 0 ? (
        <EmptyState title={t('settings.providerCredentials.provider.noEntries')} />
      ) : (
        <Table
          caption={t('settings.providerCredentials.table.caption', { provider: title })}
          head={
            <tr>
              {ENTRY_COLUMNS.map((column) => (
                <ColumnHead
                  key={column.labelKey}
                  label={t(column.labelKey)}
                  help={t(column.helpKey)}
                />
              ))}
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
              onEdit={() =>
                navigate(providerCredentialEditPath(group.mode, group.provider_id, entry.entry_id))
              }
            />
          ))}
        </Table>
      )}
    </Card>
  );
}

/**
 * The modes overview (t105) — one row per credential mode, **including modes with nothing
 * configured**, which is the whole point of it.
 *
 * ## The gap it closes
 *
 * Everything above this card is driven by `data.providers`, so a mode the operator has never
 * touched renders *nothing at all*: there is no card, no header, no hint that `scap` exists. The
 * only way in was the top-level "new entry" form's mode dropdown, which an operator has to already
 * know to open. This table is built from {@link MODES} instead of from the response, so all four
 * modes are always listed and each has its own way in — `providerCredentialCreatePath(mode)` opens
 * the entry form already switched to that mode.
 *
 * ## Why the copy is deliberately narrow
 *
 * The "what it is for" / "how to configure" sentences describe real qualified-signature
 * infrastructure, so every claim in them is taken from the implementation rather than from what a
 * mode's name suggests: the per-mode required fields from {@link SECRET_FIELDS} and the api's
 * `assemble_*` / `validate_*` gates, the single-vs-multi instance split from
 * {@link MULTI_INSTANCE_MODES}, and whether an address is configurable at all from
 * {@link ENDPOINT_MODES}. Where the code does not settle a question the copy stays silent — an
 * under-claim is recoverable, a confident invention on this surface is not.
 */
function ProviderModesCard({
  providers,
  storable,
}: {
  providers: readonly ProviderCredentialGroupView[];
  storable: boolean;
}) {
  const t = useT();
  const navigate = useNavigate();

  // Entries per mode, summed across every provider group of that mode. Seeded with all four modes
  // at zero so an unconfigured mode reports 0 rather than falling out of the table.
  const counts = useMemo(() => {
    const out: Record<CredentialMode, number> = { cmd: 0, csc: 0, scap: 0, pkcs12: 0 };
    for (const group of providers) {
      if (group.mode in out) out[group.mode] += group.entries.length;
    }
    return out;
  }, [providers]);

  return (
    <Card title={t('settings.providerCredentials.modes.title')}>
      <p className="field__hint">{t('settings.providerCredentials.modes.lede')}</p>
      <Table
        caption={t('settings.providerCredentials.modes.caption')}
        head={
          <tr>
            {MODE_COLUMNS.map((column) => (
              <ColumnHead
                key={column.labelKey}
                label={t(column.labelKey)}
                help={t(column.helpKey)}
              />
            ))}
          </tr>
        }
      >
        {MODES.map((mode) => {
          const label = modeLabel(t, mode);
          const count = counts[mode];
          return (
            // `role="group"` + the mode as the row's accessible name mirrors `EntryRow`: it is what
            // disambiguates four identically-labelled action buttons for a screen reader.
            <tr key={mode} data-mode={mode} role="group" aria-label={label}>
              <td data-label={t('settings.providerCredentials.modes.column.mode')}>
                <p className="card__label">{label}</p>
              </td>
              <td data-label={t('settings.providerCredentials.modes.column.purpose')}>
                {t(`settings.providerCredentials.modes.purpose.${mode}` as MessageKey)}
              </td>
              <td data-label={t('settings.providerCredentials.modes.column.setup')}>
                {t(`settings.providerCredentials.modes.setup.${mode}` as MessageKey)}
              </td>
              {/* Zero is informative, not empty: it is how an operator sees that a mode exists and
                  is not configured. It stays a bare numeral so no locale has to inflect a noun
                  around it. */}
              <td data-label={t('settings.providerCredentials.modes.column.entries')}>
                <Badge tone={count > 0 ? 'ok' : 'neutral'}>{count}</Badge>
              </td>
              <td data-label={t('settings.providerCredentials.modes.column.actions')}>
                <GateButton
                  perm="signing.configure"
                  type="button"
                  variant="secondary"
                  icon={<Icon.Cog />}
                  // Same posture as the top-level create control: with no storable secret backend
                  // the form could only end in a server refusal, and the banner carries the reason.
                  disabled={!storable}
                  onClick={() => navigate(providerCredentialCreatePath(mode))}
                >
                  {t('settings.providerCredentials.modes.configure')}
                </GateButton>
              </td>
            </tr>
          );
        })}
      </Table>
    </Card>
  );
}

export function ProviderCredentialsSection() {
  const t = useT();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const credentials = useProviderCredentials();

  // Pre-dedicated-page bookmarks used `?configure=<mode>` on this list. Preserve them as a
  // redirect, never by reviving the inline form. Unknown/retired values are simply stripped.
  useEffect(() => {
    const requested = searchParams.get('configure');
    if (requested === null) return;
    if ((LEGACY_CONFIGURE_MODES as readonly string[]).includes(requested)) {
      navigate(providerCredentialCreatePath(requested as CredentialMode), { replace: true });
      return;
    }
    const next = new URLSearchParams(searchParams);
    next.delete('configure');
    setSearchParams(next, { replace: true });
  }, [navigate, searchParams, setSearchParams]);

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

      <Card
        title={t('settings.providerCredentials.cardTitle')}
        actions={
          <GateButton
            perm="signing.configure"
            variant="primary"
            icon={<Icon.Plus />}
            disabled={!storable}
            onClick={() => navigate(providerCredentialCreatePath())}
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

      {providers.map((group) => (
        <ProviderGroupCard key={`${group.mode}:${group.provider_id}`} group={group} />
      ))}

      <ProviderModesCard providers={providers} storable={storable} />
    </div>
  );
}
