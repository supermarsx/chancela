/**
 * Configurações — the end-to-end configuration surface (user request: "make the
 * whole app fully configurable end to end and allow the user to configure it too").
 *
 * It consumes the frozen §2.8 settings document (GET/PUT /v1/settings), holds a full
 * working copy, and — for the Aparência section — previews changes *live* as the
 * operator edits (theme, grain intensity, re-roll), reverting any unsaved preview to
 * the committed settings when leaving the page. Saving PUTs the whole document; the
 * mutation updates the shared cache optimistically, so the global appearance layer
 * (mounted in the shell) stays in step everywhere else in the app.
 *
 * Sections are reached through a segmented sub-nav (the Ferramentas idiom, via the shared
 * `<SubNav>`): Aparência · Documentos · Assinaturas · Gestão · Sobre. The
 * active section is deep-linkable (`/settings/data`); the working copy spans all of
 * them, so the
 * save flow stays a single whole-document PUT (global draft) reachable from every section.
 */
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from 'react';
import { Navigate, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { useSectionNav } from '../../app/navPath';
import {
  useHealth,
  useLedgerVerify,
  usePlatformLogs,
  useSettings,
  useUpdateSettings,
} from '../../api/hooks';
import { useAutosave } from '../../hooks/useAutosave';
import { useToast } from '../../ui';
import {
  localeLabels,
  numberingSchemeLabels,
  optionsFrom,
  signatureFamilyLabels,
  themeModeLabels,
} from '../../api/labels';
import {
  DEFAULT_SETTINGS,
  LOCALES,
  NUMBERING_SCHEMES,
  PLATFORM_EMITTED_LOG_LEVELS,
  PLATFORM_SERVICE_IDS,
  REGISTERED_ENTITY_COLUMNS,
  SIGNATURE_FAMILIES,
  THEME_MODES,
  type AiSettings,
  type ConnectorSettings,
  type EmailSettings,
  type AppearanceSettings,
  type BackupRecoveryPolicySettings,
  type CatalogSettings,
  type DataManagementSettings,
  type DocumentSettings,
  type Locale,
  type NumberingScheme,
  type OrganizationSettings,
  type PlatformEmittedLogLevel,
  type PlatformLogEntry,
  type PlatformLogsQueryParams,
  type PlatformSettings,
  type PlatformServiceId,
  type RegisteredEntityColumn,
  type RegistryAutoUpdateSettings,
  type RetainedExportCleanupSettings,
  type Settings,
  type SignatureFamily,
  type SigningProviderMetadata,
  type SigningSettings,
  type ThemeMode,
  type TsaProviderSettings,
  type TslSourceSettings,
  type UiSettings,
  type WorkflowReminderSettings,
  type WorkflowReminderSourceSettings,
  type WorkflowSettings,
} from '../../api/types';
import { UI_VERSION, displayVersion } from '../../api/versionCheck';
import { useActiveLocale, useT } from '../../i18n';
import type { MessageKey } from '../../i18n';
import { type ServerEnvCopyKey, useServerEnvT } from '../../i18n/serverEnvFallback';
import { useTableColumnsT } from '../../i18n/tableColumnsFallback';
import { useAdminT } from '../../i18n/adminFallback';
import { grainStore } from '../../theme/grainStore';
import { colorStore } from '../../theme/colorStore';
import { applyAppearance, applyLocale, COLOR_OVERRIDE_FIELDS } from '../../theme/appearance';
import type { ColorOverrideField } from '../../theme/appearance';
import { ColorPicker } from '../../theme/ColorPicker';
import { BookIntegritySection } from '../recovery/BookIntegritySection';
import { DataManagementSection } from '../recovery/DataManagementSection';
import { ZkObjectRootSection } from '../recovery/ZkObjectRootSection';
import { RolesSection } from '../rbac/RolesSection';
import { DelegationsSection } from '../rbac/DelegationsSection';
import { AdminIntegrationsPanel } from '../admin/AdminIntegrationsPanel';
import { ApiKeysSection } from './ApiKeysSection';
import { ConnectorEgressSection, parseAllowedHosts } from './ConnectorEgressSection';
import { EmailSection } from './EmailSection';
import { LanguagePreferenceSection } from './LanguagePreferenceSection';
import { ProviderCredentialsSection } from './ProviderCredentialsSection';
import { PairingPanel } from '../pairing/PairingPanel';
import { ApiServerSection } from './ApiServerSection';
import { ServerEnvSection } from './ServerEnvSection';
import { CacheSection } from './CacheSection';
import { DatabaseSection } from './DatabaseSection';
import { McpSection } from './McpSection';
import { MCP_TAB_PATH, PlatformOperationsSection } from './PlatformOperationsSection';
import { PrivacyComplianceSection } from './PrivacyComplianceSection';
import { RegistryAutoUpdateSection } from './RegistryAutoUpdateSection';
import { useCan } from '../session/permissions';
import {
  Badge,
  Button,
  ButtonLink,
  Card,
  ColumnHead,
  DateTime,
  ErrorNote,
  Field,
  FieldHelp,
  Icon,
  IconButton,
  InlineWarning,
  Input,
  PageHeader,
  Select,
  SkeletonDeflist,
  SkeletonForm,
  SkeletonRegion,
  SubNav,
  Table,
  Toggle,
  TooltipText,
} from '../../ui';
import { editUserPath, NEW_USER_PATH } from '../users/paths';
import { UsersList } from '../users/UserListPage';

/** Trim to a value or `null` (the contract's "unset" for nullable strings). */
const orNull = (s: string): string | null => (s.trim() === '' ? null : s.trim());

/**
 * Seed colours for the picker swatches when a field is UNSET — representative theme hexes
 * so the picker opens on a sensible value. They do not override anything until the
 * operator commits a choice (which is what actually writes {@link colorStore}).
 */
const COLOR_SEEDS: Record<ColorOverrideField, string> = {
  primary: '#b8963e',
  secondary: '#6b4d12',
  background: '#f7f3ea',
  surface: '#fffdf8',
};

function numberValue(value: string, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function boundedNumberValue(value: string, fallback: number, min: number, max: number): number {
  const parsed = numberValue(value, fallback);
  return Math.min(max, Math.max(min, Math.trunc(parsed)));
}

function integerValue(value: number, fallback: number): number {
  return Number.isFinite(value) ? Math.trunc(value) : fallback;
}

const TRUST_SOURCE_ID_PREFIX = 'trust-source';
const TSA_PROVIDER_ID_PREFIX = 'tsa-provider';
const RETAINED_EXPORT_CLEANUP_MAXIMUM_AGE_DAYS = 3650;
const RETAINED_EXPORT_CLEANUP_MAX_KEEP_LATEST = 100;
const BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS = 3650;
const BACKUP_RECOVERY_MAX_TARGET_MINUTES = 60 * 24 * 365;

function normalizeConfigId(value: string): string {
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/-+/g, '-')
    .slice(0, 64);
  return normalized || 'source';
}

function nextConfigId(prefix: string, rows: readonly { id: string }[]): string {
  const existing = new Set(rows.map((row) => row.id));
  let index = rows.length + 1;
  let candidate = normalizeConfigId(`${prefix}-${index}`);
  while (existing.has(candidate)) {
    index += 1;
    candidate = normalizeConfigId(`${prefix}-${index}`);
  }
  return candidate;
}

function makeTslSource(rows: readonly TslSourceSettings[], name: string): TslSourceSettings {
  return {
    id: nextConfigId(TRUST_SOURCE_ID_PREFIX, rows),
    name,
    enabled: false,
    url: DEFAULT_SETTINGS.signing.tsl_url,
    path: null,
    country: null,
    scheme: 'eidas',
    digest: null,
    timeout_seconds: 30,
    max_bytes: 26214400,
    refresh: { enabled: false, cadence: { kind: 'manual' } },
  };
}

function makeTsaProvider(
  rows: readonly TsaProviderSettings[],
  name: string,
  enabledDefault: boolean,
): TsaProviderSettings {
  return {
    id: nextConfigId(TSA_PROVIDER_ID_PREFIX, rows),
    name,
    enabled: enabledDefault,
    url: DEFAULT_SETTINGS.signing.tsa_url,
    path: null,
    default: enabledDefault,
    policy: null,
    digest: 'sha256',
    timeout_seconds: 30,
    max_bytes: 1048576,
  };
}

function normalizeRefreshCadence(cadence: TslSourceSettings['refresh']['cadence']) {
  if (cadence.kind === 'daily') {
    return { kind: 'daily' as const, hour_utc: Math.min(Math.max(cadence.hour_utc ?? 0, 0), 23) };
  }
  if (cadence.kind === 'interval_hours') {
    return {
      kind: 'interval_hours' as const,
      hours: Math.min(Math.max(cadence.hours ?? 24, 1), 720),
    };
  }
  return { kind: 'manual' as const };
}

function normalizeTslSource(source: TslSourceSettings): TslSourceSettings {
  return {
    ...source,
    id: normalizeConfigId(source.id),
    name: source.name.trim() || source.id,
    url: orNull(source.url ?? ''),
    path: orNull(source.path ?? ''),
    country: orNull(source.country ?? ''),
    scheme: orNull(source.scheme ?? ''),
    digest: orNull(source.digest ?? ''),
    timeout_seconds: Math.min(Math.max(source.timeout_seconds, 1), 300),
    max_bytes: Math.min(Math.max(source.max_bytes, 1024), 104857600),
    refresh: {
      enabled: source.refresh.enabled,
      cadence: normalizeRefreshCadence(source.refresh.cadence),
    },
  };
}

function normalizeTsaProvider(provider: TsaProviderSettings): TsaProviderSettings {
  return {
    ...provider,
    id: normalizeConfigId(provider.id),
    name: provider.name.trim() || provider.id,
    url: orNull(provider.url ?? ''),
    path: orNull(provider.path ?? ''),
    policy: orNull(provider.policy ?? ''),
    digest: provider.digest.trim() || 'sha256',
    timeout_seconds: Math.min(Math.max(provider.timeout_seconds, 1), 300),
    max_bytes: Math.min(Math.max(provider.max_bytes, 1024), 1048576),
  };
}

function ensureOneEnabledDefaultProvider(
  providers: readonly TsaProviderSettings[],
): TsaProviderSettings[] {
  const enabledProviders = providers.filter((provider) => provider.enabled);
  if (enabledProviders.length === 0) {
    return providers.map((provider) => ({ ...provider, default: false }));
  }
  const defaultId =
    enabledProviders.find((provider) => provider.default)?.id ?? enabledProviders[0].id;
  return providers.map((provider) => ({
    ...provider,
    default: provider.enabled && provider.id === defaultId,
  }));
}

type SettingsWithMaybeAi = Omit<
  Settings,
  | 'ai'
  | 'signing'
  | 'registry_auto_update'
  | 'ui'
  | 'platform'
  | 'workflow'
  | 'data_management'
  | 'connectors'
  | 'email'
> & {
  ai?: Partial<AiSettings> | null;
  // Absent on a server predating t23; defaulted to "mail off, STARTTLS" rather than assumed.
  email?: Partial<EmailSettings> | null;
  // Absent whenever no runtime allowlist is set and no deployment ceiling is stamped.
  connectors?: Partial<ConnectorSettings> | null;
  ui?: Partial<UiSettings> | null;
  platform?: Partial<PlatformSettings> | null;
  registry_auto_update?: Partial<RegistryAutoUpdateSettings> | null;
  workflow?:
    | (Partial<Omit<WorkflowSettings, 'reminders'>> & {
        reminders?:
          | (Partial<Omit<WorkflowReminderSettings, 'sources'>> & {
              sources?: Partial<WorkflowReminderSourceSettings> | null;
            })
          | null;
      })
    | null;
  data_management?:
    | (Partial<Omit<DataManagementSettings, 'retained_export_cleanup' | 'backup_recovery'>> & {
        retained_export_cleanup?: Partial<RetainedExportCleanupSettings> | null;
        backup_recovery?: Partial<BackupRecoveryPolicySettings> | null;
      })
    | null;
  signing: Omit<SigningSettings, 'providers' | 'tsl_sources' | 'tsa_providers'> &
    Partial<Pick<SigningSettings, 'providers' | 'tsl_sources' | 'tsa_providers'>>;
};

function withSettingsDefaults(settings: SettingsWithMaybeAi): Settings {
  const platform: Partial<PlatformSettings> = settings.platform ?? {};
  const platformLogging: Partial<PlatformSettings['logging']> = platform.logging ?? {};
  const workflow = settings.workflow ?? {};
  const workflowReminders = workflow.reminders ?? {};
  const workflowReminderSources = workflowReminders.sources ?? {};
  const dataManagement = settings.data_management ?? {};
  const retainedExportCleanup = dataManagement.retained_export_cleanup ?? {};
  const backupRecovery = dataManagement.backup_recovery ?? {};
  return {
    ...settings,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      ...settings.signing,
      cmd: { ...DEFAULT_SETTINGS.signing.cmd, ...(settings.signing.cmd ?? {}) },
      tsl_sources: settings.signing.tsl_sources ?? DEFAULT_SETTINGS.signing.tsl_sources,
      tsa_providers: settings.signing.tsa_providers ?? DEFAULT_SETTINGS.signing.tsa_providers,
      providers: settings.signing.providers ?? DEFAULT_SETTINGS.signing.providers,
    },
    ai: { ...DEFAULT_SETTINGS.ai, ...(settings.ai ?? {}) },
    ui: {
      ...DEFAULT_SETTINGS.ui,
      ...(settings.ui ?? {}),
      registered_entity_columns:
        settings.ui?.registered_entity_columns ?? DEFAULT_SETTINGS.ui.registered_entity_columns,
    },
    platform: {
      ...DEFAULT_SETTINGS.platform,
      ...platform,
      logging: {
        ...DEFAULT_SETTINGS.platform.logging,
        ...platformLogging,
        service_overrides:
          platformLogging.service_overrides ?? DEFAULT_SETTINGS.platform.logging.service_overrides,
      },
      api_server: {
        ...DEFAULT_SETTINGS.platform.api_server,
        ...(platform.api_server ?? {}),
      },
      mcp_stdio_server: {
        ...DEFAULT_SETTINGS.platform.mcp_stdio_server,
        ...(platform.mcp_stdio_server ?? {}),
      },
      audit: platform.audit ?? DEFAULT_SETTINGS.platform.audit,
    },
    registry_auto_update: {
      ...DEFAULT_SETTINGS.registry_auto_update,
      ...(settings.registry_auto_update ?? {}),
      cadence:
        settings.registry_auto_update?.cadence ?? DEFAULT_SETTINGS.registry_auto_update.cadence,
      entity_defaults: {
        ...DEFAULT_SETTINGS.registry_auto_update.entity_defaults,
        ...(settings.registry_auto_update?.entity_defaults ?? {}),
        enabled_profiles:
          settings.registry_auto_update?.entity_defaults?.enabled_profiles ??
          DEFAULT_SETTINGS.registry_auto_update.entity_defaults.enabled_profiles,
      },
    },
    workflow: {
      ...DEFAULT_SETTINGS.workflow,
      ...workflow,
      reminders: {
        ...DEFAULT_SETTINGS.workflow.reminders,
        ...workflowReminders,
        sources: {
          ...DEFAULT_SETTINGS.workflow.reminders.sources,
          ...workflowReminderSources,
        },
      },
    },
    data_management: {
      ...DEFAULT_SETTINGS.data_management,
      ...dataManagement,
      retained_export_cleanup: {
        ...DEFAULT_SETTINGS.data_management.retained_export_cleanup,
        ...retainedExportCleanup,
      },
      backup_recovery: {
        ...DEFAULT_SETTINGS.data_management.backup_recovery,
        ...backupRecovery,
      },
    },
    connectors: {
      ...DEFAULT_SETTINGS.connectors,
      ...(settings.connectors ?? {}),
      allowed_hosts:
        settings.connectors?.allowed_hosts ?? DEFAULT_SETTINGS.connectors.allowed_hosts,
    },
    email: { ...DEFAULT_SETTINGS.email, ...(settings.email ?? {}) },
  };
}

/**
 * Normalise the whole working copy to the wire shape (empty → null for nullables; a
 * blank actor falls back to the server default so the audit event stays attributed).
 * Pure, so both the debounced autosave and an explicit "Guardar agora" persist an
 * identical document, and change-detection compares the *normalised* form (so typing a
 * trailing space that normalises away never triggers a save).
 */
function toWireBody(draft: Settings): Settings {
  return {
    ...draft,
    organization: {
      name: orNull(draft.organization.name ?? ''),
      // The audit actor is attributed from the session (topbar picker), not entered here;
      // the stored default is passed through, falling back to the system actor.
      default_actor: draft.organization.default_actor.trim() || 'api',
    },
    catalog: {
      // Pass through the strict-chain fields untouched (the CAE-source editor is t23-e3);
      // only the legacy single URL is edited here.
      ...draft.catalog,
      cae_update_url: orNull(draft.catalog.cae_update_url ?? ''),
    },
    signing: {
      ...draft.signing,
      tsa_url: orNull(draft.signing.tsa_url ?? ''),
      tsl_url: orNull(draft.signing.tsl_url ?? ''),
      tsl_sources: draft.signing.tsl_sources.map(normalizeTslSource),
      tsa_providers: ensureOneEnabledDefaultProvider(
        draft.signing.tsa_providers.map(normalizeTsaProvider),
      ),
    },
    ai: {
      enabled: draft.ai.enabled === true,
    },
    email: {
      ...draft.email,
      host: orNull(draft.email.host ?? ''),
      username: orNull(draft.email.username ?? ''),
      from_address: orNull(draft.email.from_address ?? '')?.toLowerCase() ?? null,
      from_name: orNull(draft.email.from_name ?? ''),
      helo_name: orNull(draft.email.helo_name ?? ''),
      port: boundedNumberValue(String(draft.email.port), DEFAULT_SETTINGS.email.port, 1, 65535),
      // The cleartext acknowledgement is only meaningful while encryption is actually off; clearing
      // it on the way out means re-enabling TLS and disabling it again asks the operator afresh.
      allow_insecure: draft.email.encryption === 'none' && draft.email.allow_insecure === true,
    },
    registry_auto_update: {
      ...draft.registry_auto_update,
      entity_defaults: {
        ...draft.registry_auto_update.entity_defaults,
        enabled_profiles: draft.registry_auto_update.entity_defaults.enabled_profiles
          .map((profile) => profile.trim())
          .filter(Boolean),
      },
    },
    workflow: {
      ...draft.workflow,
      reminders: {
        ...draft.workflow.reminders,
        enabled: draft.workflow.reminders.enabled === true,
        dashboard_limit: integerValue(
          draft.workflow.reminders.dashboard_limit,
          DEFAULT_SETTINGS.workflow.reminders.dashboard_limit,
        ),
        due_soon_days: integerValue(
          draft.workflow.reminders.due_soon_days,
          DEFAULT_SETTINGS.workflow.reminders.due_soon_days,
        ),
        attendance_lookahead_days: integerValue(
          draft.workflow.reminders.attendance_lookahead_days,
          DEFAULT_SETTINGS.workflow.reminders.attendance_lookahead_days,
        ),
        sources: {
          profile_calendar: draft.workflow.reminders.sources.profile_calendar === true,
          act_follow_ups: draft.workflow.reminders.sources.act_follow_ups === true,
          attendance_hygiene: draft.workflow.reminders.sources.attendance_hygiene === true,
          privacy_control_reviews:
            draft.workflow.reminders.sources.privacy_control_reviews === true,
        },
      },
    },
    data_management: {
      ...draft.data_management,
      retained_export_cleanup: {
        minimum_age_days: boundedNumberValue(
          String(draft.data_management.retained_export_cleanup.minimum_age_days),
          DEFAULT_SETTINGS.data_management.retained_export_cleanup.minimum_age_days,
          0,
          RETAINED_EXPORT_CLEANUP_MAXIMUM_AGE_DAYS,
        ),
        keep_latest: boundedNumberValue(
          String(draft.data_management.retained_export_cleanup.keep_latest),
          DEFAULT_SETTINGS.data_management.retained_export_cleanup.keep_latest,
          0,
          RETAINED_EXPORT_CLEANUP_MAX_KEEP_LATEST,
        ),
      },
      backup_recovery: {
        max_drill_age_days: boundedNumberValue(
          String(draft.data_management.backup_recovery.max_drill_age_days),
          DEFAULT_SETTINGS.data_management.backup_recovery.max_drill_age_days,
          1,
          BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS,
        ),
        target_rpo_minutes: boundedNumberValue(
          String(draft.data_management.backup_recovery.target_rpo_minutes),
          DEFAULT_SETTINGS.data_management.backup_recovery.target_rpo_minutes,
          1,
          BACKUP_RECOVERY_MAX_TARGET_MINUTES,
        ),
        target_rto_minutes: boundedNumberValue(
          String(draft.data_management.backup_recovery.target_rto_minutes),
          DEFAULT_SETTINGS.data_management.backup_recovery.target_rto_minutes,
          1,
          BACKUP_RECOVERY_MAX_TARGET_MINUTES,
        ),
      },
    },
    connectors: {
      // The stamped ceiling is server-owned and read-only; never echo it back on save.
      allowed_hosts: parseAllowedHosts(draft.connectors.allowed_hosts.join('\n')),
    },
  };
}

/** The sub-tabs, in order. Each label reuses its section card title (identical text).
 *  The array is appended cleanly by peers (t60 Utilizadores, t62 Administração). */
type SettingsSection =
  | 'appearance'
  | 'documents'
  | 'signing'
  | 'management'
  | 'operations'
  | 'privacy'
  | 'users'
  | 'devices'
  | 'integrity'
  | 'about';

type SettingsSectionNav =
  | { id: SettingsSection; label: MessageKey; icon: ReactNode; literal?: never }
  | { id: SettingsSection; label?: never; icon: ReactNode; literal: string };

const SETTINGS_SECTIONS: SettingsSectionNav[] = [
  { id: 'appearance', label: 'settings.appearance.cardTitle', icon: <Icon.Palette /> },
  { id: 'documents', label: 'settings.documents.cardTitle', icon: <Icon.FileText /> },
  // Assinaturas is no longer a Configurações tab (t50): the whole signing-configuration cluster
  // (providers / policy / tsl / tsa / trust-services / cmd) moved to the Administração surface at
  // `/admin/signing`, joining Operações as the second admin section. Exactly like the t36 operations
  // move, the `signing` section id, its SUBSECTION_NAV / SETTINGS_SUBSECTIONS / STANDALONE / WIDE /
  // RETIRED entries and the ~600-line render block all remain in place — they are reached only from
  // the admin surface (and, for the settings surface, from the retired `signing-providers` /
  // pt-PT `assinaturas` aliases that forward on to `/admin/signing/*`, see the forward guard below).
  { id: 'management', label: 'settings.management.cardTitle', icon: <Icon.Sliders /> },
  // Operações is no longer a Configurações tab (t36): its panes moved to the Administração surface
  // at `/admin`, reached through the `<SettingsPage surface="admin">` wrapper. The `operations`
  // section id, its SUBSECTION_NAV / SETTINGS_SUBSECTIONS / STANDALONE / RETIRED entries and the
  // render block all remain — they are reached only from the admin surface and, for the settings
  // surface, from the retired aliases that forward on to `/admin/*` (see the forward guard below).
  { id: 'privacy', label: 'settings.privacy.tab', icon: <Icon.Seal /> },
  { id: 'users', label: 'settings.users.cardTitle', icon: <Icon.Users /> },
  { id: 'devices', label: 'pairing.tab', icon: <Icon.IdCard /> },
  // Funções and Delegações were top-level tabs beside Utilizadores until t106. They are now the
  // second and third sub-tabs OF it (see SUBSECTION_NAV) — same three panels, one fewer thing to
  // scan in this strip. Their old addresses resolve through RETIRED_SECTIONS.
  { id: 'integrity', label: 'integrity.cardTitle', icon: <Icon.Layers /> },
  // Gestão de dados moved into Operações (t105). It is instance operations — storage, backups,
  // keys — not a subject of its own beside Livros. Its old address resolves via RETIRED_SECTIONS.
  { id: 'about', label: 'settings.about.cardTitle', icon: <Icon.Info /> },
];

/**
 * The Administração surface's OWN top-level sections (t50). Where Configurações hides its section
 * strip on the admin surface, /admin now hosts TWO sections and shows a strip for them: Operações
 * (the t36 panes + integrations subtabs) and Assinaturas (the signing-configuration cluster t50
 * moved here). Both ids, their sub-navs and render blocks already live in this page; this list is
 * only what the admin section strip renders, and both labels reuse their existing frozen catalog
 * card titles (Operações → "Plataforma"; Assinaturas → settings.signing.cardTitle "Assinaturas"),
 * so the move needs no new UI string.
 */
const ADMIN_SECTIONS: SettingsSectionNav[] = [
  { id: 'operations', label: 'settings.platform.cardTitle', icon: <Icon.Power /> },
  { id: 'signing', label: 'settings.signing.cardTitle', icon: <Icon.PenNib /> },
];

/** The sub-tabs that manage their OWN data (not the settings working copy), so the
 *  autosave savebar is not shown for them. The RBAC tabs (Funções, Delegações) self-gate
 *  their own `role.manage`/`delegation.*` affordances, so they are standalone too. */
const SETTINGS_SUBSECTIONS = {
  operations: [
    'services',
    'logs',
    'api',
    'database',
    'cache',
    'storage',
    'backups',
    'keys',
    'mcp',
    'email',
    'env',
    'api-keys',
    // Integrations (t36): the three areas the retired standalone `/operations` tab held —
    // Grupos / Conectores / Repositórios ZK — folded in as subtabs of the Administração surface.
    // They are STANDALONE (own data + own gating; see STANDALONE_SUBSECTIONS) and render through
    // <AdminIntegrationsPanel>, not a settings-document pane.
    'groups',
    'connectors',
    'repositories',
  ],
  signing: ['providers', 'policy', 'tsl', 'tsa', 'trust-services', 'cmd'],
  users: ['users', 'delegations', 'roles'],
} as const;

type SettingsSubsection =
  | (typeof SETTINGS_SUBSECTIONS)['operations'][number]
  | (typeof SETTINGS_SUBSECTIONS)['signing'][number]
  | (typeof SETTINGS_SUBSECTIONS)['users'][number];

/** A sub-tab label is normally a frozen catalog key. "Ambiente do servidor" (t14) is the one
 *  exception: its whole copy lives in `i18n/serverEnvFallback` (the shared catalogs were locked when
 *  it landed), so it names a key in that module instead, resolved with `st(...)` at render — the same
 *  split the pane itself uses. Exactly one of `label`/`serverEnvLabel` is present. */
type SettingsSubsectionNav =
  | { id: SettingsSubsection; label: MessageKey; icon: ReactNode; serverEnvLabel?: never }
  | { id: SettingsSubsection; label?: never; icon: ReactNode; serverEnvLabel: ServerEnvCopyKey };

/**
 * Second-level sub-tabs (t73). Two parents grew long enough to need their own strip, and three
 * former top-level sub-tabs belonged inside them rather than beside them. Same primitive and same
 * contract as every other tab strip: the shared `<SubNav>`, a deep-linkable query param, and
 * "the first sub-tab is the default and carries no segment". The second level is a second path
 * segment under the parent's — `/settings/operations/email`. Every label reuses the card
 * title it heads.
 */
const SUBSECTION_NAV: Partial<Record<SettingsSection, SettingsSubsectionNav[]>> = {
  operations: [
    // Serviços and Registos (t101). These were a THIRD level — a `useState` strip inside the
    // Plataforma sub-tab — so neither had an address and neither could be linked to. Promoting
    // them here is the standalone follow-up t82 deliberately deferred: they are siblings of the
    // other operations panels, not children of one of them. `platform` is no longer an id, and the
    // address it used to answer is covered twice over: the pt-PT spelling anyone could actually
    // have bookmarked, `/configuracoes/operacoes/plataforma`, is forwarded EXPLICITLY by
    // `app/legacySlugs.ts` (`plataforma: 'services'`), and the English spelling — which existed
    // only between this morning's id rename and this change, and which nothing links — falls
    // through to the first entry below. Both land on Serviços, the pane that address opened on.
    { id: 'services', label: 'settings.platform.tab.services', icon: <Icon.Power /> },
    { id: 'logs', label: 'settings.platform.tab.logs', icon: <Icon.Layers /> },
    // API (t82b). One button covering TWO addresses — `.../api` (server) and `.../api-keys`
    // (keys) — which is why `api-keys` is a valid subsection but not an entry here. See
    // API_PANES below.
    { id: 'api', label: 'settings.subnav.api', icon: <Icon.Power /> },
    // Base de dados and Redis (t105). Both are launch-time environment surfaces, shown the same
    // read-only way the API pane already shows CHANCELA_ADDR and the rate limits — see the header
    // comment on each section for why neither is an editor.
    { id: 'database', label: 'settings.database.cardTitle', icon: <Icon.Archive /> },
    { id: 'cache', label: 'settings.cache.cardTitle', icon: <Icon.Layers /> },
    // Gestão de dados was a single subtab whose own internal strip held three panes
    // (Armazenamento / Cópias e recuperação / Chaves e reposição). t28 promotes those three to
    // sibling subtabs here so each has a stable, bookmarkable address; the former `/…/data`
    // address is kept resolving to Armazenamento by RETIRED_SUBSECTIONS. All three are standalone —
    // see STANDALONE_SUBSECTIONS, which is what preserves their `data.manage`/`backup.manage` gating.
    { id: 'storage', label: 'data.status.tab.storage', icon: <Icon.Layers /> },
    { id: 'backups', label: 'data.status.tab.backup', icon: <Icon.Archive /> },
    { id: 'keys', label: 'data.status.tab.keys', icon: <Icon.Shuffle /> },
    // MCP (t82). Sits next to Plataforma because that is where its controls came from; it is a
    // sibling rather than a third level inside Plataforma so it has a stable address of its own.
    { id: 'mcp', label: 'settings.subnav.mcp', icon: <Icon.Sliders /> },
    { id: 'email', label: 'settings.email.cardTitle', icon: <Icon.Tray /> },
    // Ambiente do servidor (t14) — the editable superset of the read-only environment panes above
    // (API, Base de dados, Redis). It lists every var the server declares and overrides the safe
    // ones; it sits last because it is the advanced, comprehensive surface rather than a curated
    // one. Its label is the one sub-tab whose copy lives in the serverEnvFallback module, not the
    // catalog, so it is resolved with `st(...)` in the strip below.
    { id: 'env', serverEnvLabel: 'settings.serverEnv.title', icon: <Icon.Sliders /> },
    // Integrations (t36) — Grupos / Conectores / Repositórios ZK. These were the standalone
    // `/operations` tab's three views; folding them in here is what makes them "part of the admin
    // subtabs". They sit last, after the platform/data/env panes, and reuse the existing
    // `operations.tabs.*` catalog labels. They render <AdminIntegrationsPanel> rather than a
    // settings-document pane, and are STANDALONE so the autosave fieldset never wraps them.
    { id: 'groups', label: 'operations.tabs.groups', icon: <Icon.Users /> },
    { id: 'connectors', label: 'operations.tabs.connectors', icon: <Icon.Shuffle /> },
    { id: 'repositories', label: 'operations.tabs.repositories', icon: <Icon.Archive /> },
  ],
  signing: [
    { id: 'providers', label: 'settings.providerCredentials.cardTitle', icon: <Icon.IdCard /> },
    { id: 'policy', label: 'settings.signing.policy.cardTitle', icon: <Icon.Scale /> },
    { id: 'tsl', label: 'settings.signing.tslSources.title', icon: <Icon.Layers /> },
    { id: 'tsa', label: 'settings.signing.tsaProviders.title', icon: <Icon.Calendar /> },
    { id: 'trust-services', label: 'settings.signing.providers.title', icon: <Icon.Sliders /> },
    { id: 'cmd', label: 'settings.signing.cmd.title', icon: <Icon.PenNib /> },
  ],
  // Utilizadores (t106). Three panels that were three top-level tabs: the roster, who may act for
  // whom, and what a função may do. They are one subject — who has authority here — and reading
  // them as one tab with three children is how an operator actually uses them (grant a delegation,
  // check the função it inherits, find the person it names).
  //
  // The first label is "Utilizadores", the same word as the parent, and that is deliberate rather
  // than the loop the Operações note above warns against. The rule this strip follows is the
  // stronger one — every label reuses the card title it heads — and the roster's own card title
  // genuinely IS `users.list.cardTitle`. Operações differs because its first child had a truthful
  // name of its own ("Plataforma"); inventing one here would rename a surface operators know.
  users: [
    { id: 'users', label: 'users.list.cardTitle', icon: <Icon.Users /> },
    { id: 'delegations', label: 'rbac.delegacoes.tab', icon: <Icon.ArrowRight /> },
    { id: 'roles', label: 'rbac.funcoes.tab', icon: <Icon.Scale /> },
  ],
};

/** Each strip gets its own aria-label, so the two levels are told apart by AT. Deliberately NOT
 *  the wording of `settings.platform.subnav.aria`, which labels the THIRD-level strip inside
 *  Plataforma — two identically-named landmarks on one page is a real defect. */
const SUBSECTION_ARIA: Partial<Record<SettingsSection, MessageKey>> = {
  operations: 'settings.subnav.operations.aria',
  signing: 'settings.subnav.signing.aria',
  users: 'settings.subnav.users.aria',
};

/**
 * The API tab's two panes (t82b) — the one place a THIRD level of sub-tab ids sits behind a single
 * second-level button.
 *
 * The user asked for the API surface to be aggregated into one sub-tab, and it is: one button,
 * one destination. But server configuration and key management cannot share a *panel*. Everything
 * on "Servidor" is `settings.manage` working-copy state that the page inerts with a disabled
 * fieldset; the keys pane is gated on `user.manage` and owns its own data. Rendering the keys
 * table inside that fieldset would remove key management from anyone holding `user.manage` without
 * `settings.manage` — a silent narrowing of who may rotate a credential, which is precisely the
 * failure this restructure must not introduce.
 *
 * Keeping them as two sub-tab ids rather than local state is what preserves that: `isStandalone`
 * keys off `operations:api-keys`, so the keys pane keeps its exact savebar and fieldset treatment,
 * and the bookmarkable `/settings/operations/api-keys` address keeps working.
 */
const API_PANES = [
  { id: 'api', label: 'settings.api.tab.server', icon: <Icon.Power /> },
  { id: 'api-keys', label: 'settings.apiKeys.cardTitle', icon: <Icon.Seal /> },
] as const satisfies readonly { id: SettingsSubsection; label: MessageKey; icon: ReactNode }[];

const isApiPane = (sub: SettingsSubsection | undefined): boolean =>
  sub === 'api' || sub === 'api-keys';

/**
 * `users` covers all three of its sub-tabs (t106), and that is the whole of what keeps Funções and
 * Delegações behaving exactly as they did when they were top-level sections.
 *
 * `isStandalone` is what decides `editingLocked`, and `editingLocked` inerts the panel with a
 * disabled fieldset. Funções and Delegações gate themselves on `role.manage` and
 * `delegation.revoke` — NOT on `settings.manage`. Had they become sub-tabs of a parent that was not
 * standalone, a principal holding `role.manage` without `settings.manage` would have found the
 * whole panel greyed out: authority they hold, silently removed by a navigation change. That is
 * the inherited-gate failure t102 flagged on the privacy registers, and it is asserted by test
 * rather than left to this comment.
 */
const STANDALONE_SECTIONS: readonly SettingsSection[] = [
  'users',
  'privacy',
  'integrity',
  'devices',
];

/** The same rule one level down: Chaves API and Fornecedores de assinatura keep their own
 *  endpoints and their own gating, so they carry no savebar even though their parent does.
 *
 *  `operations:storage`/`backups`/`keys` are here because Gestão de dados WAS a standalone
 *  top-level section (t105 moved it under Operações; t28 split it into these three subtabs).
 *  Dropping them from `STANDALONE_SECTIONS` without listing them here would have handed each its
 *  parent's gating instead of its own: the panel would be wrapped in the `settings.manage` disabled
 *  fieldset, so a principal holding `data.manage`/`backup.manage` without `settings.manage` would
 *  find backups and key rotation greyed out — authority they hold, removed by a navigation change.
 *  That is the exact inherited-gate hole t102 flagged on the privacy registers, and it is asserted
 *  by test rather than left to this comment.
 *
 *  The retained-export-cleanup and backup-recovery POLICY editors that t28 co-locates onto the
 *  storage and backups subtabs are `settings.manage` working-copy, so they carry their OWN inner
 *  `settings.manage` fieldset in the render — the subtab staying standalone must not silently widen
 *  who may edit those policies. */
const STANDALONE_SUBSECTIONS: readonly string[] = [
  'operations:api-keys',
  'operations:storage',
  'operations:backups',
  'operations:keys',
  // Ambiente do servidor (t14) owns its own data (`GET`/`PUT /v1/platform/env`) and its own save,
  // not the settings working copy, so it carries no whole-document savebar and is not inerted by
  // the page's `settings.manage` fieldset — the pane gates its own editors on `settings.manage`.
  'operations:env',
  // Integrations (t36). Grupos / Conectores / Repositórios ZK own their own data (the entities
  // directory + the connector/ZK endpoints) and their own gating (each area component keeps its
  // `perm="…"` disable-with-tooltip checks), so — like the other standalone subtabs — the page's
  // `settings.manage` fieldset must not wrap them and the whole-document savebar must not show.
  'operations:groups',
  'operations:connectors',
  'operations:repositories',
  'signing:providers',
];

const isStandalone = (section: SettingsSection, sub: SettingsSubsection | undefined): boolean =>
  STANDALONE_SECTIONS.includes(section) ||
  (sub !== undefined && STANDALONE_SUBSECTIONS.includes(`${section}:${sub}`));

/**
 * Sub-tabs that opt out of the shell prose measure (t64's shared `.wide-page`, see
 * `theme.css`). Listed per SUB-TAB rather than per section, exactly as Arquivo puts the
 * class on its panel rather than its page: Configurações renders one panel for all
 * sections, so the measure has to follow whichever one is mounted.
 *
 * All three are repeated-entry grids of six or seven columns that scroll sideways inside
 * `.table-wrap` at EVERY viewport at the 1080px measure, however large the window — the
 * defect t64 was opened for. Their siblings are not here on purpose: Política de assinatura
 * is label/control rows (measured 78ch → 126ch when widened), CMD is a definition list, and
 * Prestadores is a four-column read-only table whose Notas column is wrapping prose already
 * at 61ch and which never scrolls (61ch → 96ch if widened — worse, not better).
 */
const WIDE_SUBSECTIONS: readonly string[] = ['signing:tsl', 'signing:tsa', 'signing:providers'];

const isWideSubsection = (section: SettingsSection, sub: SettingsSubsection | undefined): boolean =>
  sub !== undefined && WIDE_SUBSECTIONS.includes(`${section}:${sub}`);

/**
 * Whether autosave is enabled. Autosave is always-on today (t49) — there is no
 * server-side disable toggle yet (a deferred t60 slice needing an `autosave_enabled`
 * settings field). The persistent "Guardar agora" flush is therefore hidden: it would
 * only ever return when a future toggle turns autosave OFF (`!autosaveEnabled`). A failed
 * save still exposes a retry affordance regardless (see the savebar), so nothing is stuck.
 * When the field lands, replace this constant with `draft.<…>.autosave_enabled ?? true`.
 */
const AUTOSAVE_ENABLED = true;

const ENTITY_COLUMN_LABEL_KEYS: Record<RegisteredEntityColumn, MessageKey> = {
  Name: 'entities.columns.name',
  Nipc: 'entities.columns.nipc',
  Seat: 'entities.columns.seat',
  Type: 'entities.columns.type',
  Matricula: 'entities.columns.matricula',
  Constitution: 'entities.columns.constitution',
  Capital: 'entities.columns.capital',
  Cae: 'entities.columns.cae',
  Registry: 'entities.columns.registry',
  LastRegistryChange: 'entities.columns.lastRegistryChange',
  FiscalYearEnd: 'entities.columns.fiscalYearEnd',
  LastBook: 'entities.columns.lastBook',
  LastActivity: 'entities.columns.lastActivity',
  Actions: 'entities.columns.actions',
};

const isSettingsSection = (v: string | undefined): v is SettingsSection =>
  SETTINGS_SECTIONS.some((s) => s.id === v);

/** Retired sub-tabs, kept resolvable so their deep links still land where the content went.
 *  `identity` (the organisation name printed ON generated documents) merged into
 *  Documentos as its own card — same subject matter, one fewer sub-tab. The old link
 *  therefore opens Documentos and scrolls to the moved card rather than 404ing. */
const RETIRED_SECTIONS: Record<string, { section: SettingsSection; sub?: SettingsSubsection }> = {
  identity: { section: 'documents' },
  email: { section: 'operations', sub: 'email' },
  'api-keys': { section: 'operations', sub: 'api-keys' },
  // Not a retired address — a courtesy one. `/settings/mcp` is the link an operator is
  // most likely to guess or hand-write for a tab called MCP, so it resolves rather than
  // falling back to Aparência.
  mcp: { section: 'operations', sub: 'mcp' },
  api: { section: 'operations', sub: 'api' },
  'signing-providers': { section: 'signing', sub: 'providers' },
  // t105: Gestão de dados moved from a top-level section to a sub-tab of Operações. `/settings/data`
  // was a real, linkable address — and the pt-PT original `/configuracoes/dados` reaches it through
  // the same table — so both keep resolving to the pane rather than falling back to Aparência.
  // t28 split that sub-tab into three; the former address lands on Armazenamento (the successor of
  // its old default pane). `/settings/operations/data` (the sub-level spelling) is kept resolving by
  // RETIRED_SUBSECTIONS below.
  data: { section: 'operations', sub: 'storage' },
  // t106: Funções and Delegações moved from top-level sections to sub-tabs of Utilizadores.
  // `/settings/roles` and `/settings/delegations` were both real, linkable addresses — and the
  // pt-PT originals `/configuracoes/funcoes` and `/configuracoes/delegacoes` reach these two
  // entries through the positional slug translation in `app/legacySlugs.ts`, so BOTH spellings of
  // both addresses keep landing on the panel they always landed on. Neither may 404.
  roles: { section: 'users', sub: 'roles' },
  delegations: { section: 'users', sub: 'delegations' },
};

/** Retired SUB-tabs — the same courtesy as `RETIRED_SECTIONS`, one level down. A retired sub name
 *  under a still-live section resolves to its successor sub rather than falling through to the
 *  section's first sub-tab (which would silently redirect a real bookmark to an unrelated pane).
 *
 *  `operations:data` was a real, bookmarkable address (t105) before t28 split Gestão de dados into
 *  three sibling subtabs. It lands on Armazenamento, the successor of its old default pane, so
 *  `/settings/operations/data` (and the pt-PT `/configuracoes/operacoes/dados`, which reaches the
 *  same segment through `app/legacySlugs.ts`) never 404s or drops to Serviços. */
const RETIRED_SUBSECTIONS: Partial<Record<SettingsSection, Record<string, SettingsSubsection>>> = {
  operations: { data: 'storage' },
};

/** Anchor for the moved Identidade card, targeted by the retired `/settings/identity`
 *  link. */
const IDENTITY_ANCHOR_ID = 'settings-identity';

function providerModeLabel(provider: SigningProviderMetadata, t: ReturnType<typeof useT>): string {
  switch (provider.mode) {
    case 'CMD':
      return t('settings.signing.providerMode.cmd');
    case 'CC':
      return t('settings.signing.providerMode.cc');
    case 'CSC_QTSP':
      return t('settings.signing.providerMode.cscQtsp');
    case 'LOCAL_PKCS12':
      return t('settings.signing.providerMode.localPkcs12');
  }
}

/** The `providers` sub-tab credential mode a table row's "Configurar" action deep-links to,
 *  or `null` when the mode has no in-app configuration. Cartão de Cidadão is configured on the
 *  operator's own machine (a card reader plus the Autenticação.gov middleware), so its row
 *  carries a muted note rather than a navigating control — there is no route to invent. The
 *  `configure` value is the URL contract consumed by `ProviderCredentialsSection` (t12-e3):
 *  `/admin/signing/providers?configure=<mode>` since the cluster moved to Administração (t50),
 *  mode ∈ {cmd, csc, pkcs12}. */
function providerConfigureMode(provider: SigningProviderMetadata): 'cmd' | 'csc' | 'pkcs12' | null {
  switch (provider.mode) {
    case 'CMD':
      return 'cmd';
    case 'CSC_QTSP':
      return 'csc';
    case 'LOCAL_PKCS12':
      return 'pkcs12';
    case 'CC':
      return null;
  }
}

function providerStatus(
  provider: SigningProviderMetadata,
  t: ReturnType<typeof useT>,
): {
  tone: 'ok' | 'error' | 'accent' | 'warn';
  label: string;
} {
  if (provider.production_blocked) {
    return { tone: 'error', label: t('settings.signing.providerStatus.productionBlocked') };
  }
  if (provider.configured)
    return { tone: 'ok', label: t('settings.signing.providerStatus.configured') };
  if (provider.local_only)
    return { tone: 'accent', label: t('settings.signing.providerStatus.localOnly') };
  return { tone: 'warn', label: t('settings.signing.providerStatus.unconfigured') };
}

const PLATFORM_LOG_TAIL_OPTIONS = [25, 50, 100, 200] as const;

function platformLogServiceLabel(serviceId: PlatformServiceId, t: ReturnType<typeof useT>) {
  return t(`settings.platform.service.${serviceId}` as MessageKey);
}

function platformLogLevelTone(
  level: PlatformEmittedLogLevel,
): 'neutral' | 'accent' | 'warn' | 'error' | 'ok' {
  if (level === 'error') return 'error';
  if (level === 'warn') return 'warn';
  if (level === 'info') return 'accent';
  return 'neutral';
}

function platformLogContextText(context: PlatformLogEntry['context']): string {
  if (context === undefined) return '';
  try {
    return JSON.stringify(context, null, 2) ?? String(context);
  } catch {
    return String(context);
  }
}

function platformLogSequenceText(seq: number | null): string {
  return seq === null ? 'n/a' : String(seq);
}

function PlatformLogTailPanel() {
  const t = useT();
  const [serviceId, setServiceId] = useState<PlatformServiceId | ''>('');
  const [level, setLevel] = useState<PlatformEmittedLogLevel | ''>('');
  const [tail, setTail] = useState<number>(100);
  const params = useMemo<PlatformLogsQueryParams>(
    () => ({
      service_id: serviceId || undefined,
      level: level || undefined,
      tail,
    }),
    [level, serviceId, tail],
  );
  const logs = usePlatformLogs(params);
  const serviceOptions = useMemo(
    () => [
      { value: '', label: t('settings.platform.logs.filter.service.all') },
      ...PLATFORM_SERVICE_IDS.map((id) => ({
        value: id,
        label: platformLogServiceLabel(id, t),
      })),
    ],
    [t],
  );
  const levelOptions = useMemo(
    () => [
      { value: '', label: t('settings.platform.logs.filter.level.all') },
      ...PLATFORM_EMITTED_LOG_LEVELS.map((item) => ({
        value: item,
        label: t(`settings.platform.logLevel.${item}` as MessageKey),
      })),
    ],
    [t],
  );
  const tailOptions = useMemo(
    () => PLATFORM_LOG_TAIL_OPTIONS.map((item) => ({ value: String(item), label: String(item) })),
    [],
  );
  const orderLabel =
    logs.data?.order === 'chronological'
      ? t('settings.platform.logs.order.chronological')
      : (logs.data?.order ?? t('settings.platform.logs.order.unknown'));

  return (
    <Card
      title={t('settings.platform.logs.cardTitle')}
      actions={
        <IconButton
          type="button"
          icon={<Icon.Refresh />}
          label={
            logs.isFetching
              ? t('settings.platform.logs.refreshing')
              : t('settings.platform.logs.refresh')
          }
          disabled={logs.isFetching}
          onClick={() => void logs.refetch()}
        />
      }
    >
      <div className="form">
        <p className="field__hint">{t('settings.platform.logs.hint')}</p>
        <div className="platform-log-controls">
          <Field label={t('settings.platform.logs.filter.service')} htmlFor="platform-log-service">
            <Select
              id="platform-log-service"
              value={serviceId}
              options={serviceOptions}
              onChange={(e) => setServiceId(e.target.value as PlatformServiceId | '')}
            />
          </Field>
          <Field label={t('settings.platform.logs.filter.level')} htmlFor="platform-log-level">
            <Select
              id="platform-log-level"
              value={level}
              options={levelOptions}
              onChange={(e) => setLevel(e.target.value as PlatformEmittedLogLevel | '')}
            />
          </Field>
          <Field label={t('settings.platform.logs.filter.tail')} htmlFor="platform-log-tail">
            <Select
              id="platform-log-tail"
              value={String(tail)}
              options={tailOptions}
              onChange={(e) => setTail(Number(e.target.value))}
            />
          </Field>
        </div>

        {logs.isLoading ? <SkeletonDeflist rows={4} /> : null}
        {logs.error ? <ErrorNote error={logs.error} /> : null}

        {logs.data ? (
          <div className="stack--tight">
            <InlineWarning tone="info" title={t('settings.platform.logs.limitations.title')}>
              <ul className="platform-log-limitations">
                {logs.data.limitations.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </InlineWarning>
            <dl
              className="platform-log-retention"
              aria-label={t('settings.platform.logs.retention.title')}
            >
              <div>
                <dt>{t('settings.platform.logs.retention.limit')}</dt>
                <dd>{logs.data.retention.retention_limit}</dd>
              </div>
              <div>
                <dt>{t('settings.platform.logs.retention.retained')}</dt>
                <dd>{logs.data.retention.retained_count}</dd>
              </div>
              <div>
                <dt>{t('settings.platform.logs.retention.oldest')}</dt>
                <dd>{platformLogSequenceText(logs.data.retention.oldest_seq)}</dd>
              </div>
              <div>
                <dt>{t('settings.platform.logs.retention.newest')}</dt>
                <dd>{platformLogSequenceText(logs.data.retention.newest_seq)}</dd>
              </div>
              <div>
                <dt>{t('settings.platform.logs.retention.droppedBefore')}</dt>
                <dd>{platformLogSequenceText(logs.data.retention.dropped_before_seq)}</dd>
              </div>
              <div>
                <dt>{t('settings.platform.logs.retention.basis')}</dt>
                <dd>
                  {logs.data.retention.durable
                    ? t('settings.platform.logs.retention.basis.durable')
                    : t('settings.platform.logs.retention.basis.memory')}
                </dd>
              </div>
              <div>
                <dt>{t('settings.platform.logs.retention.source')}</dt>
                <dd className="mono">{logs.data.retention.source}</dd>
              </div>
            </dl>
            <p className="field__hint">
              {t('settings.platform.logs.summary', {
                count: logs.data.logs.length,
                tail: logs.data.tail,
                order: orderLabel,
              })}
            </p>
            {logs.data.logs.length === 0 ? (
              <InlineWarning tone="info" title={t('settings.platform.logs.empty.title')}>
                {t('settings.platform.logs.empty.body')}
              </InlineWarning>
            ) : (
              <div className="platform-log-table-wrap">
                <table className="table platform-log-table">
                  <thead>
                    <tr>
                      <th>{t('settings.platform.logs.column.seq')}</th>
                      <th>{t('settings.platform.logs.column.time')}</th>
                      <th>{t('settings.platform.logs.column.service')}</th>
                      <th>{t('settings.platform.logs.column.level')}</th>
                      <th>{t('settings.platform.logs.column.target')}</th>
                      <th>{t('settings.platform.logs.column.message')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.data.logs.map((entry) => {
                      const context = platformLogContextText(entry.context);
                      return (
                        <tr key={entry.id}>
                          <td className="mono" data-label={t('settings.platform.logs.column.seq')}>
                            {entry.seq}
                          </td>
                          <td className="mono" data-label={t('settings.platform.logs.column.time')}>
                            {/* A platform log is an audit record: evidentiary. */}
                            <DateTime value={entry.timestamp} evidentiary />
                          </td>
                          <td data-label={t('settings.platform.logs.column.service')}>
                            {platformLogServiceLabel(entry.service_id, t)}
                          </td>
                          <td data-label={t('settings.platform.logs.column.level')}>
                            <Badge tone={platformLogLevelTone(entry.level)}>
                              {t(`settings.platform.logLevel.${entry.level}` as MessageKey)}
                            </Badge>
                          </td>
                          <td
                            className="mono"
                            data-label={t('settings.platform.logs.column.target')}
                          >
                            {entry.target}
                          </td>
                          <td
                            className="platform-log-message-cell"
                            data-label={t('settings.platform.logs.column.message')}
                          >
                            <p>{entry.message}</p>
                            {context ? (
                              <details className="platform-log-context">
                                <summary>{t('settings.platform.logs.context.show')}</summary>
                                <pre>{context}</pre>
                              </details>
                            ) : (
                              <p className="field__hint">
                                {t('settings.platform.logs.context.empty')}
                              </p>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : null}
      </div>
    </Card>
  );
}

/**
 * The two surfaces this page powers (t36). `settings` is Configurações at `/settings`; `admin` is
 * the Administração surface at `/admin`, reached through the thin {@link AdminPage} wrapper which
 * renders this page as `<SettingsPage surface="admin" />`.
 *
 * t36-e1 introduces this prop as the CONTRACT ONLY — AdminPage needs it to typecheck, and the value
 * is currently threaded no further than the root element's `data-surface`. t36-e2 implements the
 * admin-surface BEHAVIOUR behind it: force the operations section, hide the Configurações section
 * strip, use `admin.title` for the header, fold the integrations subtabs (groups/connectors/
 * repositories) into the operations strip with an `<AdminIntegrationsPanel>` render arm, and forward
 * the retired settings→operations aliases into `/admin/*`. Until then `admin` behaves as `settings`.
 */
export type SettingsSurface = 'settings' | 'admin';
export interface SettingsPageProps {
  surface?: SettingsSurface;
}

export function SettingsPage({ surface = 'settings' }: SettingsPageProps = {}) {
  const t = useT();
  // The "Ambiente do servidor" sub-tab label is the one strip entry whose copy lives in the
  // serverEnvFallback module rather than the frozen catalog (t14) — resolved here for the strip.
  const st = useServerEnvT();
  // "Administração" copy (title + nav) lives in its own owned fallback module (t36), same split.
  const at = useAdminT();
  // The entities-column card is now the ORG DEFAULT (t37): its hint says so, from an owned module.
  const ct = useTableColumnsT();
  // The Administração surface (`/admin`) renders this page with `surface="admin"`: it titles the
  // page "Administração", shows a two-section strip (Operações + Assinaturas, t50) in place of the
  // Configurações one, and reads its section+sub off the `/admin/:sub?/:detail?` path. Every
  // operations/signing pane, the standalone/RETIRED machinery and the autosave savebar are reused
  // unchanged — only the chrome around them differs.
  const isAdmin = surface === 'admin';
  const toast = useToast();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  // Aparência is the default and carries no segment (so `/settings` lands on it). The
  // section is read off the path on every render, so a deep link paints the right tab at once.
  // A retired address (`/settings/email`) still resolves — to the sub-tab its content
  // moved to — because the old query-string form redirected here and must keep landing.
  const {
    section: rawSection,
    raw: secSegment,
    select: selectRawSection,
  } = useSectionNav<SettingsSection>({
    base: '/settings',
    // Retired ids are not `SettingsSection`s, so they cannot be resolved here; the raw
    // segment is re-read below for the alias table. Anything unknown falls back to Aparência.
    parse: (raw) => (isSettingsSection(raw) ? raw : 'appearance'),
    fallback: 'appearance',
    replace: true,
    // The `?user=` state redirects straight out to the edit screen, so it must never be
    // carried onto another section's address.
    dropParams: ['user'],
  });
  // The admin surface hosts two sections — Operações and Assinaturas (t50). The first `/admin`
  // segment names the section: `signing` selects Assinaturas (sub read one level deeper off
  // `/admin/signing/:detail`), everything else is an Operações sub read off `/admin/:sub` exactly as
  // t36 left it (no operations sub is named `signing`, so there is no collision). The settings
  // section-level nav above is only meaningful for `/settings`, so on the admin surface its result is
  // discarded and `retired` (a settings-alias table) is not consulted. On the settings surface a
  // retired alias (`/settings/email`, `/settings/data`, `/settings/signing-providers`, …) can still
  // resolve INTO operations or signing — the forward guard below then sends it on to `/admin/*`.
  const retired = isAdmin || secSegment === undefined ? undefined : RETIRED_SECTIONS[secSegment];
  const section: SettingsSection = isAdmin
    ? secSegment === 'signing'
      ? 'signing'
      : 'operations'
    : (retired?.section ?? rawSection);
  // The second level, for the two sections that have one. Like the section, the first sub-tab is
  // the default and carries no segment; an unknown one falls back to it rather than blanking the
  // panel. A retired address names its own destination sub-tab and wins over any sub segment.
  const subNav = SUBSECTION_NAV[section];
  // Anchored on the RESOLVED section, so selecting a sub-tab from a retired address writes the
  // real one (`/settings/email` → `/settings/operations/mcp`) rather than compounding it.
  // A PUSH, so the browser Back button walks back through the sub-tabs the operator opened
  // (the t34/t62 rule: navigation the user performed must be undoable).
  const { section: subSegment, select: selectRawSub } = useSectionNav<string>({
    // On the admin surface the signing section adds a path level (`/admin/signing/:detail`), so its
    // sub is read one segment deeper than the operations section (`/admin/:sub`). t50.
    base: isAdmin ? (section === 'signing' ? '/admin/signing' : '/admin') : `/settings/${section}`,
    parse: (raw) => raw ?? '',
    fallback: '',
  });
  // Validity is decided by SETTINGS_SUBSECTIONS, not by the strip: `api-keys` is a real,
  // bookmarkable address that no longer has a button of its own (it is a pane of the API tab),
  // and resolving it through the strip would silently redirect an existing bookmark to Plataforma.
  const validSubs: readonly string[] | undefined =
    section === 'operations' || section === 'signing' || section === 'users'
      ? SETTINGS_SUBSECTIONS[section]
      : undefined;
  const sub: SettingsSubsection | undefined = subNav
    ? (retired?.sub ??
      RETIRED_SUBSECTIONS[section]?.[subSegment] ??
      (validSubs?.includes(subSegment) ? (subSegment as SettingsSubsection) : subNav[0].id))
    : undefined;
  // Scoped to the ROSTER sub-tab, not to the whole Utilizadores section (t106). `?user=` is the
  // roster's own legacy state and redirects out to the edit screen; left section-wide it would
  // fire on `/settings/users/roles?user=u1` too, throwing an operator off the Funções panel.
  const selectedUser = section === 'users' && sub === 'users' ? params.get('user') : null;
  // Leaving a section drops its sub-tab: the base is rebuilt from `/settings`, so the new
  // section opens on its own default rather than on a stale child id. On the admin surface the two
  // sections address off `/admin` instead (Assinaturas at `/admin/signing`, Operações at the bare
  // `/admin`), so section selection is rebuilt from that base rather than the settings one. t50.
  const selectSection = (next: SettingsSection) => {
    if (isAdmin) {
      navigate(next === 'signing' ? '/admin/signing' : '/admin');
      return;
    }
    selectRawSection(next);
  };
  const selectSub = (next: SettingsSubsection) =>
    selectRawSub(subNav && next === subNav[0].id ? '' : next);
  // The fragment of the current location, carried through the `?user=` → edit-screen redirect.
  // `search` is preserved verbatim by the retired-alias → /admin forwarding below, so the provider
  // `?configure=` deep link survives a `/settings/signing-providers?configure=…` bookmark (t50).
  const { hash, pathname, search } = useLocation();
  const settings = useSettings();
  const health = useHealth();
  const ledger = useLedgerVerify();
  // The live UI language, for the read-only "Sobre" table: it is a fact an operator needs in a
  // support report, and it is the ONLY environment fact the client can state without guessing.
  const activeLocale = useActiveLocale();
  const save = useUpdateSettings();
  // Writing the settings document requires `settings.manage` (PUT /v1/settings, t64-E3).
  // Without it the whole-document autosave is suspended and the working-copy sections are
  // disabled-with-explanation; the standalone sub-tabs (Utilizadores/Integridade/Dados)
  // gate their OWN actions, and "Sobre" is read-only info — so only the editable sections
  // lock. Reads (`settings.read`) still render everything.
  const can = useCan();
  const canManageSettings = can('settings.manage');
  // The signing-configuration cluster is gated on its own dedicated verb since t50 (the whole
  // cluster moved into /admin and was re-permissioned): `signing.configure`, not `settings.manage`.
  // Grandfathering grants it to every prior `settings.manage` holder (t50-e1), so this narrows who
  // may future-custom-role edit signing policy WITHOUT removing it from any current operator.
  const canConfigureSigning = can('signing.configure');
  // The verb that gates the ACTIVE section's editors: signing → `signing.configure`, everything else
  // → `settings.manage`. This is the page-level lock; the server is the real gate (put_settings
  // signing-slice guard + the provider-credential endpoints, t50-e1).
  const sectionEditGate = section === 'signing' ? canConfigureSigning : canManageSettings;
  // Lock only the editable working-copy sections (not the self-gating standalone sub-tabs,
  // nor the read-only "Sobre").
  const standalone = isStandalone(section, sub);
  const editingLocked = !sectionEditGate && !standalone && section !== 'about';
  // The two standalone subtabs that, since t28, host a `settings.manage` working-copy policy editor
  // co-located with their readouts (Armazenamento → retained-export cleanup; Cópias e recuperação →
  // backup-recovery). They DO touch the settings document, so — unlike other standalone subtabs —
  // the autosave save/error bar must still surface here; otherwise a failed policy save is silent.
  const hostsSettingsPolicy = section === 'operations' && (sub === 'storage' || sub === 'backups');

  // The committed (persisted) document, tracked in a ref so the unmount cleanup can
  // restore it if the operator navigated away mid-preview without saving.
  const committed = useMemo(
    () => withSettingsDefaults(settings.data ?? DEFAULT_SETTINGS),
    [settings.data],
  );
  const committedRef = useRef(committed);
  committedRef.current = committed;

  // Full working copy, seeded once when the document first loads.
  const [draft, setDraft] = useState<Settings | null>(null);
  useEffect(() => {
    if (settings.data && !draft) setDraft(withSettingsDefaults(settings.data));
  }, [settings.data, draft]);

  // Live preview: apply the draft appearance/locale as it is edited so the operator
  // sees the theme switch, grain fade and language flip immediately.
  useEffect(() => {
    if (!draft) return;
    applyAppearance(draft.appearance);
    applyLocale(draft.documents.locale);
    // Keyed on the appearance/locale slices only; `draft` as a whole would re-apply
    // on unrelated edits (org name, etc.).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft?.appearance, draft?.documents.locale]);

  // On leaving the page, drop any unsaved preview and restore the committed look.
  useEffect(() => {
    return () => {
      applyAppearance(committedRef.current.appearance);
      applyLocale(committedRef.current.documents.locale);
    };
  }, []);

  // Custom colour overrides (client-only, localStorage-backed). Edited directly on the
  // store so they apply + persist live — the shell's AppearanceEffects subscribes too, so
  // a picker change repaints the whole app immediately (no draft/save round-trip, exactly
  // like the leather re-roll). An empty store means the theme defaults are in force.
  const colors = useSyncExternalStore(colorStore.subscribe, colorStore.get, colorStore.get);
  const hasColorOverrides = COLOR_OVERRIDE_FIELDS.some((f) => colors[f] !== undefined);

  // The normalised wire document the operator's edits currently amount to. Autosave
  // debounces every edit across all sub-tabs and PUTs this whole document (the §2.8
  // contract is a single whole-document PUT); the optimistic `useUpdateSettings` keeps
  // the shared cache — and thus the global appearance layer — in step. A committed save
  // raises a normal success toast (no inline "Guardado" — the save bar stays hidden on a
  // clean form); a failure raises an error toast AND keeps an inline error + retry, and
  // the fields stay editable so it self-heals on the next edit or a manual retry.
  const body = useMemo(() => (draft ? toWireBody(draft) : null), [draft]);
  const autosave = useAutosave<Settings | null>({
    value: body,
    enabled: !!draft && canManageSettings,
    onSave: (b) => (b ? save.mutateAsync(b) : Promise.resolve()),
    onSuccess: () => toast.success(t('toast.settings.saved')),
    onError: (e) => toast.error(e),
  });

  // A retired deep link opens the section that absorbed it; once the section has actually
  // rendered, take the operator to the card that moved rather than to the top of a section
  // they did not ask for. (`scrollIntoView` is absent in jsdom, hence the optional call.)
  useEffect(() => {
    if (!retired || !draft) return;
    document.getElementById(IDENTITY_ANCHOR_ID)?.scrollIntoView?.({ block: 'start' });
  }, [retired, draft]);

  // Both waits are the same wait: `draft` is seeded from `settings` in an effect, so the
  // page has no content in either branch. What arrives is stacked cards of form rows.
  const settingsSkeleton = (
    <div className="stack">
      <Card>
        <SkeletonRegion>
          <SkeletonForm fields={4} className="settings-rows" />
        </SkeletonRegion>
      </Card>
      <Card>
        <SkeletonForm fields={3} className="settings-rows" />
      </Card>
    </div>
  );
  // Retired-alias forwarding into the Administração surface (t36 + t50). Neither Operações nor
  // Assinaturas is a Configurações tab any more, but their RETIRED settings aliases still reach THIS
  // page (only it knows the RETIRED_SECTIONS table): `/settings/email`, `/settings/mcp`,
  // `/settings/api`, `/settings/api-keys` and `/settings/data` resolve `section` to operations, and
  // `/settings/signing-providers` (plus the pt-PT `/configuracoes/assinaturas` slug, via
  // `legacySlugs`) resolve to signing. Forward each on to `/admin/<…>` so the bookmark lands on the
  // moved pane rather than 404ing or dropping to Aparência. The literal `/settings/operations/*` and
  // `/settings/signing/*` never arrive here — the router redirects intercept them first (t36/t50) —
  // so the two forwarding mechanisms are disjoint. Guarded to genuine `/settings` addresses so a
  // `/admin/*` render (whose segment[1] can coincide with a retired alias name) never re-forwards.
  // `search` (the provider `?configure=` deep link) and `hash` are preserved verbatim. `sub` is
  // always defined here because both operations and signing carry a sub-nav.
  if (!isAdmin && pathname.startsWith('/settings') && section === 'operations') {
    return <Navigate to={`${sub ? `/admin/${sub}` : '/admin'}${search}${hash}`} replace />;
  }
  if (!isAdmin && pathname.startsWith('/settings') && section === 'signing') {
    return (
      <Navigate
        to={`${sub ? `/admin/signing/${sub}` : '/admin/signing'}${search}${hash}`}
        replace
      />
    );
  }
  if (settings.isLoading) return settingsSkeleton;
  if (settings.error) return <ErrorNote error={settings.error} />;
  if (!draft) return settingsSkeleton;

  const setOrganization = <K extends keyof OrganizationSettings>(
    key: K,
    value: OrganizationSettings[K],
  ) => setDraft((d) => (d ? { ...d, organization: { ...d.organization, [key]: value } } : d));
  const setDocuments = <K extends keyof DocumentSettings>(key: K, value: DocumentSettings[K]) =>
    setDraft((d) => (d ? { ...d, documents: { ...d.documents, [key]: value } } : d));
  const setCatalog = <K extends keyof CatalogSettings>(key: K, value: CatalogSettings[K]) =>
    setDraft((d) => (d ? { ...d, catalog: { ...d.catalog, [key]: value } } : d));
  const setSigning = <K extends keyof SigningSettings>(key: K, value: SigningSettings[K]) =>
    setDraft((d) => (d ? { ...d, signing: { ...d.signing, [key]: value } } : d));
  const setAppearance = <K extends keyof AppearanceSettings>(
    key: K,
    value: AppearanceSettings[K],
  ) => setDraft((d) => (d ? { ...d, appearance: { ...d.appearance, [key]: value } } : d));
  const setEmail = <K extends keyof EmailSettings>(key: K, value: EmailSettings[K]) =>
    setDraft((d) => (d ? { ...d, email: { ...d.email, [key]: value } } : d));
  const setAi = <K extends keyof AiSettings>(key: K, value: AiSettings[K]) =>
    setDraft((d) => (d ? { ...d, ai: { ...d.ai, [key]: value } } : d));
  const setUi = <K extends keyof UiSettings>(key: K, value: UiSettings[K]) =>
    setDraft((d) => (d ? { ...d, ui: { ...d.ui, [key]: value } } : d));
  const setRegistryAutoUpdate = (registry_auto_update: RegistryAutoUpdateSettings) =>
    setDraft((d) => (d ? { ...d, registry_auto_update } : d));
  const setConnectors = (connectors: ConnectorSettings) =>
    setDraft((d) => (d ? { ...d, connectors } : d));
  const setWorkflowReminder = <K extends keyof WorkflowReminderSettings>(
    key: K,
    value: WorkflowReminderSettings[K],
  ) =>
    setDraft((d) =>
      d
        ? {
            ...d,
            workflow: {
              ...d.workflow,
              reminders: { ...d.workflow.reminders, [key]: value },
            },
          }
        : d,
    );
  const setWorkflowReminderSource = <K extends keyof WorkflowReminderSourceSettings>(
    key: K,
    value: WorkflowReminderSourceSettings[K],
  ) =>
    setDraft((d) =>
      d
        ? {
            ...d,
            workflow: {
              ...d.workflow,
              reminders: {
                ...d.workflow.reminders,
                sources: { ...d.workflow.reminders.sources, [key]: value },
              },
            },
          }
        : d,
    );
  const setRetainedExportCleanupPolicy = <K extends keyof RetainedExportCleanupSettings>(
    key: K,
    value: RetainedExportCleanupSettings[K],
  ) =>
    setDraft((d) =>
      d
        ? {
            ...d,
            data_management: {
              ...d.data_management,
              retained_export_cleanup: {
                ...d.data_management.retained_export_cleanup,
                [key]: value,
              },
            },
          }
        : d,
    );
  const setBackupRecoveryPolicy = <K extends keyof BackupRecoveryPolicySettings>(
    key: K,
    value: BackupRecoveryPolicySettings[K],
  ) =>
    setDraft((d) =>
      d
        ? {
            ...d,
            data_management: {
              ...d.data_management,
              backup_recovery: {
                ...d.data_management.backup_recovery,
                [key]: value,
              },
            },
          }
        : d,
    );
  const setPlatform = (platform: PlatformSettings) => setDraft((d) => (d ? { ...d, platform } : d));
  const setTslSources = (updater: (sources: TslSourceSettings[]) => TslSourceSettings[]) =>
    setDraft((d) =>
      d
        ? {
            ...d,
            signing: {
              ...d.signing,
              tsl_sources: updater(d.signing.tsl_sources),
            },
          }
        : d,
    );
  const setTsaProviders = (updater: (providers: TsaProviderSettings[]) => TsaProviderSettings[]) =>
    setDraft((d) =>
      d
        ? {
            ...d,
            signing: {
              ...d.signing,
              tsa_providers: ensureOneEnabledDefaultProvider(updater(d.signing.tsa_providers)),
            },
          }
        : d,
    );

  const updateTslSource = (id: string, patch: Partial<TslSourceSettings>) =>
    setTslSources((sources) =>
      sources.map((source) => (source.id === id ? { ...source, ...patch } : source)),
    );
  const updateTsaProvider = (id: string, patch: Partial<TsaProviderSettings>) =>
    setTsaProviders((providers) =>
      providers.map((provider) => (provider.id === id ? { ...provider, ...patch } : provider)),
    );
  const addTslSource = () =>
    setTslSources((sources) => [
      ...sources,
      makeTslSource(sources, t('settings.signing.tslSources.newName')),
    ]);
  const addTsaProvider = () =>
    setTsaProviders((providers) => {
      const enabledDefault = !providers.some((provider) => provider.enabled);
      return [
        ...providers,
        makeTsaProvider(providers, t('settings.signing.tsaProviders.newName'), enabledDefault),
      ];
    });
  const removeTslSource = (id: string) =>
    setTslSources((sources) => sources.filter((source) => source.id !== id));
  const removeTsaProvider = (id: string) =>
    setTsaProviders((providers) => providers.filter((provider) => provider.id !== id));
  const makeDefaultTsaProvider = (id: string) =>
    setTsaProviders((providers) =>
      providers.map((provider) => ({
        ...provider,
        enabled: provider.id === id ? true : provider.enabled,
        default: provider.id === id,
      })),
    );

  const toggleEntityColumn = (column: RegisteredEntityColumn, checked: boolean) => {
    const current = draft.ui.registered_entity_columns;
    const next = checked
      ? REGISTERED_ENTITY_COLUMNS.filter(
          (candidate) => candidate === column || current.includes(candidate),
        )
      : current.filter((candidate) => candidate !== column);
    setUi('registered_entity_columns', next.length > 0 ? next : ['Actions']);
  };

  const a = draft.appearance;
  const reminderPolicy = draft.workflow.reminders;
  const retainedExportCleanupPolicy = draft.data_management.retained_export_cleanup;
  const backupRecoveryPolicy = draft.data_management.backup_recovery;

  return (
    // `data-surface` is the t36-e1 contract seam only (see SettingsPageProps); t36-e2 keys the
    // admin-surface behaviour off `surface` here.
    <div className="stack" data-surface={surface}>
      {/* No `crumbs`: both surfaces are a top-level tab with no parent, so a breadcrumb would only
          restate the title. On the Administração surface the header reads "Administração" from the
          owned admin fallback, and the section strip lists the admin sections — Operações and
          Assinaturas (t50) — rather than the Configurações ones. (t36 hid this strip entirely when
          admin had a single section; t50 restores it now that admin hosts two.) */}
      <PageHeader title={isAdmin ? at('admin.title') : t('settings.page.title')}>
        <SubNav
          items={(isAdmin ? ADMIN_SECTIONS : SETTINGS_SECTIONS).map((s) => ({
            id: s.id,
            label: 'literal' in s ? s.literal : t(s.label),
            icon: s.icon,
          }))}
          active={section}
          onSelect={selectSection}
          ariaLabel={t('settings.subnav.aria')}
        />
      </PageHeader>

      {/* Honest disable-with-explanation for the editable settings when the user lacks
          `settings.manage`: the working-copy sections are inerted (a disabled fieldset) and
          this note explains why. Standalone sub-tabs manage their own gating. */}
      {editingLocked ? (
        <InlineWarning tone="info" title={t('perm.denied.title')}>
          {t('perm.denied.body')}
        </InlineWarning>
      ) : null}

      {/* The second-level strip for the sections that have one (Operações, Assinaturas). It sits
          OUTSIDE the fieldset on purpose: `editingLocked` inerts the fieldset, and a reader
          without `settings.manage` must still be able to move between sub-tabs — including to
          the standalone ones that are not locked at all. */}
      {subNav && sub ? (
        <SubNav
          items={subNav.map((s) => ({
            id: s.id,
            label: s.serverEnvLabel ? st(s.serverEnvLabel) : t(s.label),
            icon: s.icon,
          }))}
          // `api-keys` is a pane of the API tab, so the API button is the one that reads as
          // active while it is open — otherwise the strip would show nothing selected.
          active={sub === 'api-keys' ? 'api' : sub}
          onSelect={selectSub}
          ariaLabel={t(SUBSECTION_ARIA[section] ?? 'settings.subnav.aria')}
        />
      ) : null}

      {/* The API tab's own strip. Outside the fieldset for the same reason the level above is:
          a reader looking at the inerted server pane must still be able to reach the keys pane,
          which is not locked at all. */}
      {section === 'operations' && isApiPane(sub) ? (
        <SubNav
          items={API_PANES.map((p) => ({ id: p.id, label: t(p.label), icon: p.icon }))}
          active={sub as string}
          onSelect={(next) => selectSub(next as SettingsSubsection)}
          ariaLabel={t('settings.api.subnav.aria')}
        />
      ) : null}

      {/* One section at a time; the working copy spans all of them and the save bar below
          is always reachable. The panel replays the route-enter fade on each switch. */}
      <fieldset className="settings-fieldset" disabled={editingLocked}>
        <div
          className={
            isWideSubsection(section, sub)
              ? 'route-transition settings-section wide-page'
              : 'route-transition settings-section'
          }
          key={sub ? `${section}:${sub}` : section}
        >
          {/* Aparência --------------------------------------------------------------- */}
          {/* Aparência ---------------------------------------------------------------- */}
          {/* Two cards, because the tab carries two SCOPES and the split is the only thing that
              says so: the appearance card edits the instance-wide settings document (plus the
              browser-local colour overrides), while the language card edits the signed-in user's
              own record. Same tab, different blast radius. */}
          {section === 'appearance' ? (
            <div className="stack">
              <Card title={t('settings.appearance.cardTitle')}>
                <div className="form settings-rows">
                  <Field
                    label={t('settings.appearance.theme.label')}
                    htmlFor="set-theme"
                    hint={t('settings.appearance.theme.hint')}
                    help={t('settings.appearance.theme.help')}
                  >
                    <Select
                      id="set-theme"
                      value={a.theme}
                      onChange={(e) => setAppearance('theme', e.target.value as ThemeMode)}
                      options={optionsFrom(THEME_MODES, themeModeLabels)}
                    />
                  </Field>

                  <Toggle
                    label={
                      <>
                        {t('settings.appearance.leatherBg.label')}{' '}
                        <FieldHelp text={t('settings.appearance.leatherBg.help')} />
                      </>
                    }
                    checked={a.leather_texture}
                    onChange={(v) => setAppearance('leather_texture', v)}
                  />

                  <Toggle
                    label={
                      <>
                        {t('settings.appearance.leatherButtons.label')}{' '}
                        <FieldHelp text={t('settings.appearance.leatherButtons.help')} />
                      </>
                    }
                    checked={a.button_texture}
                    onChange={(v) => setAppearance('button_texture', v)}
                  />

                  <Field
                    label={t('settings.appearance.intensity.label', { value: a.texture_intensity })}
                    htmlFor="set-intensity"
                    hint={t('settings.appearance.intensity.hint')}
                    help={t('settings.appearance.intensity.help')}
                  >
                    <input
                      id="set-intensity"
                      className="control control--range"
                      type="range"
                      min={0}
                      max={100}
                      step={1}
                      value={a.texture_intensity}
                      disabled={!a.leather_texture}
                      onChange={(e) => setAppearance('texture_intensity', Number(e.target.value))}
                    />
                  </Field>

                  {/* Grão — a named group rather than a loose action row (t100). The re-roll is
                    not a setting the card saves: it redraws the texture for this session only
                    (grainStore holds no persisted field), so it does not read as one more
                    banded row. Same `settings-group` shape as the colours block below, which
                    is the other per-browser, non-saved control on this card. */}
                  <div className="settings-group">
                    <div className="field__labelrow">
                      <p className="settings-group__title">
                        {t('settings.appearance.grain.title')}
                      </p>
                      <FieldHelp text={t('settings.appearance.grain.help')} />
                    </div>
                    <p className="field__hint">{t('settings.appearance.grain.hint')}</p>

                    <div className="form__actions">
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.Shuffle />}
                        disabled={!a.leather_texture}
                        onClick={() => grainStore.reroll()}
                      >
                        {t('settings.appearance.reroll')}
                      </Button>
                    </div>
                  </div>

                  {/* Custom colours — operator-set primary/secondary/background/surface, with
                    a reset to the app's default theme. Applied live via colorStore. */}
                  <div className="color-customizer">
                    <div className="field__labelrow">
                      <p className="color-customizer__title">
                        {t('settings.appearance.colors.title')}
                      </p>
                      <FieldHelp text={t('settings.appearance.colors.help')} />
                    </div>
                    <p className="field__hint">{t('settings.appearance.colors.hint')}</p>

                    <div className="color-customizer__grid">
                      {COLOR_OVERRIDE_FIELDS.map((fieldKey) => {
                        const value = colors[fieldKey] ?? COLOR_SEEDS[fieldKey];
                        const isSet = colors[fieldKey] !== undefined;
                        const label = t(`settings.appearance.colors.${fieldKey}.label`);
                        return (
                          <div key={fieldKey} className="color-customizer__field">
                            <label className="field__label" id={`set-color-${fieldKey}-label`}>
                              {label}
                            </label>
                            <div className="color-customizer__row">
                              <ColorPicker
                                value={value}
                                isSet={isSet}
                                label={label}
                                onChange={(hex) => colorStore.setField(fieldKey, hex)}
                                onClear={() => colorStore.setField(fieldKey, undefined)}
                              />
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="form__actions">
                      <Button
                        type="button"
                        variant="ghost"
                        icon={<Icon.Refresh />}
                        disabled={!hasColorOverrides}
                        onClick={() => colorStore.reset()}
                      >
                        {t('settings.appearance.colors.reset')}
                      </Button>
                      {!hasColorOverrides ? (
                        <span className="field__hint color-customizer__status">
                          {t('settings.appearance.colors.usingDefault')}
                        </span>
                      ) : null}
                    </div>
                  </div>
                </div>
              </Card>
              <LanguagePreferenceSection />
            </div>
          ) : null}

          {/* Documentos -------------------------------------------------------------- */}
          {/* Identidade used to be its own sub-tab, but the organisation name it holds is
              what appears ON generated documents — the same subject matter. It lives here
              now as its own card (t36's grouping idiom: one card per concern, stacked),
              kept as a distinct heading rather than interleaved with the document defaults
              so it stays findable. `/settings/identity` still resolves here, anchored
              below. */}
          {section === 'documents' ? (
            <div className="stack">
              <div id={IDENTITY_ANCHOR_ID}>
                <Card title={t('settings.identity.cardTitle')}>
                  <div className="form settings-rows">
                    <Field
                      label={t('settings.identity.orgName.label')}
                      htmlFor="set-org-name"
                      hint={t('settings.identity.orgName.hint')}
                      help={t('settings.identity.orgName.help')}
                    >
                      <Input
                        id="set-org-name"
                        value={draft.organization.name ?? ''}
                        placeholder={t('settings.identity.orgName.placeholder')}
                        onChange={(e) => setOrganization('name', e.target.value)}
                      />
                    </Field>
                    <p className="field__hint">{t('settings.identity.actorNote')}</p>
                  </div>
                </Card>
              </div>
              <Card title={t('settings.documents.cardTitle')}>
                <div className="form settings-rows">
                  <Field
                    label={t('settings.documents.locale.label')}
                    htmlFor="set-locale"
                    hint={t('settings.documents.locale.hint')}
                    help={t('settings.documents.locale.help')}
                  >
                    <Select
                      id="set-locale"
                      value={draft.documents.locale}
                      onChange={(e) => setDocuments('locale', e.target.value as Locale)}
                      options={optionsFrom(LOCALES, localeLabels)}
                    />
                  </Field>
                  <Field
                    label={t('settings.documents.numbering.label')}
                    htmlFor="set-numbering"
                    hint={t('settings.documents.numbering.hint')}
                    help={t('settings.documents.numbering.help')}
                  >
                    <Select
                      id="set-numbering"
                      value={draft.documents.numbering_scheme_default}
                      onChange={(e) =>
                        setDocuments('numbering_scheme_default', e.target.value as NumberingScheme)
                      }
                      options={optionsFrom(NUMBERING_SCHEMES, numberingSchemeLabels)}
                    />
                  </Field>
                  <Field
                    label={t('settings.documents.caeUrl.label')}
                    htmlFor="set-cae-url"
                    hint={t('settings.documents.caeUrl.hint')}
                    help={t('settings.documents.caeUrl.help')}
                  >
                    <Input
                      id="set-cae-url"
                      type="url"
                      value={draft.catalog.cae_update_url ?? ''}
                      placeholder={t('settings.documents.caeUrl.placeholder')}
                      onChange={(e) => setCatalog('cae_update_url', e.target.value)}
                    />
                  </Field>
                </div>
              </Card>
            </div>
          ) : null}

          {/* Assinaturas ------------------------------------------------------------- */}
          {/* Four cards by concern, not one column of forty controls (t36). The policy that
              governs every signature comes FIRST — `require_qualified_for_seal` used to sit ~300
              lines down, below both provider lists. The two repeated lists are grids: every TSL
              source and every TSA answers the same questions, so their answers belong in aligned
              columns where two rows can be compared without scrolling. The read-only inventories
              (provider modes, CMD) are last and visually separate, because nothing there is
              editable here. */}
          {section === 'signing' ? (
            <div className="stack">
              {/* Fornecedores de assinatura — the credentials manager that used to be a sibling
                  top-level sub-tab. It keeps its own endpoints and its own gating, so it is
                  standalone (no savebar) even though its five siblings are working-copy cards. */}
              {sub === 'providers' ? <ProviderCredentialsSection /> : null}

              {sub === 'policy' ? (
                <Card title={t('settings.signing.policy.cardTitle')}>
                  <div className="form settings-rows">
                    <Field
                      label={t('settings.signing.family.label')}
                      htmlFor="set-family"
                      hint={t('settings.signing.family.hint')}
                      help={t('settings.signing.family.help')}
                    >
                      <Select
                        id="set-family"
                        value={draft.signing.preferred_family}
                        onChange={(e) =>
                          setSigning('preferred_family', e.target.value as SignatureFamily)
                        }
                        options={optionsFrom(SIGNATURE_FAMILIES, signatureFamilyLabels)}
                      />
                    </Field>
                    <Toggle
                      label={
                        <>
                          {t('settings.signing.requireQualified.label')}{' '}
                          <FieldHelp text={t('settings.signing.requireQualified.help')} />
                        </>
                      }
                      checked={draft.signing.require_qualified_for_seal}
                      onChange={(v) => setSigning('require_qualified_for_seal', v)}
                    />
                    <p className="field__hint">{t('settings.signing.requireQualified.hint')}</p>
                    <p className="field__hint">{t('settings.signing.note')}</p>
                  </div>
                </Card>
              ) : null}

              {sub === 'tsl' ? (
                <Card title={t('settings.signing.tslSources.title')}>
                  <div className="form settings-rows">
                    <p className="field__hint">{t('settings.signing.tslSources.hint')}</p>

                    <Field
                      label={t('settings.signing.tslUrl.label')}
                      htmlFor="set-tsl"
                      hint={t('settings.signing.fallbackHint')}
                      help={t('settings.signing.tslUrl.help')}
                    >
                      <div className="input-reset">
                        <Input
                          id="set-tsl"
                          type="url"
                          value={draft.signing.tsl_url ?? ''}
                          placeholder={t('settings.signing.tslUrl.placeholder')}
                          onChange={(e) => setSigning('tsl_url', e.target.value)}
                        />
                        <IconButton
                          type="button"
                          variant="ghost"
                          icon={<Icon.Refresh />}
                          label={t('settings.signing.reset')}
                          disabled={
                            (draft.signing.tsl_url ?? '') ===
                            (DEFAULT_SETTINGS.signing.tsl_url ?? '')
                          }
                          onClick={() =>
                            setSigning('tsl_url', DEFAULT_SETTINGS.signing.tsl_url ?? '')
                          }
                        />
                      </div>
                    </Field>

                    <div className="section-head">
                      <p className="field__hint">{t('settings.signing.source.urlOrPath')}</p>
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.Plus />}
                        onClick={addTslSource}
                      >
                        {t('settings.signing.tslSources.add')}
                      </Button>
                    </div>

                    {draft.signing.tsl_sources.length === 0 ? (
                      <InlineWarning
                        tone="info"
                        title={t('settings.signing.tslSources.empty.title')}
                      >
                        {t('settings.signing.tslSources.empty.body')}
                      </InlineWarning>
                    ) : (
                      <Table
                        caption={t('settings.signing.tslSources.caption')}
                        head={
                          <tr>
                            <ColumnHead
                              label={t('settings.signing.source.name')}
                              help={t('settings.signing.tslSources.help.name')}
                            />
                            <ColumnHead
                              label={t('settings.signing.table.status')}
                              help={t('settings.signing.tslSources.help.status')}
                            />
                            <ColumnHead
                              label={t('settings.signing.source.url')}
                              help={t('settings.signing.tslSources.help.url')}
                            />
                            <ColumnHead
                              label={t('settings.signing.source.path')}
                              help={t('settings.signing.tslSources.help.path')}
                            />
                            <ColumnHead
                              label={t('settings.signing.source.country')}
                              help={t('settings.signing.tslSources.help.country')}
                            />
                            <ColumnHead
                              label={t('settings.signing.source.scheme')}
                              help={t('settings.signing.tslSources.help.scheme')}
                            />
                            <ColumnHead
                              label={t('settings.signing.table.actions')}
                              help={t('settings.signing.tslSources.help.actions')}
                            />
                          </tr>
                        }
                      >
                        {draft.signing.tsl_sources.map((source) => {
                          const rowTitle = source.name.trim() || source.id;
                          return (
                            <tr key={source.id} role="group" aria-label={rowTitle}>
                              <td data-label={t('settings.signing.source.name')}>
                                <Input
                                  aria-label={t('settings.signing.source.name')}
                                  value={source.name}
                                  onChange={(e) =>
                                    updateTslSource(source.id, { name: e.target.value })
                                  }
                                />
                                <TooltipText
                                  label={source.id}
                                  as="code"
                                  className="field__hint mono"
                                >
                                  {source.id}
                                </TooltipText>
                              </td>
                              <td data-label={t('settings.signing.table.status')}>
                                <Toggle
                                  label={
                                    source.enabled
                                      ? t('settings.signing.sourceStatus.enabled')
                                      : t('settings.signing.sourceStatus.disabled')
                                  }
                                  checked={source.enabled}
                                  onChange={(enabled) => updateTslSource(source.id, { enabled })}
                                />
                              </td>
                              <td data-label={t('settings.signing.source.url')}>
                                <Input
                                  aria-label={t('settings.signing.source.url')}
                                  type="url"
                                  value={source.url ?? ''}
                                  placeholder={t('settings.signing.tslUrl.placeholder')}
                                  onChange={(e) =>
                                    updateTslSource(source.id, { url: e.target.value })
                                  }
                                />
                              </td>
                              <td data-label={t('settings.signing.source.path')}>
                                <Input
                                  aria-label={t('settings.signing.source.path')}
                                  value={source.path ?? ''}
                                  onChange={(e) =>
                                    updateTslSource(source.id, { path: e.target.value })
                                  }
                                />
                              </td>
                              <td data-label={t('settings.signing.source.country')}>
                                <Input
                                  aria-label={t('settings.signing.source.country')}
                                  value={source.country ?? ''}
                                  placeholder="PT"
                                  onChange={(e) =>
                                    updateTslSource(source.id, { country: e.target.value })
                                  }
                                />
                              </td>
                              <td data-label={t('settings.signing.source.scheme')}>
                                <Input
                                  aria-label={t('settings.signing.source.scheme')}
                                  value={source.scheme ?? ''}
                                  placeholder="eidas"
                                  onChange={(e) =>
                                    updateTslSource(source.id, { scheme: e.target.value })
                                  }
                                />
                              </td>
                              <td data-label={t('settings.signing.table.actions')}>
                                <IconButton
                                  type="button"
                                  variant="ghost"
                                  icon={<Icon.Trash />}
                                  label={t('common.remove')}
                                  onClick={() => removeTslSource(source.id)}
                                />
                              </td>
                            </tr>
                          );
                        })}
                      </Table>
                    )}
                  </div>
                </Card>
              ) : null}

              {sub === 'tsa' ? (
                <Card title={t('settings.signing.tsaProviders.title')}>
                  <div className="form settings-rows">
                    <p className="field__hint">{t('settings.signing.tsaProviders.hint')}</p>

                    <Field
                      label={t('settings.signing.tsaUrl.label')}
                      htmlFor="set-tsa"
                      hint={t('settings.signing.fallbackHint')}
                      help={t('settings.signing.tsaUrl.help')}
                    >
                      <div className="input-reset">
                        <Input
                          id="set-tsa"
                          type="url"
                          value={draft.signing.tsa_url ?? ''}
                          placeholder={t('settings.signing.tsaUrl.placeholder')}
                          onChange={(e) => setSigning('tsa_url', e.target.value)}
                        />
                        <IconButton
                          type="button"
                          variant="ghost"
                          icon={<Icon.Refresh />}
                          label={t('settings.signing.reset')}
                          disabled={
                            (draft.signing.tsa_url ?? '') ===
                            (DEFAULT_SETTINGS.signing.tsa_url ?? '')
                          }
                          onClick={() =>
                            setSigning('tsa_url', DEFAULT_SETTINGS.signing.tsa_url ?? '')
                          }
                        />
                      </div>
                    </Field>

                    <div className="section-head">
                      <p className="field__hint">{t('settings.signing.source.urlOrPath')}</p>
                      <Button
                        type="button"
                        variant="secondary"
                        icon={<Icon.Plus />}
                        onClick={addTsaProvider}
                      >
                        {t('settings.signing.tsaProviders.add')}
                      </Button>
                    </div>

                    {draft.signing.tsa_providers.length === 0 ? (
                      <InlineWarning
                        tone="info"
                        title={t('settings.signing.tsaProviders.empty.title')}
                      >
                        {t('settings.signing.tsaProviders.empty.body')}
                      </InlineWarning>
                    ) : (
                      <Table
                        caption={t('settings.signing.tsaProviders.caption')}
                        head={
                          <tr>
                            <ColumnHead
                              label={t('settings.signing.source.name')}
                              help={t('settings.signing.tsaProviders.help.name')}
                            />
                            <ColumnHead
                              label={t('settings.signing.table.status')}
                              help={t('settings.signing.tsaProviders.help.status')}
                            />
                            <ColumnHead
                              label={t('settings.signing.source.url')}
                              help={t('settings.signing.tsaProviders.help.url')}
                            />
                            <ColumnHead
                              label={t('settings.signing.source.path')}
                              help={t('settings.signing.tsaProviders.help.path')}
                            />
                            <ColumnHead
                              label={t('settings.signing.tsaProviders.policy')}
                              help={t('settings.signing.tsaProviders.help.policy')}
                            />
                            <ColumnHead
                              label={t('settings.signing.table.limits')}
                              help={t('settings.signing.tsaProviders.help.limits')}
                            />
                            <ColumnHead
                              label={t('settings.signing.table.actions')}
                              help={t('settings.signing.tsaProviders.help.actions')}
                            />
                          </tr>
                        }
                      >
                        {draft.signing.tsa_providers.map((provider) => {
                          const rowTitle = provider.name.trim() || provider.id;
                          return (
                            <tr key={provider.id} role="group" aria-label={rowTitle}>
                              <td data-label={t('settings.signing.source.name')}>
                                <Input
                                  aria-label={t('settings.signing.source.name')}
                                  value={provider.name}
                                  onChange={(e) =>
                                    updateTsaProvider(provider.id, { name: e.target.value })
                                  }
                                />
                                <TooltipText
                                  label={provider.id}
                                  as="code"
                                  className="field__hint mono"
                                >
                                  {provider.id}
                                </TooltipText>
                              </td>
                              <td data-label={t('settings.signing.table.status')}>
                                <Toggle
                                  label={
                                    provider.enabled
                                      ? t('settings.signing.sourceStatus.enabled')
                                      : t('settings.signing.sourceStatus.disabled')
                                  }
                                  checked={provider.enabled}
                                  onChange={(enabled) =>
                                    updateTsaProvider(provider.id, { enabled })
                                  }
                                />
                                {/* Exactly one enabled provider is the default, enforced by
                                  `ensureOneEnabledDefaultProvider` on every edit — so this is a
                                  badge OR a promote button, never both. */}
                                {provider.enabled && provider.default ? (
                                  <Badge tone="accent">
                                    {t('settings.signing.tsaProviders.defaultBadge')}
                                  </Badge>
                                ) : (
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    icon={<Icon.Check />}
                                    onClick={() => makeDefaultTsaProvider(provider.id)}
                                  >
                                    {t('settings.signing.tsaProviders.makeDefault')}
                                  </Button>
                                )}
                              </td>
                              <td data-label={t('settings.signing.source.url')}>
                                <Input
                                  aria-label={t('settings.signing.source.url')}
                                  type="url"
                                  value={provider.url ?? ''}
                                  placeholder={t('settings.signing.tsaUrl.placeholder')}
                                  onChange={(e) =>
                                    updateTsaProvider(provider.id, { url: e.target.value })
                                  }
                                />
                              </td>
                              <td data-label={t('settings.signing.source.path')}>
                                <Input
                                  aria-label={t('settings.signing.source.path')}
                                  value={provider.path ?? ''}
                                  onChange={(e) =>
                                    updateTsaProvider(provider.id, { path: e.target.value })
                                  }
                                />
                              </td>
                              <td data-label={t('settings.signing.tsaProviders.policy')}>
                                <Input
                                  aria-label={t('settings.signing.tsaProviders.policy')}
                                  value={provider.policy ?? ''}
                                  placeholder="1.2.3.4"
                                  onChange={(e) =>
                                    updateTsaProvider(provider.id, { policy: e.target.value })
                                  }
                                />
                              </td>
                              {/* Server-owned, not editable here — shown so a row is complete. */}
                              <td className="mono" data-label={t('settings.signing.table.limits')}>
                                {t('settings.signing.table.limitsValue', {
                                  digest: provider.digest,
                                  timeout: provider.timeout_seconds,
                                  maxBytes: provider.max_bytes,
                                })}
                              </td>
                              <td data-label={t('settings.signing.table.actions')}>
                                <IconButton
                                  type="button"
                                  variant="ghost"
                                  icon={<Icon.Trash />}
                                  label={t('common.remove')}
                                  onClick={() => removeTsaProvider(provider.id)}
                                />
                              </td>
                            </tr>
                          );
                        })}
                      </Table>
                    )}
                  </div>
                </Card>
              ) : null}

              {sub === 'trust-services' ? (
                <Card title={t('settings.signing.providers.title')}>
                  <div className="form settings-rows">
                    <p className="field__hint">{t('settings.signing.providers.hint')}</p>
                    <Table
                      caption={t('settings.signing.providers.caption')}
                      head={
                        <tr>
                          <ColumnHead
                            label={t('settings.signing.table.provider')}
                            help={t('settings.signing.providers.help.provider')}
                          />
                          <ColumnHead
                            label={t('settings.signing.table.mode')}
                            help={t('settings.signing.providers.help.mode')}
                          />
                          <ColumnHead
                            label={t('settings.signing.table.status')}
                            help={t('settings.signing.providers.help.status')}
                          />
                          <ColumnHead
                            label={t('settings.signing.table.notes')}
                            help={t('settings.signing.providers.help.notes')}
                          />
                          <ColumnHead
                            label={t('settings.signing.table.actions')}
                            help={t('settings.signing.providers.help.actions')}
                          />
                        </tr>
                      }
                    >
                      {draft.signing.providers.map((provider) => {
                        const status = providerStatus(provider, t);
                        const configure = providerConfigureMode(provider);
                        return (
                          <tr key={provider.id}>
                            <td data-label={t('settings.signing.table.provider')}>
                              {provider.label}
                            </td>
                            <td data-label={t('settings.signing.table.mode')}>
                              {providerModeLabel(provider, t)}
                            </td>
                            <td data-label={t('settings.signing.table.status')}>
                              <span className="row-wrap">
                                <Badge tone={status.tone}>{status.label}</Badge>
                                {provider.configured && provider.production_blocked ? (
                                  <Badge tone="warn">
                                    {t('settings.signing.providerStatus.incomplete')}
                                  </Badge>
                                ) : null}
                                {provider.local_only ? (
                                  <Badge tone="accent">
                                    {t('settings.signing.providerStatus.localOnly')}
                                  </Badge>
                                ) : null}
                              </span>
                            </td>
                            <td data-label={t('settings.signing.table.notes')}>{provider.note}</td>
                            <td data-label={t('settings.signing.table.actions')}>
                              {configure ? (
                                <Button
                                  type="button"
                                  variant="secondary"
                                  icon={<Icon.Sliders />}
                                  aria-label={t('settings.signing.providers.action.configureAria', {
                                    mode: providerModeLabel(provider, t),
                                  })}
                                  onClick={() =>
                                    navigate(`/admin/signing/providers?configure=${configure}`)
                                  }
                                >
                                  {t('settings.signing.providers.action.configure')}
                                </Button>
                              ) : (
                                // Cartão de Cidadão has no in-app configuration target — it is set
                                // up on the operator's own machine. A muted note plus a help glyph,
                                // never a dead button pointing at a route that does not exist.
                                <span className="row-wrap muted">
                                  {t('settings.signing.providers.action.unavailable')}
                                  <FieldHelp
                                    text={t('settings.signing.providers.action.unavailableHelp')}
                                  />
                                </span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </Table>
                  </div>
                </Card>
              ) : null}

              {/* Explainer — what each signing mode is for and where it is configured. Read-only
                  guidance that sits below the modes table; the per-mode "Configurar" affordance
                  reuses the same deep-link contract as the table's Actions column. */}
              {sub === 'trust-services' ? (
                <Card title={t('settings.signing.providers.guide.title')}>
                  <div className="form settings-rows">
                    <p className="field__hint">{t('settings.signing.providers.guide.intro')}</p>
                    <dl className="deflist">
                      <div>
                        <dt>{t('settings.signing.providerMode.cmd')}</dt>
                        <dd>
                          <p>{t('settings.signing.providers.guide.cmd.purpose')}</p>
                          <p className="muted">
                            {t('settings.signing.providers.guide.cmd.configure')}
                          </p>
                        </dd>
                      </div>
                      <div>
                        <dt>{t('settings.signing.providerMode.cc')}</dt>
                        <dd>
                          <p>{t('settings.signing.providers.guide.cc.purpose')}</p>
                          <p className="muted">
                            {t('settings.signing.providers.guide.cc.configure')}
                          </p>
                        </dd>
                      </div>
                      <div>
                        <dt>{t('settings.signing.providerMode.cscQtsp')}</dt>
                        <dd>
                          <p>{t('settings.signing.providers.guide.cscQtsp.purpose')}</p>
                          <p className="muted">
                            {t('settings.signing.providers.guide.cscQtsp.configure')}
                          </p>
                        </dd>
                      </div>
                      <div>
                        <dt>{t('settings.signing.providerMode.localPkcs12')}</dt>
                        <dd>
                          <p>{t('settings.signing.providers.guide.localPkcs12.purpose')}</p>
                          <p className="muted">
                            {t('settings.signing.providers.guide.localPkcs12.configure')}
                          </p>
                        </dd>
                      </div>
                    </dl>
                  </div>
                </Card>
              ) : null}

              {/* Chave Móvel Digital — read-only config. The non-secret selectors (env,
                  ApplicationId) plus the "AMA cert configured?" flag come from the server; the
                  AMA secret material itself is supplied via environment variables, never the
                  settings document, so it is surfaced here for transparency, not edited. */}
              {sub === 'cmd' ? (
                <Card title={t('settings.signing.cmd.title')}>
                  <div className="form settings-rows">
                    <p className="field__hint">{t('settings.signing.cmd.intro')}</p>
                    <dl className="deflist">
                      <div>
                        <dt>{t('settings.signing.cmd.env')}</dt>
                        <dd>
                          {draft.signing.cmd.env === 'prod'
                            ? t('settings.signing.cmd.envProd')
                            : t('settings.signing.cmd.envPreprod')}
                        </dd>
                      </div>
                      <div>
                        <dt>{t('settings.signing.cmd.applicationId')}</dt>
                        <dd className="mono">
                          {draft.signing.cmd.application_id ?? t('settings.signing.cmd.unset')}
                        </dd>
                      </div>
                      <div>
                        <dt>{t('settings.signing.cmd.amaCert')}</dt>
                        <dd>
                          {draft.signing.cmd.ama_cert_configured ? (
                            <Badge tone="ok">{t('settings.signing.cmd.configured')}</Badge>
                          ) : (
                            <Badge tone="warn">{t('settings.signing.cmd.notConfigured')}</Badge>
                          )}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </Card>
              ) : null}
            </div>
          ) : null}

          {/* Gestão ------------------------------------------------------------------ */}
          {section === 'management' ? (
            <div className="stack">
              <Card title={t('settings.management.cardTitle')}>
                <div className="form settings-rows">
                  {/* The AI/MCP gate moved to Operações › IA e MCP, which is now its only
                      writer. What is left here is a read-only pointer — state, not a control —
                      so the two screens cannot disagree. Kept behind the same
                      `canManageSettings` condition the toggle itself carried, so a reader
                      without `settings.manage` sees exactly what they saw before: nothing. */}
                  {canManageSettings ? (
                    <dl className="deflist deflist--tight">
                      <div>
                        <dt>{t('settings.management.ai.label')}</dt>
                        <dd>
                          <Badge tone={draft.ai.enabled ? 'ok' : 'neutral'}>
                            {draft.ai.enabled
                              ? t('settings.platform.enabled.yes')
                              : t('settings.platform.enabled.no')}
                          </Badge>{' '}
                          {t('settings.management.ai.moved')}
                        </dd>
                      </div>
                    </dl>
                  ) : null}
                  <p className="field__hint">{t('settings.management.note')}</p>
                  <div className="row-wrap">
                    {canManageSettings ? (
                      <ButtonLink to={MCP_TAB_PATH} icon={<Icon.Sliders />}>
                        {t('settings.subnav.mcp')}
                      </ButtonLink>
                    ) : null}
                    <ButtonLink to="/settings/users" icon={<Icon.Users />}>
                      {t('settings.management.usersLink')}
                    </ButtonLink>
                    <ButtonLink to="/tools" icon={<Icon.Wrench />}>
                      {t('settings.management.toolsLink')}
                    </ButtonLink>
                  </div>
                </div>
              </Card>
              <Card title={t('settings.reminders.cardTitle')}>
                <div className="form settings-rows">
                  <Toggle
                    label={t('settings.reminders.enabled.label')}
                    checked={reminderPolicy.enabled}
                    onChange={(enabled) => setWorkflowReminder('enabled', enabled)}
                  />
                  <p className="field__hint">{t('settings.reminders.note')}</p>

                  <div className="registry-auto-update-grid">
                    <Field
                      label={t('settings.reminders.dashboardLimit.label')}
                      htmlFor="workflow-reminders-dashboard-limit"
                      hint={t('settings.reminders.dashboardLimit.hint')}
                    >
                      <Input
                        id="workflow-reminders-dashboard-limit"
                        type="number"
                        min={0}
                        max={50}
                        value={reminderPolicy.dashboard_limit}
                        onChange={(e) =>
                          setWorkflowReminder(
                            'dashboard_limit',
                            numberValue(e.target.value, reminderPolicy.dashboard_limit),
                          )
                        }
                      />
                    </Field>
                    <Field
                      label={t('settings.reminders.dueSoon.label')}
                      htmlFor="workflow-reminders-due-soon-days"
                      hint={t('settings.reminders.dueSoon.hint')}
                    >
                      <Input
                        id="workflow-reminders-due-soon-days"
                        type="number"
                        min={0}
                        max={365}
                        value={reminderPolicy.due_soon_days}
                        onChange={(e) =>
                          setWorkflowReminder(
                            'due_soon_days',
                            numberValue(e.target.value, reminderPolicy.due_soon_days),
                          )
                        }
                      />
                    </Field>
                    <Field
                      label={t('settings.reminders.attendanceLookahead.label')}
                      htmlFor="workflow-reminders-attendance-lookahead-days"
                      hint={t('settings.reminders.attendanceLookahead.hint')}
                    >
                      <Input
                        id="workflow-reminders-attendance-lookahead-days"
                        type="number"
                        min={0}
                        max={365}
                        value={reminderPolicy.attendance_lookahead_days}
                        onChange={(e) =>
                          setWorkflowReminder(
                            'attendance_lookahead_days',
                            numberValue(e.target.value, reminderPolicy.attendance_lookahead_days),
                          )
                        }
                      />
                    </Field>
                  </div>

                  <div className="stack--tight">
                    <p className="card__label">{t('settings.reminders.sources.title')}</p>
                    <div
                      className="checkbox-grid"
                      role="group"
                      aria-label={t('settings.reminders.sources.aria')}
                    >
                      <Toggle
                        label={t('settings.reminders.sources.profileCalendar')}
                        checked={reminderPolicy.sources.profile_calendar}
                        onChange={(checked) =>
                          setWorkflowReminderSource('profile_calendar', checked)
                        }
                      />
                      <Toggle
                        label={t('settings.reminders.sources.actFollowUps')}
                        checked={reminderPolicy.sources.act_follow_ups}
                        onChange={(checked) => setWorkflowReminderSource('act_follow_ups', checked)}
                      />
                      <Toggle
                        label={t('settings.reminders.sources.attendanceHygiene')}
                        checked={reminderPolicy.sources.attendance_hygiene}
                        onChange={(checked) =>
                          setWorkflowReminderSource('attendance_hygiene', checked)
                        }
                      />
                      <Toggle
                        label={t('settings.reminders.sources.privacyReviews')}
                        checked={reminderPolicy.sources.privacy_control_reviews}
                        onChange={(checked) =>
                          setWorkflowReminderSource('privacy_control_reviews', checked)
                        }
                      />
                    </div>
                  </div>
                </div>
              </Card>
              {/* The retained-export-cleanup and backup-recovery policy editors moved to the
                  Operações › Armazenamento and Cópias e recuperação subtabs respectively (t28), next
                  to the export-cleanup action and the recovery-freshness readout they govern. They
                  keep their `settings.manage` gating there via an inner fieldset. */}
              <RegistryAutoUpdateSection
                value={draft.registry_auto_update}
                onChange={setRegistryAutoUpdate}
              />
              <Card title={t('settings.entityTable.title')}>
                <div className="form settings-rows">
                  <p className="field__hint">{ct('tableColumns.entities.orgDefaultHint')}</p>
                  <div
                    className="checkbox-grid"
                    role="group"
                    aria-label={t('settings.entityTable.columns.aria')}
                  >
                    {REGISTERED_ENTITY_COLUMNS.map((column) => (
                      <Toggle
                        key={column}
                        label={t(ENTITY_COLUMN_LABEL_KEYS[column])}
                        checked={draft.ui.registered_entity_columns.includes(column)}
                        onChange={(checked) => toggleEntityColumn(column, checked)}
                      />
                    ))}
                  </div>
                </div>
              </Card>
            </div>
          ) : null}

          {/* Operações -------------------------------------------------------------- */}
          {section === 'operations' ? (
            <div className="stack">
              {/* Serviços and Registos: the same panels, the same working copy, the same
                  endpoints and the same `settings.manage` fieldset as when they were a third
                  level inside Plataforma — only which one shows is now decided by the address
                  rather than by component state. */}
              {sub === 'services' || sub === 'logs' ? (
                <div className="stack">
                  <PlatformOperationsSection
                    tab={sub}
                    value={draft.platform}
                    audit={committed.platform.audit}
                    onChange={setPlatform}
                    logsPanel={<PlatformLogTailPanel />}
                  />
                  {/* The connector egress boundary stays with Serviços: it is deployment-adjacent,
                      and `settings.manage` at Global — the highest privilege this document is
                      gated by — is what may move it. */}
                  {sub === 'services' ? (
                    <ConnectorEgressSection value={draft.connectors} onChange={setConnectors} />
                  ) : null}
                </div>
              ) : null}

              {/* Base de dados and Redis (t105). Read-only environment surfaces, not editors —
                  every value on both panes is resolved once at process start, and several embed a
                  password. See the header comments in each file for the classification. */}
              {sub === 'database' ? <DatabaseSection /> : null}
              {sub === 'cache' ? <CacheSection /> : null}

              {/* Gestão de dados (t105/t28). Its three former internal panes are now three subtabs.
                  STANDALONE: each manages its own data behind its own gates, so `editingLocked`
                  leaves it alone exactly as it did when it was one tab. `DataManagementSection` is now
                  driven by the `tab` prop (its internal SubNav is used only when rendered standalone,
                  e.g. its own unit test) so the route decides which pane shows.

                  Armazenamento. The ZK object-root declaration renders here (t28, D1): it is
                  instance-configuration for the object store, and Armazenamento is the storage pane.
                  It carries its own `settings.manage` gate inside ZkObjectRootSection. The
                  retained-export-cleanup POLICY editor is co-located here (t28), next to the export
                  cleanup action it governs (the Manutenção panel), wrapped in its own
                  `settings.manage` fieldset so this standalone subtab does not widen who may edit it. */}
              {sub === 'storage' ? (
                <div className="stack">
                  <ZkObjectRootSection />
                  <DataManagementSection tab="storage" />
                  <fieldset className="settings-fieldset" disabled={!canManageSettings}>
                    <Card title={t('settings.retainedExportCleanup.cardTitle')}>
                      <div className="form settings-rows">
                        <p className="field__hint">{t('settings.retainedExportCleanup.note')}</p>
                        <div className="registry-auto-update-grid">
                          <Field
                            label={t('settings.retainedExportCleanup.minimumAge.label')}
                            htmlFor="retained-export-cleanup-minimum-age-days"
                            hint={t('settings.retainedExportCleanup.minimumAge.hint')}
                          >
                            <Input
                              id="retained-export-cleanup-minimum-age-days"
                              type="number"
                              min={0}
                              max={RETAINED_EXPORT_CLEANUP_MAXIMUM_AGE_DAYS}
                              value={retainedExportCleanupPolicy.minimum_age_days}
                              onChange={(e) =>
                                setRetainedExportCleanupPolicy(
                                  'minimum_age_days',
                                  boundedNumberValue(
                                    e.target.value,
                                    retainedExportCleanupPolicy.minimum_age_days,
                                    0,
                                    RETAINED_EXPORT_CLEANUP_MAXIMUM_AGE_DAYS,
                                  ),
                                )
                              }
                            />
                          </Field>
                          <Field
                            label={t('settings.retainedExportCleanup.keepLatest.label')}
                            htmlFor="retained-export-cleanup-keep-latest"
                            hint={t('settings.retainedExportCleanup.keepLatest.hint')}
                          >
                            <Input
                              id="retained-export-cleanup-keep-latest"
                              type="number"
                              min={0}
                              max={RETAINED_EXPORT_CLEANUP_MAX_KEEP_LATEST}
                              value={retainedExportCleanupPolicy.keep_latest}
                              onChange={(e) =>
                                setRetainedExportCleanupPolicy(
                                  'keep_latest',
                                  boundedNumberValue(
                                    e.target.value,
                                    retainedExportCleanupPolicy.keep_latest,
                                    0,
                                    RETAINED_EXPORT_CLEANUP_MAX_KEEP_LATEST,
                                  ),
                                )
                              }
                            />
                          </Field>
                        </div>
                      </div>
                    </Card>
                  </fieldset>
                </div>
              ) : null}

              {/* Cópias e recuperação. The backup action + recovery-drill/freshness readouts, plus
                  the backup-recovery POLICY editor co-located here (t28), next to the freshness
                  readout it governs, wrapped in its own `settings.manage` fieldset for the same
                  reason as Armazenamento's policy above. */}
              {sub === 'backups' ? (
                <div className="stack">
                  <DataManagementSection tab="backups" />
                  <fieldset className="settings-fieldset" disabled={!canManageSettings}>
                    <Card title={t('settings.backupRecovery.cardTitle')}>
                      <div className="form settings-rows">
                        <p className="field__hint">{t('settings.backupRecovery.note')}</p>
                        <div className="registry-auto-update-grid">
                          <Field
                            label={t('settings.backupRecovery.maxDrillAge.label')}
                            htmlFor="backup-recovery-max-drill-age-days"
                            hint={t('settings.backupRecovery.maxDrillAge.hint')}
                          >
                            <Input
                              id="backup-recovery-max-drill-age-days"
                              type="number"
                              min={1}
                              max={BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS}
                              value={backupRecoveryPolicy.max_drill_age_days}
                              onChange={(e) =>
                                setBackupRecoveryPolicy(
                                  'max_drill_age_days',
                                  boundedNumberValue(
                                    e.target.value,
                                    backupRecoveryPolicy.max_drill_age_days,
                                    1,
                                    BACKUP_RECOVERY_MAX_DRILL_AGE_DAYS,
                                  ),
                                )
                              }
                            />
                          </Field>
                          <Field
                            label={t('settings.backupRecovery.targetRpo.label')}
                            htmlFor="backup-recovery-target-rpo-minutes"
                            hint={t('settings.backupRecovery.targetRpo.hint')}
                          >
                            <Input
                              id="backup-recovery-target-rpo-minutes"
                              type="number"
                              min={1}
                              max={BACKUP_RECOVERY_MAX_TARGET_MINUTES}
                              value={backupRecoveryPolicy.target_rpo_minutes}
                              onChange={(e) =>
                                setBackupRecoveryPolicy(
                                  'target_rpo_minutes',
                                  boundedNumberValue(
                                    e.target.value,
                                    backupRecoveryPolicy.target_rpo_minutes,
                                    1,
                                    BACKUP_RECOVERY_MAX_TARGET_MINUTES,
                                  ),
                                )
                              }
                            />
                          </Field>
                          <Field
                            label={t('settings.backupRecovery.targetRto.label')}
                            htmlFor="backup-recovery-target-rto-minutes"
                            hint={t('settings.backupRecovery.targetRto.hint')}
                          >
                            <Input
                              id="backup-recovery-target-rto-minutes"
                              type="number"
                              min={1}
                              max={BACKUP_RECOVERY_MAX_TARGET_MINUTES}
                              value={backupRecoveryPolicy.target_rto_minutes}
                              onChange={(e) =>
                                setBackupRecoveryPolicy(
                                  'target_rto_minutes',
                                  boundedNumberValue(
                                    e.target.value,
                                    backupRecoveryPolicy.target_rto_minutes,
                                    1,
                                    BACKUP_RECOVERY_MAX_TARGET_MINUTES,
                                  ),
                                )
                              }
                            />
                          </Field>
                        </div>
                      </div>
                    </Card>
                  </fieldset>
                </div>
              ) : null}

              {/* Chaves e reposição. Data-key rotation + the reset/recomeço operations. */}
              {sub === 'keys' ? <DataManagementSection tab="keys" /> : null}

              {/* API — t82b, the "Servidor" pane. Same working copy, same endpoints, same
                  `settings.manage` gate the API service row and API log levels already had. */}
              {sub === 'api' ? (
                <ApiServerSection
                  value={draft.platform}
                  canManage={canManageSettings}
                  onChange={setPlatform}
                />
              ) : null}

              {/* MCP — t82. Every MCP-specific control, gathered. It edits the SAME
                  `platform.logging` object and posts the SAME service-action endpoint as the
                  Plataforma tab did, so it is part of the settings working copy and autosaves
                  with it; `canManage` and the page's `settings.manage` fieldset carry over
                  unchanged. `ai.enabled` and the connector egress allow-list are NOT here —
                  see the comment block in McpSection.tsx. */}
              {sub === 'mcp' ? (
                <McpSection
                  value={draft.platform}
                  aiEnabled={draft.ai.enabled}
                  canManage={canManageSettings}
                  onChange={setPlatform}
                  onAiEnabledChange={(enabled) => setAi('enabled', enabled)}
                />
              ) : null}

              {/* Email (SMTP) — t23. Relocated here by t73; the section's CONTENTS are untouched.
                  The non-secret fields are part of the settings working copy and autosave with
                  everything else; the password and the test send are its own endpoints. */}
              {sub === 'email' ? <EmailSection email={draft.email} onChange={setEmail} /> : null}

              {/* Ambiente do servidor — t14. STANDALONE: it reads and writes its own endpoint
                  (`/v1/platform/env`), so it sits outside the settings working copy and the page
                  fieldset, gating its own editors on `settings.manage`. It is the editable superset
                  of the read-only environment panes above; every value is resolved once at startup,
                  so an override is stored and takes effect on the next restart, never live. */}
              {sub === 'env' ? <ServerEnvSection /> : null}

              {/* Chaves API — the API tab's second pane since t82b, but STILL its own
                  address and still in STANDALONE_SUBSECTIONS, which is what keeps its
                  `user.manage` gating and its no-savebar/no-fieldset treatment byte-identical.
                  Its component is untouched: the plaintext secret is still shown once, on
                  create/rotate only, and the table still renders the non-secret prefix alone. */}
              {sub === 'api-keys' ? <ApiKeysSection /> : null}

              {/* Integrations (t36) — Grupos / Conectores / Repositórios ZK. The one arm that is not
                  a settings-document pane: it renders the re-parented body of the retired
                  `/operations` tab (tenant picker + area dispatch), driven by the admin `:sub`
                  segment. STANDALONE, so the fieldset above never inerts it and each area keeps its
                  own gating. Reached on the admin surface (`/admin/{groups,connectors,repositories}`)
                  and via the retired `/operations/*` → `/admin/*` router redirect (t36-e1). */}
              {sub === 'groups' || sub === 'connectors' || sub === 'repositories' ? (
                <AdminIntegrationsPanel sub={sub} />
              ) : null}
            </div>
          ) : null}

          {/* Utilizadores ------------------------------------------------------------ */}
          {/* ONLY the roster lives here. Neither creating nor editing a user is an inline panel
            any more: creation left in t71, editing in t89, and both left for the same reason —
            they hand out or change authority and credentials, which is not a thing to bury under
            a list, and two addresses for one action is a defect rather than a convenience. The
            old `?user=novo` and `?user=:id` states redirect OUT to those screens, so bookmarks
            resolve and there is exactly one place each action happens. */}
          {section === 'users' && sub === 'users' ? (
            selectedUser === 'novo' ? (
              <Navigate to={NEW_USER_PATH} replace />
            ) : selectedUser ? (
              // The fragment travels with the redirect: a bookmarked
              // `/settings/users?user=u1#acesso` must still land on the access section.
              <Navigate to={editUserPath(selectedUser, hash)} replace />
            ) : (
              <UsersList />
            )
          ) : null}

          {/* Email (SMTP), Chaves API and Fornecedores de assinatura moved one level down in
              t73 — they render inside Operações / Assinaturas above, and their old
              addresses resolve there via RETIRED_SECTIONS. */}

          {/* Dispositivos — companion phone pairing (wp27) -------------------------- */}
          {section === 'devices' ? <PairingPanel /> : null}

          {/* Privacidade e conformidade ------------------------------------------- */}
          {section === 'privacy' ? <PrivacyComplianceSection /> : null}

          {/* Funções e permissões (t64-E6) — a sub-tab of Utilizadores since t106 -------- */}
          {/* The components are mounted, not changed: RolesSection still gates itself on
              `role.manage` and DelegationsSection on `delegation.revoke`/grantor identity, exactly
              as they did as top-level sections. Moving where a panel hangs must not move who may
              use it, in either direction. */}
          {section === 'users' && sub === 'roles' ? <RolesSection /> : null}

          {/* Delegações (t64-E6) — a sub-tab of Utilizadores since t106 ------------------ */}
          {section === 'users' && sub === 'delegations' ? <DelegationsSection /> : null}

          {/* Livros & Integridade ---------------------------------------------------- */}
          {section === 'integrity' ? <BookIntegritySection /> : null}

          {/* Sobre ------------------------------------------------------------------- */}
          {/* Name/value version facts are genuinely tabular, so they render as a table with a
              hidden caption naming it for a screen reader. Read-only throughout: an operator
              transcribes these into a support report, never edits them here. */}
          {section === 'about' ? (
            <Card title={t('settings.about.cardTitle')}>
              <Table
                caption={t('settings.about.tableCaption')}
                head={
                  <tr>
                    <th scope="col">{t('settings.about.column.item')}</th>
                    <th scope="col">{t('settings.about.column.value')}</th>
                  </tr>
                }
              >
                <tr>
                  <th scope="row">{t('settings.about.serverVersion')}</th>
                  <td className="mono">
                    {health.data?.version ? displayVersion(health.data.version) : '—'}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('settings.about.uiVersion')}</th>
                  <td className="mono">
                    {displayVersion(UI_VERSION)}
                    {health.data?.version && health.data.version !== UI_VERSION && (
                      <>
                        {' '}
                        <Badge tone="error">{t('settings.about.serverOutdated')}</Badge>
                      </>
                    )}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('settings.about.ledger')}</th>
                  <td>
                    {ledger.data ? (
                      ledger.data.valid ? (
                        <Badge tone="ok">
                          {t('settings.about.ledger.valid', { count: ledger.data.length })}
                        </Badge>
                      ) : (
                        <Badge tone="error">{t('settings.about.ledger.compromised')}</Badge>
                      )
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <th scope="row">{t('settings.about.schemaVersion')}</th>
                  <td className="mono">{draft.schema_version}</td>
                </tr>
                <tr>
                  <th scope="row">{t('settings.about.interfaceLocale')}</th>
                  <td>{localeLabels[activeLocale]}</td>
                </tr>
              </Table>
            </Card>
          ) : null}
        </div>
      </fieldset>

      {/* Save bar ------------------------------------------------------------------ */}
      {/* Edits across every sub-tab persist automatically (debounced whole-document PUT).
          A committed save confirms with a normal success toast (not an inline block), so
          there is no persistent status block to clutter a clean form. The bar therefore
          renders ONLY when it has something to act on:
            • Autosave ON (today): a *failed* save — an inline error plus a retry. Success
              is the toast; a clean or in-flight form shows nothing (no "Guardar agora").
            • Autosave OFF (a future toggle): whenever there are unsaved changes, to host
              the "Guardar agora" flush; a clean form shows nothing.
          The standalone sub-tabs (Utilizadores, Integridade, Chaves e reposição…) manage their own
          data and never touch the settings document, so the bar is hidden there entirely — EXCEPT
          Armazenamento and Cópias e recuperação, which host a settings-document policy editor since
          t28 (`hostsSettingsPolicy`) and so keep the same save/error feedback they had in Gestão. */}
      {(!standalone || hostsSettingsPolicy) &&
      (AUTOSAVE_ENABLED ? autosave.status === 'error' : autosave.isDirty) ? (
        <Card>
          <div className="stack--tight">
            {autosave.status === 'error' ? <ErrorNote error={autosave.error} /> : null}
            <div className="row-wrap settings-savebar">
              {/* In manual mode the bar carries a live status beside the flush button;
                  success never shows inline (it is a toast), so there is no "Guardado". */}
              {!AUTOSAVE_ENABLED ? (
                <span className="settings-autosave muted" role="status" aria-live="polite">
                  {autosave.status === 'saving'
                    ? t('common.saving')
                    : autosave.status === 'dirty'
                      ? t('settings.autosave.pending')
                      : autosave.status === 'error'
                        ? t('settings.autosave.error')
                        : ''}
                </span>
              ) : null}
              {/* Persistent manual flush only when autosave is OFF (never today). When it is
                  ON, the only manual control is an error-state retry, so a failed save is
                  always recoverable without a standing "Guardar agora" button. */}
              {!AUTOSAVE_ENABLED ? (
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.Save />}
                  disabled={!autosave.isDirty || autosave.isSaving}
                  onClick={() => autosave.flush()}
                >
                  {t('settings.saveNow')}
                </Button>
              ) : (
                <Button
                  type="button"
                  variant="secondary"
                  icon={<Icon.Refresh />}
                  disabled={autosave.isSaving}
                  onClick={() => autosave.flush()}
                >
                  {t('settings.autosave.retry')}
                </Button>
              )}
            </div>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
