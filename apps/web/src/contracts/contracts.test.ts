/**
 * Client-vs-contract tests (plan t15 §2.6, t15-e3).
 *
 * The canonical wire fixtures in the top-level `contracts/` directory (authored by
 * t15-e1, consumed here READ-ONLY) are fed through the **real** client parse path:
 * each fixture's raw bytes are returned by a mocked `fetch` with an
 * `application/json` content type, and the actual typed `api.*` function deserialises
 * them via `parseResponse`. We then assert the typed result — every field present,
 * enum encodings recognised, dates/timestamps parseable, digests well-formed.
 *
 * Drift breaks a test on **whichever side moved**:
 *  - if a fixture gains/loses/renames a field, the runtime key-set assertion fails;
 *  - if `api/types.ts` gains/loses/renames a field, the `Record<keyof T, true>` key
 *    map below fails to compile (a missing/excess key), so `tsc -b`/vitest fails.
 *
 * Together they pin the shape; the Rust harness (`e2e_contracts.rs`) pins the same
 * fixtures against live server bytes, so a server/DTO change is caught on both ends.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { api, ApiError } from '../api/client';
import {
  ACT_STATES,
  BOOK_KINDS,
  CAE_LEVELS,
  CAE_REVISIONS,
  CAE_ROLES,
  DSR_REQUEST_OUTCOMES,
  DSR_REQUEST_STATUSES,
  DSR_REQUEST_TYPES,
  ENTITY_KINDS,
  LAW_DIPLOMA_KINDS,
  LAW_VERIFICATIONS,
  LOCALES,
  MEETING_CHANNELS,
  NUMBERING_SCHEMES,
  PASSWORD_POLICY_RULE_CODES,
  PERMISSION_SOURCES,
  PLATFORM_LOG_LEVELS,
  PLATFORM_SERVICE_ACTIONS,
  PRIVACY_RECORD_STATUSES,
  PRIVACY_RISK_LEVELS,
  RETENTION_DISPOSAL_ACTIONS,
  RETENTION_POLICY_STATUSES,
  SIGNATURE_FAMILIES,
  THEME_MODES,
  TSL_SERVICE_STATUS_KINDS,
  TSL_SIGNATURE_STATUSES,
  TSL_SOURCE_KINDS,
  TSA_PROBE_KINDS,
  TSA_PROBE_STATUSES,
  TSA_STATUS_KINDS,
  type ApiKeyCreated,
  type ApiKeyGrantView,
  type ApiKeyRateLimit,
  type ApiKeyView,
  type ActMesa,
  type ActSealMetadata,
  type ActView,
  type AiSettings,
  type AppearanceSettings,
  type BackupFile,
  type BackupManifest,
  type BookView,
  type CaeSourceEntry,
  type CaeUpdates,
  type CaeVersion,
  type CatalogSettings,
  type CaeCatalogView,
  type CaeEntryView,
  type CaeLevelCounts,
  type CaeNode,
  type CaeRefView,
  type Dashboard,
  type DashboardActStateCounts,
  type DashboardAction,
  type DashboardAlert,
  type DashboardAlertTarget,
  type DashboardCurrentWork,
  type DashboardI18n,
  type DashboardLawReference,
  type DashboardOpenBook,
  type DashboardReminder,
  type DashboardTargetLinks,
  type DocumentSettings,
  type DpiaRecordView,
  type DsrRequestView,
  type Entity,
  type EntityCalendarPreset,
  type EntityProfile,
  type InscriptionDetailView,
  type ImportedDocumentView,
  type LawEntryView,
  type LawArticleView,
  type LawCorpusView,
  type LawCounts,
  type LawDiplomaDetailView,
  type LawDiplomaSummaryView,
  type LawSearchHitView,
  type LawSearchView,
  type LawSourceView,
  type LedgerEventView,
  type OnboardingSettings,
  type OrganizationSettings,
  type PasswordPolicyView,
  type PasswordRuleView,
  type PaperBookImportClassification,
  type PaperBookImportDateSpan,
  type PaperBookImportFinding,
  type PaperBookImportIdentity,
  type PaperBookContinuationRecommendation,
  type PaperBookLinkingEvidence,
  type PaperBookOriginalAtaNumberRange,
  type PaperBookImportPackage,
  type PaperBookImportReport,
  type PaperBookPageRange,
  type PermissionGrant,
  type PermissionScope,
  type PlatformActionCapability,
  type PlatformAuditEvent,
  type PlatformControlResponse,
  type PlatformControlResult,
  type PlatformLoggingSettings,
  type PlatformServiceControlSettings,
  type PlatformServiceLastAction,
  type PlatformServiceStatus,
  type PlatformServicesResponse,
  type PlatformSettings,
  type ProcessorRecordView,
  type RegistryAnnotationView,
  type RegistryEventView,
  type RegistryExtractView,
  type RegistryOfficerView,
  type RegistryProvenanceView,
  type RegistryAutoUpdateSettings,
  type RosterUser,
  type SessionRoster,
  type SessionView,
  type Settings,
  type RetentionPolicyView,
  type SigningCmdSettings,
  type SigningProviderMetadata,
  type SigningSettings,
  type TslCatalogView,
  type TslIdentitySummaryView,
  type TslProviderAnalysisView,
  type TslProviderView,
  type TslRefreshStatusView,
  type TslServiceStatusView,
  type TslServiceSummaryView,
  type TslSourceView,
  type TslSummaryView,
  type TslValidationView,
  type TsaAcceptedHashView,
  type TsaCatalogView,
  type TsaPolicyAnalysisView,
  type TsaProbeView,
  type TsaProfileView,
  type TsaRecordAnalysisView,
  type TsaRecordView,
  type TsaSummaryView,
  type TsaTimestampMetadataView,
  type TsaTslDiagnosticsView,
  type UiSettings,
  type UserDsrExport,
  type UserDsrExportUser,
  type UserDsrRoleAssignment,
  type UserView,
} from '../api/types';

// --- Fixture loading -----------------------------------------------------------
//
// Load each contract fixture as raw text (via Vite's `?raw`) so the mocked `fetch`
// returns the exact fixture BYTES, not a re-serialised object — the client's real
// JSON/text path runs on the wire representation. `import.meta.glob` (typed by
// `vite/client`) keeps the files out of the TS program, so `tsc -b`'s composite
// rootDir stays confined to `src/` while the fixtures live at the repo root.
const rawFixtures = import.meta.glob('../../../../contracts/*.json', {
  eager: true,
  query: '?raw',
  import: 'default',
}) as Record<string, string>;

const rawMarkdownFixtures = import.meta.glob('../../../../contracts/act.*.md', {
  eager: true,
  query: '?raw',
  import: 'default',
}) as Record<string, string>;

function fixture(name: string): string {
  const entry = Object.entries(rawFixtures).find(([path]) => path.endsWith(`/${name}`));
  if (!entry) {
    throw new Error(
      `contract fixture ${name} not found — loaded: ${Object.keys(rawFixtures).join(', ')}`,
    );
  }
  return entry[1];
}

function markdownFixture(name: string): string {
  const entry = Object.entries(rawMarkdownFixtures).find(([path]) => path.endsWith(`/${name}`));
  if (!entry) {
    throw new Error(
      `contract fixture ${name} not found — loaded: ${Object.keys(rawMarkdownFixtures).join(', ')}`,
    );
  }
  return entry[1];
}

/** Stub `fetch` to return a fixture's raw bytes as an `application/json` response. */
function stubFetchRaw(
  body: string,
  status = 200,
  contentType = 'application/json',
  extraHeaders: Record<string, string> = {},
): void {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(
      new Response(body, {
        status,
        headers: { 'Content-Type': contentType, ...extraHeaders },
      }),
    ),
  );
}

function stubFetch(body: string, status = 200): void {
  stubFetchRaw(body, status);
}

afterEach(() => {
  vi.restoreAllMocks();
});

// --- Shape helpers -------------------------------------------------------------

/** The optional (`foo?:`) property keys of `T` — those a `skip_serializing_if` field
 *  may legitimately omit from the wire. */
type OptionalKeys<T> = {
  [K in keyof T]-?: Record<never, never> extends Pick<T, K> ? K : never;
}[keyof T];
/** The always-present property keys of `T`. */
type RequiredKeys<T> = Exclude<keyof T, OptionalKeys<T>>;
type SettingsWire = Omit<Settings, 'registry_auto_update'> & {
  registry_auto_update?: RegistryAutoUpdateSettings;
};

/**
 * Assert `obj`'s own keys are the REQUIRED keys of the type `T` (expressed as a
 * `Record<RequiredKeys<T>, true>` the caller writes out) plus, at most, the declared
 * OPTIONAL keys. The record forces a compile error if `T`'s required set drifts (a new
 * required field must be added here, a removed one can no longer be); the runtime check
 * fails if the fixture drops a required key or carries an unexpected one. Optional
 * (`skip_serializing_if`) keys are permitted-but-not-required, so a fixture that omits
 * them (e.g. `UserView.attestation_key_fingerprint` when no key is set) still matches.
 */
function assertExactKeys<T>(
  obj: unknown,
  requiredKeys: Record<RequiredKeys<T>, true>,
  label: string,
  optionalKeys: readonly OptionalKeys<T>[] = [],
): T {
  expect(obj, `${label} should be a non-null object`).toBeTypeOf('object');
  expect(obj, `${label} should not be null`).not.toBeNull();
  const actual = Object.keys(obj as object);
  const required = Object.keys(requiredKeys);
  const allowed = new Set([...required, ...(optionalKeys as readonly string[])]);
  for (const key of actual) {
    expect(allowed.has(key), `${label} carries an unexpected key «${key}»`).toBe(true);
  }
  for (const key of required) {
    expect(actual, `${label} is missing required key «${key}»`).toContain(key);
  }
  return obj as T;
}

/** Membership check against a pinned enum encoding array (catches unknown variants). */
function inEnum(arr: readonly string[], value: string, label: string): void {
  expect(arr, `${label}: «${value}» is not a recognised enum encoding`).toContain(value);
}

/** ISO `YYYY-MM-DD` calendar date. */
function assertIsoDate(value: string, label: string): void {
  expect(value, `${label} should be YYYY-MM-DD`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  expect(Number.isNaN(Date.parse(value)), `${label} should parse as a date`).toBe(false);
}

/** RFC 3339 timestamp (ledger/user timestamps). */
function assertTimestamp(value: string, label: string): void {
  expect(Number.isNaN(Date.parse(value)), `${label} should parse as a timestamp`).toBe(false);
  expect(value, `${label} should look like RFC 3339`).toMatch(/^\d{4}-\d{2}-\d{2}T/);
}

/** Lowercase 64-hex digest / hash. */
function assertHex64(value: string, label: string): void {
  expect(value, `${label} should be a 64-char lowercase hex digest`).toMatch(/^[0-9a-f]{64}$/);
}

function assertPermissionScope(scope: unknown, label: string): PermissionScope {
  expect(scope, `${label} should be an object`).toBeTypeOf('object');
  expect(scope, `${label} should not be null`).not.toBeNull();
  const kind = (scope as { kind?: unknown }).kind;
  inEnum(['global', 'entity', 'book'], String(kind), `${label}.kind`);
  if (kind === 'global') {
    return assertExactKeys<{ kind: 'global' }>(scope, { kind: true }, label);
  }
  const scoped = assertExactKeys<{ kind: 'entity' | 'book'; id: string }>(
    scope,
    { kind: true, id: true },
    label,
  );
  expect(scoped.id, `${label}.id should be a string`).toBeTypeOf('string');
  expect(scoped.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  return scoped;
}

function assertApiKeyGrant(grant: unknown, label: string): ApiKeyGrantView {
  expect(grant, `${label} should be an object`).toBeTypeOf('object');
  expect(grant, `${label} should not be null`).not.toBeNull();
  const kind = (grant as { kind?: unknown }).kind;
  inEnum(['role', 'permissions'], String(kind), `${label}.kind`);
  if (kind === 'role') {
    const role = assertExactKeys<Extract<ApiKeyGrantView, { kind: 'role' }>>(
      grant,
      { kind: true, role_id: true, scope: true },
      label,
    );
    expect(role.role_id.length, `${label}.role_id should be non-empty`).toBeGreaterThan(0);
    assertPermissionScope(role.scope, `${label}.scope`);
    return role;
  }
  const perms = assertExactKeys<Extract<ApiKeyGrantView, { kind: 'permissions' }>>(
    grant,
    { kind: true, permissions: true, scope: true },
    label,
  );
  expect(Array.isArray(perms.permissions), `${label}.permissions should be an array`).toBe(true);
  expect(perms.permissions.length, `${label}.permissions should be non-empty`).toBeGreaterThan(0);
  for (const permission of perms.permissions) {
    expect(permission, `${label}.permissions[] should be dotted permission text`).toMatch(
      /^[a-z]+(?:\.[a-z]+)+$/,
    );
  }
  assertPermissionScope(perms.scope, `${label}.scope`);
  return perms;
}

function assertApiKeyRateLimit(rateLimit: unknown, label: string): ApiKeyRateLimit {
  const rl = assertExactKeys<ApiKeyRateLimit>(rateLimit, { rpm: true, burst: true }, label);
  expect(Number.isInteger(rl.rpm), `${label}.rpm should be an integer`).toBe(true);
  expect(Number.isInteger(rl.burst), `${label}.burst should be an integer`).toBe(true);
  expect(rl.rpm, `${label}.rpm should be non-negative`).toBeGreaterThanOrEqual(0);
  expect(rl.burst, `${label}.burst should be non-negative`).toBeGreaterThanOrEqual(0);
  return rl;
}

function assertApiKeyMetadata(key: ApiKeyView, label: string): void {
  expect(key.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(key.name.length, `${label}.name should be non-empty`).toBeGreaterThan(0);
  expect(key.prefix, `${label}.prefix should be the non-secret key prefix`).toMatch(
    /^chk_[0-9a-f]{12}$/,
  );
  expect(key.created_by.length, `${label}.created_by should be non-empty`).toBeGreaterThan(0);
  assertTimestamp(key.created_at, `${label}.created_at`);
  if (key.expires_at !== undefined) assertTimestamp(key.expires_at, `${label}.expires_at`);
  expect(typeof key.revoked, `${label}.revoked should be boolean`).toBe('boolean');
  expect(typeof key.active, `${label}.active should be boolean`).toBe('boolean');
  assertApiKeyGrant(key.grant, `${label}.grant`);
  if (key.rate_limit !== undefined) assertApiKeyRateLimit(key.rate_limit, `${label}.rate_limit`);
  expect(key, `${label} must not expose key_hash`).not.toHaveProperty('key_hash');
}

function assertApiKeyView(obj: unknown, label: string): ApiKeyView {
  const key = assertExactKeys<ApiKeyView>(
    obj,
    {
      id: true,
      name: true,
      prefix: true,
      grant: true,
      created_by: true,
      created_at: true,
      revoked: true,
      active: true,
    },
    label,
    ['expires_at', 'rate_limit'],
  );
  assertApiKeyMetadata(key, label);
  expect(key, `${label} metadata must not include secret`).not.toHaveProperty('secret');
  return key;
}

function assertApiKeyCreated(obj: unknown, label: string): ApiKeyCreated {
  const key = assertExactKeys<ApiKeyCreated>(
    obj,
    {
      secret: true,
      id: true,
      name: true,
      prefix: true,
      grant: true,
      created_by: true,
      created_at: true,
      revoked: true,
      active: true,
    },
    label,
    ['expires_at', 'rate_limit'],
  );
  assertApiKeyMetadata(key, label);
  expect(key.secret, `${label}.secret should be a full one-time API key`).toMatch(
    /^chk_[0-9a-f]{12}_[0-9a-f]{64}$/,
  );
  expect(key.secret.startsWith(`${key.prefix}_`), `${label}.secret should match prefix`).toBe(true);
  return key;
}

function assertPrivacyRecordBase(
  record: {
    purpose: string;
    legal_basis: string;
    data_categories: string[];
    subprocessors: string[];
    risk_level: string;
    status: string;
    created_at: string;
    created_by: string;
    updated_at: string;
    updated_by: string;
  },
  label: string,
): void {
  expect(record.purpose.length, `${label}.purpose should be non-empty`).toBeGreaterThan(0);
  expect(record.legal_basis.length, `${label}.legal_basis should be non-empty`).toBeGreaterThan(0);
  expect(Array.isArray(record.data_categories), `${label}.data_categories should be an array`).toBe(
    true,
  );
  expect(
    record.data_categories.length,
    `${label}.data_categories should be non-empty`,
  ).toBeGreaterThan(0);
  expect(Array.isArray(record.subprocessors), `${label}.subprocessors should be an array`).toBe(
    true,
  );
  inEnum(PRIVACY_RISK_LEVELS, record.risk_level, `${label}.risk_level`);
  inEnum(PRIVACY_RECORD_STATUSES, record.status, `${label}.status`);
  assertTimestamp(record.created_at, `${label}.created_at`);
  assertTimestamp(record.updated_at, `${label}.updated_at`);
  expect(record.created_by.length, `${label}.created_by should be non-empty`).toBeGreaterThan(0);
  expect(record.updated_by.length, `${label}.updated_by should be non-empty`).toBeGreaterThan(0);
}

function assertProcessorRecord(obj: unknown, label: string): ProcessorRecordView {
  const record = assertExactKeys<ProcessorRecordView>(
    obj,
    {
      id: true,
      name: true,
      purpose: true,
      legal_basis: true,
      data_categories: true,
      subprocessors: true,
      risk_level: true,
      status: true,
      created_at: true,
      created_by: true,
      updated_at: true,
      updated_by: true,
    },
    label,
  );
  expect(record.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(record.name.length, `${label}.name should be non-empty`).toBeGreaterThan(0);
  assertPrivacyRecordBase(record, label);
  return record;
}

function assertDpiaRecord(obj: unknown, label: string): DpiaRecordView {
  const record = assertExactKeys<DpiaRecordView>(
    obj,
    {
      id: true,
      title: true,
      purpose: true,
      legal_basis: true,
      data_categories: true,
      subprocessors: true,
      risk_level: true,
      status: true,
      created_at: true,
      created_by: true,
      updated_at: true,
      updated_by: true,
    },
    label,
  );
  expect(record.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(record.title.length, `${label}.title should be non-empty`).toBeGreaterThan(0);
  assertPrivacyRecordBase(record, label);
  return record;
}

function assertRetentionPolicy(obj: unknown, label: string): RetentionPolicyView {
  const record = assertExactKeys<RetentionPolicyView>(
    obj,
    {
      id: true,
      name: true,
      scope: true,
      category: true,
      schedule_id: true,
      retention_period: true,
      legal_basis: true,
      disposal_action: true,
      status: true,
      active: true,
      created_at: true,
      created_by: true,
      updated_at: true,
      updated_by: true,
    },
    label,
    ['notes'],
  );
  expect(record.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(record.name.length, `${label}.name should be non-empty`).toBeGreaterThan(0);
  expect(record.scope.length, `${label}.scope should be non-empty`).toBeGreaterThan(0);
  expect(record.category.length, `${label}.category should be non-empty`).toBeGreaterThan(0);
  expect(record.schedule_id.length, `${label}.schedule_id should be non-empty`).toBeGreaterThan(0);
  expect(
    record.retention_period.length,
    `${label}.retention_period should be non-empty`,
  ).toBeGreaterThan(0);
  expect(record.legal_basis.length, `${label}.legal_basis should be non-empty`).toBeGreaterThan(0);
  inEnum(RETENTION_DISPOSAL_ACTIONS, record.disposal_action, `${label}.disposal_action`);
  inEnum(RETENTION_POLICY_STATUSES, record.status, `${label}.status`);
  expect(typeof record.active, `${label}.active should be boolean`).toBe('boolean');
  assertTimestamp(record.created_at, `${label}.created_at`);
  assertTimestamp(record.updated_at, `${label}.updated_at`);
  expect(record.created_by.length, `${label}.created_by should be non-empty`).toBeGreaterThan(0);
  expect(record.updated_by.length, `${label}.updated_by should be non-empty`).toBeGreaterThan(0);
  return record;
}

function assertPlatformLastAction(obj: unknown, label: string): PlatformServiceLastAction {
  const action = assertExactKeys<PlatformServiceLastAction>(
    obj,
    {
      action: true,
      requested_at: true,
      requested_by: true,
      outcome: true,
      message: true,
    },
    label,
  );
  inEnum(PLATFORM_SERVICE_ACTIONS, action.action, `${label}.action`);
  inEnum(
    ['unsupported', 'restart_required', 'supervisor_required'],
    action.outcome,
    `${label}.outcome`,
  );
  assertTimestamp(action.requested_at, `${label}.requested_at`);
  expect(action.requested_by.length, `${label}.requested_by should be non-empty`).toBeGreaterThan(
    0,
  );
  expect(action.message.length, `${label}.message should be non-empty`).toBeGreaterThan(0);
  return action;
}

function assertPlatformServiceControl(obj: unknown, label: string): PlatformServiceControlSettings {
  const control = assertExactKeys<PlatformServiceControlSettings>(
    obj,
    { enabled: true, desired_state: true, last_action: true },
    label,
  );
  expect(typeof control.enabled, `${label}.enabled should be boolean`).toBe('boolean');
  inEnum(['running', 'stopped'], control.desired_state, `${label}.desired_state`);
  if (control.last_action !== null)
    assertPlatformLastAction(control.last_action, `${label}.last_action`);
  return control;
}

function assertPlatformLogging(obj: unknown, label: string): PlatformLoggingSettings {
  const logging = assertExactKeys<PlatformLoggingSettings>(
    obj,
    { global: true, app: true, api: true, mcp: true, service_overrides: true },
    label,
  );
  for (const field of ['global', 'app', 'api', 'mcp'] as const) {
    inEnum(PLATFORM_LOG_LEVELS, logging[field], `${label}.${field}`);
  }
  expect(logging.service_overrides, `${label}.service_overrides should be an object`).toBeTypeOf(
    'object',
  );
  expect(logging.service_overrides, `${label}.service_overrides should not be null`).not.toBeNull();
  for (const [serviceId, level] of Object.entries(logging.service_overrides)) {
    inEnum(['app', 'api', 'mcp_stdio'], serviceId, `${label}.service_overrides key`);
    inEnum(PLATFORM_LOG_LEVELS, level, `${label}.service_overrides.${serviceId}`);
  }
  return logging;
}

function assertPlatformAuditEvent(obj: unknown, label: string): PlatformAuditEvent {
  const event = assertExactKeys<PlatformAuditEvent>(
    obj,
    {
      service_id: true,
      action: true,
      requested_at: true,
      requested_by: true,
      outcome: true,
      desired_state: true,
      message: true,
    },
    label,
  );
  inEnum(['app', 'api', 'mcp_stdio'], event.service_id, `${label}.service_id`);
  inEnum(PLATFORM_SERVICE_ACTIONS, event.action, `${label}.action`);
  inEnum(['running', 'stopped'], event.desired_state, `${label}.desired_state`);
  inEnum(
    ['unsupported', 'restart_required', 'supervisor_required'],
    event.outcome,
    `${label}.outcome`,
  );
  assertTimestamp(event.requested_at, `${label}.requested_at`);
  expect(event.requested_by.length, `${label}.requested_by should be non-empty`).toBeGreaterThan(0);
  expect(event.message.length, `${label}.message should be non-empty`).toBeGreaterThan(0);
  return event;
}

function assertPlatformActionCapability(obj: unknown, label: string): PlatformActionCapability {
  const capability = assertExactKeys<PlatformActionCapability>(
    obj,
    { action: true, supported: true, outcome: true, limitation: true },
    label,
  );
  inEnum(PLATFORM_SERVICE_ACTIONS, capability.action, `${label}.action`);
  expect(typeof capability.supported, `${label}.supported should be boolean`).toBe('boolean');
  inEnum(
    ['unsupported', 'restart_required', 'supervisor_required'],
    capability.outcome,
    `${label}.outcome`,
  );
  expect(capability.limitation.length, `${label}.limitation should be non-empty`).toBeGreaterThan(
    0,
  );
  return capability;
}

function assertPlatformServiceStatus(obj: unknown, label: string): PlatformServiceStatus {
  const service = assertExactKeys<PlatformServiceStatus>(
    obj,
    {
      id: true,
      kind: true,
      label: true,
      configured: true,
      enabled: true,
      desired_state: true,
      actual_runtime_status: true,
      controllable_actions: true,
      logging_level: true,
      last_action: true,
      limitations: true,
    },
    label,
  );
  inEnum(['api', 'mcp_stdio'], service.id, `${label}.id`);
  inEnum(['api', 'mcp'], service.kind, `${label}.kind`);
  expect(service.label.length, `${label}.label should be non-empty`).toBeGreaterThan(0);
  expect(typeof service.configured, `${label}.configured should be boolean`).toBe('boolean');
  expect(typeof service.enabled, `${label}.enabled should be boolean`).toBe('boolean');
  inEnum(['running', 'stopped'], service.desired_state, `${label}.desired_state`);
  inEnum(['running', 'unknown'], service.actual_runtime_status, `${label}.actual_runtime_status`);
  inEnum(PLATFORM_LOG_LEVELS, service.logging_level, `${label}.logging_level`);
  expect(Array.isArray(service.controllable_actions), `${label}.actions should be an array`).toBe(
    true,
  );
  for (const capability of service.controllable_actions) {
    assertPlatformActionCapability(capability, `${label}.controllable_actions[]`);
  }
  if (service.last_action !== null)
    assertPlatformLastAction(service.last_action, `${label}.last_action`);
  expect(Array.isArray(service.limitations), `${label}.limitations should be an array`).toBe(true);
  for (const limitation of service.limitations) {
    expect(limitation.length, `${label}.limitations[] should be non-empty`).toBeGreaterThan(0);
  }
  return service;
}

function assertPlatformControlResult(obj: unknown, label: string): PlatformControlResult {
  const result = assertExactKeys<PlatformControlResult>(
    obj,
    {
      kind: true,
      supported: true,
      applied_to_settings: true,
      desired_state: true,
      actual_runtime_status: true,
      message: true,
      limitations: true,
    },
    label,
  );
  inEnum(['unsupported', 'restart_required', 'supervisor_required'], result.kind, `${label}.kind`);
  expect(typeof result.supported, `${label}.supported should be boolean`).toBe('boolean');
  expect(typeof result.applied_to_settings, `${label}.applied_to_settings should be boolean`).toBe(
    'boolean',
  );
  inEnum(['running', 'stopped'], result.desired_state, `${label}.desired_state`);
  inEnum(['running', 'unknown'], result.actual_runtime_status, `${label}.actual_runtime_status`);
  expect(result.message.length, `${label}.message should be non-empty`).toBeGreaterThan(0);
  expect(Array.isArray(result.limitations), `${label}.limitations should be an array`).toBe(true);
  return result;
}

function assertPaperBookImportReport(obj: unknown, label: string): PaperBookImportReport {
  const report = assertExactKeys<PaperBookImportReport>(
    obj,
    {
      report_kind: true,
      dry_run: true,
      legal_notice: true,
      identity: true,
      date_span: true,
      package: true,
      linking_evidence: true,
      continuation: true,
      candidate_classification: true,
      can_accept_as_import_candidate: true,
      required_operator_actions: true,
      findings: true,
    },
    label,
  );
  expect(report.report_kind).toBe('paper_book_import_validation');
  expect(report.dry_run).toBe(true);
  expect(report.legal_notice.length, `${label}.legal_notice should be non-empty`).toBeGreaterThan(
    0,
  );
  const identity = assertExactKeys<PaperBookImportIdentity>(
    report.identity,
    { entity_ref: true, entity_name: true, entity_nipc: true, book_ref: true },
    `${label}.identity`,
  );
  expect(identity.entity_ref.length).toBeGreaterThan(0);
  expect(identity.entity_name.length).toBeGreaterThan(0);
  expect(identity.entity_nipc).toMatch(/^\d{9}$/);
  expect(identity.book_ref.length).toBeGreaterThan(0);
  const dateSpan = assertExactKeys<PaperBookImportDateSpan>(
    report.date_span,
    { from: true, to: true },
    `${label}.date_span`,
  );
  assertIsoDate(dateSpan.from, `${label}.date_span.from`);
  assertIsoDate(dateSpan.to, `${label}.date_span.to`);
  const pkg = assertExactKeys<PaperBookImportPackage>(
    report.package,
    {
      page_count: true,
      source_page_range: true,
      source_filename: true,
      digest: true,
      notes_present: true,
      notes_truncated: true,
    },
    `${label}.package`,
  );
  expect(pkg.page_count).toBeGreaterThan(0);
  const sourcePageRange = assertExactKeys<PaperBookPageRange>(
    pkg.source_page_range,
    { from: true, to: true },
    `${label}.package.source_page_range`,
  );
  expect(sourcePageRange.from).toBeGreaterThan(0);
  expect(sourcePageRange.to).toBeGreaterThanOrEqual(sourcePageRange.from);
  expect(sourcePageRange.to).toBeLessThanOrEqual(pkg.page_count);
  if (pkg.digest) assertHex64(pkg.digest, `${label}.package.digest`);
  const linking = assertExactKeys<PaperBookLinkingEvidence>(
    report.linking_evidence,
    {
      source_page_range: true,
      original_ata_number_range: true,
      non_canonical: true,
      planning_evidence_only: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signature_created: true,
      legal_acceptance_claimed: true,
    },
    `${label}.linking_evidence`,
  );
  expect(linking.source_page_range).toEqual(sourcePageRange);
  expect(linking.non_canonical).toBe(true);
  expect(linking.planning_evidence_only).toBe(true);
  expect(linking.canonical_act_created).toBe(false);
  expect(linking.canonical_document_created).toBe(false);
  expect(linking.signature_created).toBe(false);
  expect(linking.legal_acceptance_claimed).toBe(false);
  if (linking.original_ata_number_range) {
    const range = assertExactKeys<PaperBookOriginalAtaNumberRange>(
      linking.original_ata_number_range,
      { from: true, to: true },
      `${label}.linking_evidence.original_ata_number_range`,
    );
    expect(range.from).toBeGreaterThan(0);
    expect(range.to).toBeGreaterThanOrEqual(range.from);
  }
  const continuation = assertExactKeys<PaperBookContinuationRecommendation>(
    report.continuation,
    {
      recommendation: true,
      recommended_action: true,
      recommended_next_ata_number: true,
      action_metadata: true,
      requires_operator_review: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signature_created: true,
      legal_acceptance_claimed: true,
    },
    `${label}.continuation`,
  );
  expect(continuation.recommendation.length).toBeGreaterThan(0);
  expect(continuation.recommended_action.length).toBeGreaterThan(0);
  expect(Array.isArray(continuation.action_metadata)).toBe(true);
  expect(continuation.requires_operator_review).toBe(true);
  expect(continuation.canonical_act_created).toBe(false);
  expect(continuation.canonical_document_created).toBe(false);
  expect(continuation.signature_created).toBe(false);
  expect(continuation.legal_acceptance_claimed).toBe(false);
  const classification = assertExactKeys<PaperBookImportClassification>(
    report.candidate_classification,
    {
      classification: true,
      non_canonical: true,
      historical_evidence: true,
      preservation_status: true,
      canonical_minutes_claimed: true,
      legal_validity_claimed: true,
      signature_validity_claimed: true,
      qualified_signature_claimed: true,
    },
    `${label}.candidate_classification`,
  );
  expect(classification.classification).toBe('historical_paper_book_non_canonical_evidence');
  expect(classification.preservation_status).toBe('not_preserved_by_validation');
  expect(classification.non_canonical).toBe(true);
  expect(classification.canonical_minutes_claimed).toBe(false);
  expect(classification.legal_validity_claimed).toBe(false);
  expect(classification.signature_validity_claimed).toBe(false);
  expect(classification.qualified_signature_claimed).toBe(false);
  expect(report.can_accept_as_import_candidate).toBe(true);
  expect(report.required_operator_actions.length).toBeGreaterThan(0);
  expect(report.findings.length).toBeGreaterThan(0);
  for (const finding of report.findings) {
    const item = assertExactKeys<PaperBookImportFinding>(
      finding,
      { severity: true, code: true, message: true },
      `${label}.finding`,
    );
    inEnum(['info', 'warning', 'error'], item.severity, `${label}.finding.severity`);
    expect(item.code.length).toBeGreaterThan(0);
    expect(item.message.length).toBeGreaterThan(0);
  }
  return report;
}

// --- Per-contract tests --------------------------------------------------------

describe('contract fixtures parse through the real client', () => {
  it('entity.json → Entity (POST/GET /v1/entities)', async () => {
    stubFetch(fixture('entity.json'));
    const entity: Entity = await api.getEntity('2f1c8e40-0000-4000-8000-000000000001');
    assertExactKeys<Entity>(
      entity,
      {
        id: true,
        name: true,
        nipc: true,
        nipc_validated: true,
        seat: true,
        family: true,
        kind: true,
        profile: true,
        statute: true,
      },
      'Entity',
      ['fiscal_year_end'],
    );
    expect(entity, 'Entity should expose fiscal_year_end on the wire').toHaveProperty(
      'fiscal_year_end',
    );
    expect(entity.id).not.toHaveLength(0);
    expect(entity.nipc).toMatch(/^\d{9}$/);
    expect(typeof entity.nipc_validated).toBe('boolean');
    expect(entity.fiscal_year_end, 'Entity.fiscal_year_end should be present').not.toBeUndefined();
    if (entity.fiscal_year_end !== null && entity.fiscal_year_end !== undefined) {
      expect(entity.fiscal_year_end).toMatch(/^\d{2}-\d{2}$/);
    }
    inEnum(ENTITY_KINDS, entity.kind, 'Entity.kind');
    inEnum(
      ['CommercialCompany', 'Condominium', 'Association', 'Foundation', 'Cooperative'],
      entity.family,
      'Entity.family',
    );

    // Per-family profile (t31) — computed server-side, always present.
    const profile = assertExactKeys<EntityProfile>(
      entity.profile,
      {
        family: true,
        rule_pack_id: true,
        allowed_channels: true,
        signature_policy: true,
        template_family: true,
        calendar_presets: true,
      },
      'Entity.profile',
    );
    inEnum(
      ['CommercialCompany', 'Condominium', 'Association', 'Foundation', 'Cooperative'],
      profile.family,
      'Entity.profile.family',
    );
    inEnum(
      ['QualifiedPreferred', 'QualifiedOrHandwritten', 'ManualAttested'],
      profile.signature_policy,
      'Entity.profile.signature_policy',
    );
    for (const channel of profile.allowed_channels) inEnum(MEETING_CHANNELS, channel, 'channel');
    for (const preset of profile.calendar_presets) {
      assertExactKeys<EntityCalendarPreset>(
        preset,
        { id: true, label: true, months_after_fiscal_year_end: true },
        'Entity.profile.calendar_presets[]',
      );
    }
    // Statute overlay is null (family default) or a structured override object.
    if (entity.statute !== null) expect(entity.statute).toBeTypeOf('object');
  });

  it('book.json → BookView (POST/GET /v1/books)', async () => {
    stubFetch(fixture('book.json'));
    const book: BookView = await api.getBook('3a2b1c00-0000-4000-8000-000000000002');
    assertExactKeys<BookView>(
      book,
      {
        id: true,
        entity_id: true,
        kind: true,
        state: true,
        purpose: true,
        numbering_scheme: true,
        opening_date: true,
        closing_date: true,
        closing_reason: true,
        last_ata_number: true,
        predecessor: true,
        required_signatories_abertura: true,
        required_signatories_encerramento: true,
      },
      'BookView',
    );
    inEnum(BOOK_KINDS, book.kind, 'BookView.kind');
    inEnum(['Created', 'Open', 'Closed'], book.state, 'BookView.state');
    if (book.numbering_scheme) inEnum(NUMBERING_SCHEMES, book.numbering_scheme, 'numbering_scheme');
    if (book.opening_date) assertIsoDate(book.opening_date, 'BookView.opening_date');
    expect(typeof book.last_ata_number).toBe('number');
    expect(Array.isArray(book.required_signatories_abertura)).toBe(true);
  });

  it('act.sealed.json → ActView (GET /v1/acts/{id})', async () => {
    stubFetch(fixture('act.sealed.json'));
    const act: ActView = await api.getAct('4b3c2d00-0000-4000-8000-000000000003');
    assertExactKeys<ActView>(
      act,
      {
        id: true,
        book_id: true,
        title: true,
        channel: true,
        meeting_date: true,
        meeting_time: true,
        place: true,
        mesa: true,
        agenda: true,
        attendance_reference: true,
        members_present: true,
        members_represented: true,
        referenced_documents: true,
        deliberations: true,
        deliberation_items: true,
        telematic_evidence: true,
        attachments: true,
        signatories: true,
        state: true,
        ata_number: true,
        payload_digest: true,
        seal_event_seq: true,
        seal_metadata: true,
        retifies: true,
      },
      'ActView',
    );
    inEnum(MEETING_CHANNELS, act.channel, 'ActView.channel');
    inEnum(ACT_STATES, act.state, 'ActView.state');
    expect(act.state).toBe('Sealed');
    expect(act.ata_number).toBe(1);
    if (act.meeting_date) assertIsoDate(act.meeting_date, 'ActView.meeting_date');
    if (act.meeting_time) expect(act.meeting_time).toMatch(/^\d{2}:\d{2}$/);
    if (act.payload_digest) assertHex64(act.payload_digest, 'ActView.payload_digest');
    if (act.seal_metadata) {
      const sealMetadata = assertExactKeys<ActSealMetadata>(
        act.seal_metadata,
        {
          rule_pack_id: true,
          version: true,
          family: true,
          profile: true,
        },
        'ActView.seal_metadata',
      );
      expect(sealMetadata.rule_pack_id.length).toBeGreaterThan(0);
      expect(sealMetadata.version.length).toBeGreaterThan(0);
      inEnum(
        ['CommercialCompany', 'Condominium', 'Association', 'Foundation', 'Cooperative'],
        sealMetadata.family,
        'ActView.seal_metadata.family',
      );
      inEnum(ENTITY_KINDS, sealMetadata.profile, 'ActView.seal_metadata.profile');
    }
    expect(Array.isArray(act.attachments)).toBe(true);
    expect(Array.isArray(act.signatories)).toBe(true);

    // Structured content (t31) — mesa is always present; agenda/deliberations are arrays.
    assertExactKeys<ActMesa>(act.mesa, { presidente: true, secretarios: true }, 'ActView.mesa');
    expect(Array.isArray(act.mesa.secretarios)).toBe(true);
    expect(Array.isArray(act.agenda)).toBe(true);
    for (const item of act.agenda) {
      expect(typeof item.number).toBe('number');
      expect(typeof item.text).toBe('string');
    }
    expect(Array.isArray(act.referenced_documents)).toBe(true);
    expect(Array.isArray(act.deliberation_items)).toBe(true);
  });

  it('act.working-copy.md → Markdown export (GET /v1/acts/{id}/document/working-copy)', async () => {
    const body = markdownFixture('act.working-copy.md');
    stubFetchRaw(body, 200, 'text/markdown; charset=utf-8', {
      'Content-Disposition':
        'attachment; filename="act-4b3c2d00-0000-4000-8000-000000000003-working-copy.md"',
    });

    const workingCopy = await api.fetchActDocumentWorkingCopy(
      '4b3c2d00-0000-4000-8000-000000000003',
    );

    expect(workingCopy.text).toBe(body);
    expect(workingCopy.contentType).toBe('text/markdown; charset=utf-8');
    expect(workingCopy.blob.type).toBe('text/markdown;charset=utf-8');
    expect(workingCopy.blob.type).not.toBe('application/pdf');
    expect(workingCopy.headers.get('Content-Disposition')).toContain('working-copy.md');
    expect(workingCopy.text).toContain('WORKING COPY - NON-EVIDENTIARY');
    expect(workingCopy.text).toContain('not the preserved signed original');
    expect(workingCopy.text).toContain('Ata da Assembleia Geral Anual');
    expect(workingCopy.text).not.toMatch(/^%PDF/);
    const digest = workingCopy.text.match(/Preserved PDF digest: `([0-9a-f]{64})`/)?.[1];
    expect(digest, 'working-copy fixture should cite the preserved PDF digest').toBeTruthy();
    assertHex64(digest as string, 'working-copy preserved PDF digest');
  });

  it('document.imported.json → ImportedDocumentView (GET /v1/documents/imported/{id})', async () => {
    stubFetch(fixture('document.imported.json'));
    const doc: ImportedDocumentView = await api.getImportedDocument(
      '8f7e6d50-0000-4000-8000-000000000010',
    );
    assertExactKeys<ImportedDocumentView>(
      doc,
      {
        id: true,
        act_id: true,
        filename: true,
        size_bytes: true,
        sha256: true,
        declared_content_type: true,
        detected_content_type: true,
        imported_at: true,
        imported_by: true,
        non_canonical: true,
        legal_notice: true,
        bytes_download: true,
      },
      'ImportedDocumentView',
    );
    assertHex64(doc.sha256, 'ImportedDocumentView.sha256');
    assertTimestamp(doc.imported_at, 'ImportedDocumentView.imported_at');
    expect(doc.detected_content_type).toBe('application/pdf');
    expect(doc.non_canonical).toBe(true);
    expect(doc.bytes_download).toContain(`/v1/documents/imported/${doc.id}/bytes`);
    expect(JSON.stringify(doc)).not.toContain('%PDF');
    expect(JSON.stringify(doc)).not.toContain('access_code');
  });

  it('paper-book.import.json → PaperBookImportReport (POST /v1/books/paper-import/validate)', async () => {
    stubFetch(fixture('paper-book.import.json'));
    const report: PaperBookImportReport = await api.validatePaperBookImport({
      entity_ref: 'entity-legacy-001',
      entity_name: 'Encosto Estrategico, S.A.',
      entity_nipc: '503004642',
      book_ref: 'ag-book-1968-1971',
      date_from: '1968-01-01',
      date_to: '1971-12-31',
      page_count: 240,
      source_filename: 'ag-1968-1971.pdf',
      digest: 'abababababababababababababababababababababababababababababababab',
    });
    assertPaperBookImportReport(report, 'PaperBookImportReport');
    expect(JSON.stringify(report)).not.toContain('password_hash');
    expect(JSON.stringify(report)).not.toContain('qualified_signature_claimed":true');
  });

  it('ledger.events.json → LedgerEventView[] (GET /v1/ledger/events)', async () => {
    stubFetch(fixture('ledger.events.json'));
    const events: LedgerEventView[] = await api.listLedger();
    expect(Array.isArray(events)).toBe(true);
    expect(events.length).toBeGreaterThan(0);
    const event = assertExactKeys<LedgerEventView>(
      events[0],
      {
        id: true,
        seq: true,
        actor: true,
        justification: true,
        timestamp: true,
        scope: true,
        kind: true,
        payload_digest: true,
        prev_hash: true,
        hash: true,
        chains: true,
        attestation: true,
      },
      'LedgerEventView',
    );
    expect(typeof event.seq).toBe('number');
    expect(event.actor).not.toHaveLength(0);
    assertTimestamp(event.timestamp, 'LedgerEventView.timestamp');
    assertHex64(event.payload_digest, 'LedgerEventView.payload_digest');
    assertHex64(event.prev_hash, 'LedgerEventView.prev_hash');
    assertHex64(event.hash, 'LedgerEventView.hash');
    expect(event.chains).toContain('global');
    for (const chain of event.chains) expect(typeof chain).toBe('string');
    // Attestation is null when unattested, else a {username,fingerprint,algorithm} join (t29).
    if (event.attestation !== null) {
      assertExactKeys(
        event.attestation,
        { username: true, fingerprint: true, algorithm: true },
        'LedgerEventView.attestation',
      );
    }
  });

  it('dashboard.json → Dashboard (GET /v1/dashboard)', async () => {
    stubFetch(fixture('dashboard.json'));
    const dash: Dashboard = await api.dashboard();
    assertExactKeys<Dashboard>(
      dash,
      {
        entities: true,
        books_open: true,
        books_total: true,
        acts_total: true,
        acts_draft: true,
        acts_awaiting_signature: true,
        acts_sealed: true,
        unresolved_compliance: true,
        ledger_length: true,
        ledger_valid: true,
        current_work: true,
        alerts: true,
        reminders: true,
        recent_events: true,
      },
      'Dashboard',
    );
    for (const [k, v] of Object.entries(dash)) {
      if (
        k === 'ledger_valid' ||
        k === 'current_work' ||
        k === 'alerts' ||
        k === 'recent_events' ||
        k === 'reminders'
      ) {
        continue;
      }
      expect(typeof v, `Dashboard.${k} should be a number`).toBe('number');
    }
    expect(typeof dash.ledger_valid).toBe('boolean');
    const currentWork = assertExactKeys<DashboardCurrentWork>(
      dash.current_work,
      { open_books: true, act_counts_by_state: true },
      'Dashboard.current_work',
    );
    expect(Array.isArray(currentWork.open_books)).toBe(true);
    const openBook = assertExactKeys<DashboardOpenBook>(
      currentWork.open_books[0],
      {
        book_id: true,
        entity_id: true,
        entity_name: true,
        kind: true,
        purpose: true,
        opening_date: true,
        last_ata_number: true,
        total_acts: true,
        open_acts: true,
        next_ata_number: true,
        links: true,
      },
      'Dashboard.current_work.open_books[0]',
    );
    expect(openBook.book_id.length).toBeGreaterThan(0);
    expect(openBook.entity_id.length).toBeGreaterThan(0);
    inEnum(BOOK_KINDS, openBook.kind, 'Dashboard.current_work.open_books[0].kind');
    if (openBook.entity_name !== null) expect(openBook.entity_name.length).toBeGreaterThan(0);
    if (openBook.purpose !== null) expect(openBook.purpose.length).toBeGreaterThan(0);
    if (openBook.opening_date !== null) {
      assertIsoDate(openBook.opening_date, 'Dashboard.current_work.open_books[0].opening_date');
    }
    for (const key of ['last_ata_number', 'total_acts', 'open_acts', 'next_ata_number'] as const) {
      expect(typeof openBook[key], `Dashboard.current_work.open_books[0].${key}`).toBe('number');
    }
    const openBookLinks = assertExactKeys<DashboardTargetLinks>(
      openBook.links,
      { entity: true, book: true, act: true, ledger: true },
      'Dashboard.current_work.open_books[0].links',
    );
    if (openBookLinks.entity !== null) expect(openBookLinks.entity).toMatch(/^\/v1\/entities\//);
    if (openBookLinks.book !== null) expect(openBookLinks.book).toMatch(/^\/v1\/books\//);
    if (openBookLinks.act !== null) expect(openBookLinks.act).toMatch(/^\/v1\/acts\//);
    if (openBookLinks.ledger !== null) expect(openBookLinks.ledger).toMatch(/^\/v1\/ledger\//);

    const stateCounts = assertExactKeys<DashboardActStateCounts>(
      currentWork.act_counts_by_state,
      {
        Draft: true,
        Review: true,
        Convened: true,
        Deliberated: true,
        TextApproved: true,
        Signing: true,
        Sealed: true,
        Archived: true,
      },
      'Dashboard.current_work.act_counts_by_state',
    );
    for (const value of Object.values(stateCounts)) expect(typeof value).toBe('number');

    expect(Array.isArray(dash.alerts)).toBe(true);
    const alert = assertExactKeys<DashboardAlert>(
      dash.alerts[0],
      {
        code: true,
        label: true,
        category: true,
        message: true,
        params: true,
        target: true,
        source: true,
      },
      'Dashboard.alerts[0]',
      ['severity', 'law_refs', 'action', 'recommended_next_steps', 'i18n'],
    );
    expect(alert.code.length).toBeGreaterThan(0);
    inEnum(['Advisory', 'ReviewRequired'], alert.label, 'Dashboard.alerts[0].label');
    if (alert.severity !== undefined) {
      inEnum(['Info', 'Warning', 'Error'], alert.severity, 'Dashboard.alerts[0].severity');
    }
    expect(alert.category.length).toBeGreaterThan(0);
    expect(alert.message.length).toBeGreaterThan(0);
    expect(alert.params && typeof alert.params).toBe('object');
    for (const [key, value] of Object.entries(alert.params)) {
      expect(key.length, 'Dashboard.alerts[0].params key should be non-empty').toBeGreaterThan(0);
      expect(typeof value, `Dashboard.alerts[0].params.${key} should be string`).toBe('string');
    }
    if (alert.source !== null) expect(alert.source.length).toBeGreaterThan(0);
    const alertTarget = assertExactKeys<DashboardAlertTarget>(
      alert.target,
      { entity_id: true, book_id: true, act_id: true, links: true },
      'Dashboard.alerts[0].target',
    );
    if (alertTarget.entity_id !== null) expect(alertTarget.entity_id.length).toBeGreaterThan(0);
    if (alertTarget.book_id !== null) expect(alertTarget.book_id.length).toBeGreaterThan(0);
    if (alertTarget.act_id !== null) expect(alertTarget.act_id.length).toBeGreaterThan(0);
    assertExactKeys<DashboardTargetLinks>(
      alertTarget.links,
      { entity: true, book: true, act: true, ledger: true },
      'Dashboard.alerts[0].target.links',
    );
    expect(Array.isArray(alert.law_refs)).toBe(true);
    if (alert.law_refs && alert.law_refs.length > 0) {
      const lawRef = assertExactKeys<DashboardLawReference>(
        alert.law_refs[0],
        {
          diploma_id: true,
          article: true,
          label: true,
          heading: true,
          verification: true,
          source_url: true,
          source_complete: true,
        },
        'Dashboard.alerts[0].law_refs[0]',
      );
      expect(lawRef.diploma_id.length).toBeGreaterThan(0);
      expect(lawRef.article.length).toBeGreaterThan(0);
      expect(lawRef.label.length).toBeGreaterThan(0);
      expect(typeof lawRef.source_complete).toBe('boolean');
    }
    if (alert.action !== null && alert.action !== undefined) {
      const alertAction = assertExactKeys<DashboardAction>(
        alert.action,
        { kind: true, label_key: true, api_href: true, route: true },
        'Dashboard.alerts[0].action',
      );
      expect(alertAction.kind.length).toBeGreaterThan(0);
      expect(alertAction.label_key.length).toBeGreaterThan(0);
    }
    expect(Array.isArray(alert.recommended_next_steps)).toBe(true);
    if (alert.i18n !== null && alert.i18n !== undefined) {
      const alertI18n = assertExactKeys<DashboardI18n>(
        alert.i18n,
        { title_key: true, body_key: true, action_key: true },
        'Dashboard.alerts[0].i18n',
      );
      expect(alertI18n.title_key.length).toBeGreaterThan(0);
      expect(alertI18n.body_key.length).toBeGreaterThan(0);
    }
    expect(Array.isArray(dash.reminders)).toBe(true);
    const reminder = assertExactKeys<DashboardReminder>(
      dash.reminders[0],
      {
        due_date: true,
        severity: true,
        status: true,
        reason: true,
        entity_id: true,
        entity_name: true,
        source_rule: true,
        source_profile: true,
      },
      'Dashboard.reminders[0]',
      ['params', 'law_refs', 'action', 'recommended_next_steps', 'i18n'],
    );
    assertIsoDate(reminder.due_date, 'Dashboard.reminders[0].due_date');
    inEnum(['Advisory', 'Info', 'Warning'], reminder.severity, 'Dashboard.reminders[0].severity');
    inEnum(['Upcoming', 'DueSoon', 'Overdue'], reminder.status, 'Dashboard.reminders[0].status');
    expect(
      reminder.reason.length,
      'Dashboard.reminders[0].reason should be non-empty',
    ).toBeGreaterThan(0);
    expect(
      reminder.entity_id.length,
      'Dashboard.reminders[0].entity_id should be non-empty',
    ).toBeGreaterThan(0);
    expect(
      reminder.entity_name.length,
      'Dashboard.reminders[0].entity_name should be non-empty',
    ).toBeGreaterThan(0);
    expect(
      reminder.source_rule.length,
      'Dashboard.reminders[0].source_rule should be non-empty',
    ).toBeGreaterThan(0);
    expect(
      reminder.source_profile.length,
      'Dashboard.reminders[0].source_profile should be non-empty',
    ).toBeGreaterThan(0);
    expect(Array.isArray(reminder.law_refs)).toBe(true);
    if (reminder.law_refs && reminder.law_refs.length > 0) {
      assertExactKeys<DashboardLawReference>(
        reminder.law_refs[0],
        {
          diploma_id: true,
          article: true,
          label: true,
          heading: true,
          verification: true,
          source_url: true,
          source_complete: true,
        },
        'Dashboard.reminders[0].law_refs[0]',
      );
    }
    if (reminder.action !== null && reminder.action !== undefined) {
      assertExactKeys<DashboardAction>(
        reminder.action,
        { kind: true, label_key: true, api_href: true, route: true },
        'Dashboard.reminders[0].action',
      );
    }
    expect(Array.isArray(reminder.recommended_next_steps)).toBe(true);
    if (reminder.params !== undefined) {
      expect(typeof reminder.params, 'Dashboard.reminders[0].params').toBe('object');
      for (const [key, value] of Object.entries(reminder.params)) {
        expect(key.length, 'Dashboard.reminders[0].params key should be non-empty').toBeGreaterThan(
          0,
        );
        expect(typeof value, `Dashboard.reminders[0].params.${key} should be string`).toBe(
          'string',
        );
      }
    }
    if (reminder.i18n !== null && reminder.i18n !== undefined) {
      const reminderI18n = assertExactKeys<DashboardI18n>(
        reminder.i18n,
        { title_key: true, body_key: true, action_key: true },
        'Dashboard.reminders[0].i18n',
      );
      expect(reminderI18n.title_key.length).toBeGreaterThan(0);
      expect(reminderI18n.body_key.length).toBeGreaterThan(0);
    }
    expect(Array.isArray(dash.recent_events)).toBe(true);
    // recent_events reuse the ledger event shape.
    assertExactKeys<LedgerEventView>(
      dash.recent_events[0],
      {
        id: true,
        seq: true,
        actor: true,
        justification: true,
        timestamp: true,
        scope: true,
        kind: true,
        payload_digest: true,
        prev_hash: true,
        hash: true,
        chains: true,
        attestation: true,
      },
      'Dashboard.recent_events[0]',
    );
  });

  it('settings.json → Settings (GET/PUT /v1/settings)', async () => {
    stubFetch(fixture('settings.json'));
    const settings = (await api.getSettings()) as SettingsWire;
    assertExactKeys<SettingsWire>(
      settings,
      {
        schema_version: true,
        organization: true,
        documents: true,
        catalog: true,
        signing: true,
        platform: true,
        appearance: true,
        ui: true,
        onboarding: true,
        ai: true,
      },
      'Settings',
      ['registry_auto_update'],
    );
    expect(typeof settings.schema_version).toBe('number');
    assertExactKeys<OrganizationSettings>(
      settings.organization,
      { name: true, default_actor: true },
      'Settings.organization',
    );
    const documents = assertExactKeys<DocumentSettings>(
      settings.documents,
      { locale: true, numbering_scheme_default: true },
      'Settings.documents',
    );
    inEnum(LOCALES, documents.locale, 'Settings.documents.locale');
    inEnum(NUMBERING_SCHEMES, documents.numbering_scheme_default, 'numbering_scheme_default');
    const ui = assertExactKeys<UiSettings>(
      settings.ui,
      { registered_entity_columns: true },
      'Settings.ui',
    );
    expect(Array.isArray(ui.registered_entity_columns)).toBe(true);
    expect(ui.registered_entity_columns).toContain('Actions');
    // Catalog section — legacy single URL + the strict fidelity-gated source chain (t23).
    const catalog = assertExactKeys<CatalogSettings>(
      settings.catalog,
      {
        cae_update_url: true,
        cae_sources: true,
        cae_official_source: true,
        preferred_official_source: true,
      },
      'Settings.catalog',
    );
    if (catalog.cae_update_url !== null) {
      expect(typeof catalog.cae_update_url).toBe('string');
    }
    expect(Array.isArray(catalog.cae_sources)).toBe(true);
    expect(typeof catalog.cae_official_source).toBe('boolean');
    for (const source of catalog.cae_sources) {
      const entry = assertExactKeys<CaeSourceEntry>(
        source,
        { url: true, format: true, digest: true },
        'Settings.catalog.cae_sources[]',
      );
      inEnum(['Auto', 'Envelope', 'SimpleJson', 'Pdf'], entry.format, 'cae_sources[].format');
    }
    const signing = assertExactKeys<SigningSettings>(
      settings.signing,
      {
        preferred_family: true,
        tsa_url: true,
        tsl_url: true,
        require_qualified_for_seal: true,
        cmd: true,
        providers: true,
      },
      'Settings.signing',
    );
    inEnum(SIGNATURE_FAMILIES, signing.preferred_family, 'signing.preferred_family');
    expect(typeof signing.require_qualified_for_seal).toBe('boolean');
    // CMD remote-signing config (t57-S3) — env string, nullable application_id, cert flag.
    const cmd = assertExactKeys<SigningCmdSettings>(
      signing.cmd,
      { env: true, application_id: true, ama_cert_configured: true },
      'Settings.signing.cmd',
    );
    expect(typeof cmd.env).toBe('string');
    if (cmd.application_id !== null) expect(typeof cmd.application_id).toBe('string');
    expect(typeof cmd.ama_cert_configured).toBe('boolean');
    expect(Array.isArray(signing.providers)).toBe(true);
    for (const provider of signing.providers) {
      const row = assertExactKeys<SigningProviderMetadata>(
        provider,
        {
          id: true,
          mode: true,
          label: true,
          configured: true,
          production_blocked: true,
          local_only: true,
          note: true,
        },
        'Settings.signing.providers[]',
      );
      inEnum(['CMD', 'CC', 'CSC_QTSP', 'LOCAL_PKCS12'], row.mode, 'signing.providers[].mode');
      expect(typeof row.id).toBe('string');
      expect(typeof row.label).toBe('string');
      expect(typeof row.configured).toBe('boolean');
      expect(typeof row.production_blocked).toBe('boolean');
      expect(typeof row.local_only).toBe('boolean');
      expect(typeof row.note).toBe('string');
    }
    const appearance = assertExactKeys<AppearanceSettings>(
      settings.appearance,
      { theme: true, leather_texture: true, texture_intensity: true, button_texture: true },
      'Settings.appearance',
    );
    inEnum(THEME_MODES, appearance.theme, 'Settings.appearance.theme');
    expect(typeof appearance.leather_texture).toBe('boolean');
    expect(typeof appearance.button_texture).toBe('boolean');
    expect(appearance.texture_intensity).toBeGreaterThanOrEqual(0);
    expect(appearance.texture_intensity).toBeLessThanOrEqual(100);
    // Onboarding state (t29) — serde-defaulted, no schema bump.
    const onboarding = assertExactKeys<OnboardingSettings>(
      settings.onboarding,
      { completed: true, completed_at: true },
      'Settings.onboarding',
    );
    expect(typeof onboarding.completed).toBe('boolean');
    if (onboarding.completed_at !== null) assertTimestamp(onboarding.completed_at, 'completed_at');
    const ai = assertExactKeys<AiSettings>(settings.ai, { enabled: true }, 'Settings.ai');
    expect(typeof ai.enabled).toBe('boolean');
    const platform = assertExactKeys<PlatformSettings>(
      settings.platform,
      { logging: true, api_server: true, mcp_stdio_server: true, audit: true },
      'Settings.platform',
    );
    assertPlatformLogging(platform.logging, 'Settings.platform.logging');
    assertPlatformServiceControl(platform.api_server, 'Settings.platform.api_server');
    assertPlatformServiceControl(platform.mcp_stdio_server, 'Settings.platform.mcp_stdio_server');
    expect(Array.isArray(platform.audit), 'Settings.platform.audit should be an array').toBe(true);
    for (const event of platform.audit) {
      assertPlatformAuditEvent(event, 'Settings.platform.audit[]');
    }
    if (settings.registry_auto_update !== undefined) {
      const registryAutoUpdate = assertExactKeys<RegistryAutoUpdateSettings>(
        settings.registry_auto_update,
        {
          enabled: true,
          cadence: true,
          stale_threshold_hours: true,
          min_backoff_minutes: true,
          max_backoff_minutes: true,
          max_attempts_per_run: true,
          entity_defaults: true,
        },
        'Settings.registry_auto_update',
      );
      expect(typeof registryAutoUpdate.enabled).toBe('boolean');
      expect(registryAutoUpdate.stale_threshold_hours).toBeGreaterThanOrEqual(1);
      expect(registryAutoUpdate.stale_threshold_hours).toBeLessThanOrEqual(8760);
      expect(registryAutoUpdate.min_backoff_minutes).toBeGreaterThanOrEqual(1);
      expect(registryAutoUpdate.min_backoff_minutes).toBeLessThanOrEqual(10080);
      expect(registryAutoUpdate.max_backoff_minutes).toBeGreaterThanOrEqual(1);
      expect(registryAutoUpdate.max_backoff_minutes).toBeLessThanOrEqual(10080);
      expect(registryAutoUpdate.min_backoff_minutes).toBeLessThanOrEqual(
        registryAutoUpdate.max_backoff_minutes,
      );
      expect(registryAutoUpdate.max_attempts_per_run).toBeGreaterThanOrEqual(1);
      expect(registryAutoUpdate.max_attempts_per_run).toBeLessThanOrEqual(100);
      if (registryAutoUpdate.cadence.kind === 'interval_hours') {
        expect(registryAutoUpdate.cadence.hours).toBeGreaterThanOrEqual(1);
        expect(registryAutoUpdate.cadence.hours).toBeLessThanOrEqual(720);
      } else if (registryAutoUpdate.cadence.kind === 'daily') {
        expect(registryAutoUpdate.cadence.hour_utc).toBeGreaterThanOrEqual(0);
        expect(registryAutoUpdate.cadence.hour_utc).toBeLessThanOrEqual(23);
      } else {
        inEnum(
          ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'],
          registryAutoUpdate.cadence.weekday,
          'registry_auto_update.cadence.weekday',
        );
        expect(registryAutoUpdate.cadence.hour_utc).toBeGreaterThanOrEqual(0);
        expect(registryAutoUpdate.cadence.hour_utc).toBeLessThanOrEqual(23);
      }
      const entityDefaults = assertExactKeys<RegistryAutoUpdateSettings['entity_defaults']>(
        registryAutoUpdate.entity_defaults,
        { enabled: true, enabled_profiles: true },
        'Settings.registry_auto_update.entity_defaults',
      );
      expect(typeof entityDefaults.enabled).toBe('boolean');
      expect(Array.isArray(entityDefaults.enabled_profiles)).toBe(true);
      for (const profile of entityDefaults.enabled_profiles) {
        expect(typeof profile).toBe('string');
        expect(profile.trim().length).toBeGreaterThan(0);
      }
    }
  });

  it('platform.services.json → PlatformServicesResponse (GET /v1/platform/services)', async () => {
    stubFetch(
      JSON.stringify({
        services: [
          {
            id: 'api',
            kind: 'api',
            label: 'Chancela API server',
            configured: true,
            enabled: true,
            desired_state: 'running',
            actual_runtime_status: 'running',
            controllable_actions: [
              {
                action: 'start',
                supported: false,
                outcome: 'unsupported',
                limitation: 'The current API process cannot start another copy of itself.',
              },
              {
                action: 'stop',
                supported: false,
                outcome: 'unsupported',
                limitation: 'The current API process cannot stop itself through this request.',
              },
              {
                action: 'restart',
                supported: false,
                outcome: 'restart_required',
                limitation: 'Restart requires an external supervisor or process relaunch.',
              },
            ],
            logging_level: 'debug',
            last_action: null,
            limitations: [
              'The API can observe this process as running only because it is serving this request.',
              'Start, stop, and restart require an external supervisor or process relaunch.',
            ],
          },
          {
            id: 'mcp_stdio',
            kind: 'mcp',
            label: 'Chancela MCP stdio server',
            configured: false,
            enabled: false,
            desired_state: 'stopped',
            actual_runtime_status: 'unknown',
            controllable_actions: [
              {
                action: 'start',
                supported: false,
                outcome: 'supervisor_required',
                limitation:
                  'The stdio MCP server is launched externally; the API can only record desired state.',
              },
            ],
            logging_level: 'info',
            last_action: null,
            limitations: [
              'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
              'No MCP API key or other secret is exposed through this status surface.',
            ],
          },
        ],
      }),
    );
    const response: PlatformServicesResponse = await api.listPlatformServices();
    const parsed = assertExactKeys<PlatformServicesResponse>(
      response,
      { services: true },
      'PlatformServicesResponse',
    );
    expect(parsed.services.length).toBe(2);
    const apiService = assertPlatformServiceStatus(
      parsed.services[0],
      'PlatformServiceStatus(api)',
    );
    expect(apiService.id).toBe('api');
    expect(apiService.actual_runtime_status).toBe('running');
    expect(apiService.controllable_actions.some((action) => action.supported)).toBe(false);
    const mcpService = assertPlatformServiceStatus(
      parsed.services[1],
      'PlatformServiceStatus(mcp)',
    );
    expect(mcpService.id).toBe('mcp_stdio');
    expect(mcpService.actual_runtime_status).toBe('unknown');
  });

  it('platform.control.json → PlatformControlResponse (POST /v1/platform/services/{id}/actions/{action})', async () => {
    stubFetch(
      JSON.stringify({
        service: {
          id: 'mcp_stdio',
          kind: 'mcp',
          label: 'Chancela MCP stdio server',
          configured: false,
          enabled: true,
          desired_state: 'running',
          actual_runtime_status: 'unknown',
          controllable_actions: [
            {
              action: 'start',
              supported: false,
              outcome: 'supervisor_required',
              limitation:
                'The stdio MCP server is launched externally; the API can only record desired state.',
            },
          ],
          logging_level: 'info',
          last_action: {
            action: 'start',
            requested_at: '2026-07-09T12:00:00Z',
            requested_by: 'amelia.marques',
            outcome: 'supervisor_required',
            message:
              'MCP start desired state was recorded; relaunch the external MCP client or supervisor.',
          },
          limitations: [
            'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
          ],
        },
        action: 'start',
        result: {
          kind: 'supervisor_required',
          supported: false,
          applied_to_settings: true,
          desired_state: 'running',
          actual_runtime_status: 'unknown',
          message:
            'MCP start desired state was recorded; relaunch the external MCP client or supervisor.',
          limitations: [
            'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
          ],
        },
      }),
    );
    const response: PlatformControlResponse = await api.controlPlatformService(
      'mcp_stdio',
      'start',
    );
    const parsed = assertExactKeys<PlatformControlResponse>(
      response,
      { service: true, action: true, result: true },
      'PlatformControlResponse',
    );
    inEnum(PLATFORM_SERVICE_ACTIONS, parsed.action, 'PlatformControlResponse.action');
    const service = assertPlatformServiceStatus(parsed.service, 'PlatformControlResponse.service');
    const result = assertPlatformControlResult(parsed.result, 'PlatformControlResponse.result');
    expect(service.id).toBe('mcp_stdio');
    expect(service.enabled).toBe(true);
    expect(result.supported).toBe(false);
    expect(result.applied_to_settings).toBe(true);
    expect(result.kind).toBe('supervisor_required');
  });

  it('registry.extract.json → RegistryExtractView (GET /v1/entities/{id}/registry)', async () => {
    stubFetch(fixture('registry.extract.json'));
    const extract: RegistryExtractView = await api.getEntityRegistry(
      '2f1c8e40-0000-4000-8000-000000000001',
    );
    assertExactKeys<RegistryExtractView>(
      extract,
      {
        matricula: true,
        nipc: true,
        firma: true,
        forma_juridica: true,
        legal_form: true,
        sede: true,
        cae: true,
        objeto: true,
        capital: true,
        data_constituicao: true,
        orgaos: true,
        inscricoes: true,
        anotacoes: true,
        provenance: true,
      },
      'RegistryExtractView',
    );
    if (extract.data_constituicao) assertIsoDate(extract.data_constituicao, 'data_constituicao');

    // Role-tagged CAE (plan t14 §2.7): enriched when catalogued, null-fields when not.
    expect(Array.isArray(extract.cae)).toBe(true);
    for (const ref of extract.cae) {
      const cae = assertExactKeys<CaeRefView>(
        ref,
        { code: true, role: true, designation: true, level: true, revision: true },
        'CaeRefView',
      );
      inEnum(CAE_ROLES, cae.role, 'CaeRefView.role');
      if (cae.level) inEnum(CAE_LEVELS, cae.level, 'CaeRefView.level');
      if (cae.revision) inEnum(CAE_REVISIONS, cae.revision, 'CaeRefView.revision');
      // The uncatalogued case is rendered honestly (null designation/level/revision).
      if (cae.designation === null) {
        expect(cae.level).toBeNull();
        expect(cae.revision).toBeNull();
      }
    }

    for (const officer of extract.orgaos) {
      assertExactKeys<RegistryOfficerView>(
        officer,
        {
          name: true,
          role: true,
          appointment_date: true,
          cessation_date: true,
          source_event: true,
        },
        'RegistryOfficerView',
      );
    }
    for (const inscricao of extract.inscricoes) {
      const event = assertExactKeys<RegistryEventView>(
        inscricao,
        {
          number: true,
          kind_hint: true,
          apresentacao: true,
          date: true,
          text: true,
          detail: true,
        },
        'RegistryEventView',
      );
      // Structured detail (t21) — null when unstructured, else apresentação + payload + signatures.
      if (event.detail !== null) {
        const detail = assertExactKeys<InscriptionDetailView>(
          event.detail,
          { apresentacao: true, payload: true, signatures: true },
          'RegistryEventView.detail',
        );
        if (detail.apresentacao !== null) {
          assertExactKeys(
            detail.apresentacao,
            { number: true, date: true, time: true, act_kinds: true },
            'detail.apresentacao',
          );
        }
        if (detail.payload !== null) {
          inEnum(
            ['Constitution', 'Designation', 'Cessation', 'ContractAmendment'],
            detail.payload.type,
            'detail.payload.type',
          );
        }
        for (const sig of detail.signatures) {
          assertExactKeys(sig, { conservatoria: true, oficial: true }, 'detail.signatures[]');
        }
      }
    }

    // Averbamentos / anotações (t21).
    expect(Array.isArray(extract.anotacoes)).toBe(true);
    for (const anotacao of extract.anotacoes) {
      assertExactKeys<RegistryAnnotationView>(
        anotacao,
        { number: true, date: true, publication_url: true, text: true },
        'RegistryExtractView.anotacoes[]',
      );
    }

    // Provenance still carries ONLY the masked access code (§4) plus certidão metadata (t21).
    const provenance = assertExactKeys<RegistryProvenanceView>(
      extract.provenance,
      {
        access_code_masked: true,
        retrieved_at: true,
        source_url: true,
        raw_digest: true,
        conservatoria: true,
        oficial: true,
        subscribed_on: true,
        valid_until: true,
        expired: true,
      },
      'RegistryProvenanceView',
    );
    expect(provenance.access_code_masked, 'access code must be masked').toMatch(
      /^\*{4}-\*{4}-\d{4}$/,
    );
    assertTimestamp(provenance.retrieved_at, 'provenance.retrieved_at');
    assertHex64(provenance.raw_digest, 'provenance.raw_digest');
    if (provenance.expired !== null) expect(typeof provenance.expired).toBe('boolean');
  });

  it('cae.entry.json → CaeEntryView (GET /v1/cae/{code})', async () => {
    stubFetch(fixture('cae.entry.json'));
    const entry: CaeEntryView = await api.getCae('68110');
    assertExactKeys<CaeEntryView>(
      entry,
      { code: true, designation: true, level: true, revision: true, hierarchy: true },
      'CaeEntryView',
    );
    inEnum(CAE_LEVELS, entry.level, 'CaeEntryView.level');
    inEnum(CAE_REVISIONS, entry.revision, 'CaeEntryView.revision');
    expect(Array.isArray(entry.hierarchy)).toBe(true);
    expect(entry.hierarchy.length).toBeGreaterThan(0);
    for (const node of entry.hierarchy) {
      const n = assertExactKeys<CaeNode>(
        node,
        { code: true, designation: true, level: true, revision: true },
        'CaeEntryView.hierarchy[]',
      );
      inEnum(CAE_LEVELS, n.level, 'hierarchy node level');
      inEnum(CAE_REVISIONS, n.revision, 'hierarchy node revision');
    }
    // Hierarchy ends at the node itself (secção → … → self).
    expect(entry.hierarchy[entry.hierarchy.length - 1].code).toBe(entry.code);
  });

  it('cae.catalog.json → CaeCatalogView (GET /v1/cae, no-search metadata)', async () => {
    stubFetch(fixture('cae.catalog.json'));
    const catalog: CaeCatalogView = await api.getCaeCatalog();
    assertExactKeys<CaeCatalogView>(
      catalog,
      {
        origin: true,
        schema_version: true,
        generated_at: true,
        source_note: true,
        digest: true,
        counts: true,
      },
      'CaeCatalogView',
      // `provenance` is present only on a refreshed catalog (t23); embedded/cache omit it.
      ['provenance'],
    );
    inEnum(['Embedded', 'Cache'], catalog.origin, 'CaeCatalogView.origin');
    expect(typeof catalog.schema_version).toBe('number');
    assertTimestamp(catalog.generated_at, 'CaeCatalogView.generated_at');
    assertHex64(catalog.digest, 'CaeCatalogView.digest');
    expect(Object.keys(catalog.counts).sort()).toEqual(['rev3', 'rev4']);
    for (const rev of ['rev3', 'rev4'] as const) {
      const counts = assertExactKeys<CaeLevelCounts>(
        catalog.counts[rev],
        { seccao: true, divisao: true, grupo: true, classe: true, subclasse: true },
        `CaeCatalogView.counts.${rev}`,
      );
      for (const [level, n] of Object.entries(counts)) {
        expect(typeof n, `counts.${rev}.${level} should be a number`).toBe('number');
      }
    }
  });

  it('cae.updates.json → CaeUpdates (GET /v1/cae/updates)', async () => {
    stubFetch(fixture('cae.updates.json'));
    const updates: CaeUpdates = await api.getCaeUpdates();
    assertExactKeys<CaeUpdates>(
      updates,
      { rev3: true, rev4: true, checked_at: true },
      'CaeUpdates',
    );
    assertTimestamp(updates.checked_at, 'CaeUpdates.checked_at');
    for (const rev of ['rev3', 'rev4'] as const) {
      const version = assertExactKeys<CaeVersion>(
        updates[rev],
        { version: true, designation: true },
        `CaeUpdates.${rev}`,
      );
      // SMI version codes are `V#####` (t33).
      expect(version.version, `CaeUpdates.${rev}.version`).toMatch(/^V\d+$/);
      expect(version.designation.length).toBeGreaterThan(0);
    }
  });

  it('cae.sections.json → CaeNode[] (GET /v1/cae/sections)', async () => {
    stubFetch(fixture('cae.sections.json'));
    // The top-level secções of a revision are a bare `CaeNode[]` — the same node shape the
    // search endpoint returns, so they parse through the real `searchCae` deserialiser path.
    const sections: CaeNode[] = await api.searchCae('');
    expect(Array.isArray(sections)).toBe(true);
    expect(sections.length).toBeGreaterThan(0);
    for (const node of sections) {
      const n = assertExactKeys<CaeNode>(
        node,
        { code: true, designation: true, level: true, revision: true },
        'cae.sections[]',
      );
      inEnum(CAE_LEVELS, n.level, 'cae.sections[].level');
      inEnum(CAE_REVISIONS, n.revision, 'cae.sections[].revision');
      // Sections are the roots of the tree → always the `Seccao` level.
      expect(n.level).toBe('Seccao');
      expect(n.designation.length).toBeGreaterThan(0);
    }
  });

  it('cae.children.json → CaeNode[] (GET /v1/cae/{code}/children)', async () => {
    stubFetch(fixture('cae.children.json'));
    // The direct children of a code are likewise a bare `CaeNode[]`.
    const children: CaeNode[] = await api.searchCae('');
    expect(Array.isArray(children)).toBe(true);
    expect(children.length).toBeGreaterThan(0);
    for (const node of children) {
      const n = assertExactKeys<CaeNode>(
        node,
        { code: true, designation: true, level: true, revision: true },
        'cae.children[]',
      );
      inEnum(CAE_LEVELS, n.level, 'cae.children[].level');
      inEnum(CAE_REVISIONS, n.revision, 'cae.children[].revision');
      expect(n.designation.length).toBeGreaterThan(0);
    }
  });

  function assertTslSummary(summary: unknown, label: string): TslSummaryView {
    const s = assertExactKeys<TslSummaryView>(
      summary,
      {
        source: true,
        last_refresh: true,
        scheme_operator_name: true,
        scheme_name: true,
        scheme_territory: true,
        sequence_number: true,
        issue_date_time: true,
        next_update: true,
        stale: true,
        validation: true,
        providers: true,
        services: true,
        ca_qc_services: true,
        qualified_esignature_services: true,
        trusted_esignature_services: true,
      },
      label,
    );
    const source = assertExactKeys<TslSourceView>(
      s.source,
      { kind: true, path: true, note: true },
      `${label}.source`,
    );
    inEnum(TSL_SOURCE_KINDS, source.kind, `${label}.source.kind`);
    if (source.path !== null) expect(typeof source.path).toBe('string');
    expect(source.note.length).toBeGreaterThan(0);
    if (s.last_refresh !== null) {
      assertExactKeys<TslRefreshStatusView>(
        s.last_refresh,
        {
          attempted_at: true,
          source_kind: true,
          source_url: true,
          source_path: true,
          target_path: true,
          outcome: true,
          validation: true,
          providers: true,
          services: true,
          ca_qc_services: true,
          qualified_esignature_services: true,
          trusted_esignature_services: true,
          error: true,
        },
        `${label}.last_refresh`,
      );
    }
    if (s.issue_date_time !== null) assertTimestamp(s.issue_date_time, `${label}.issue_date_time`);
    if (s.next_update !== null) assertTimestamp(s.next_update, `${label}.next_update`);
    expect(typeof s.stale).toBe('boolean');
    const validation = assertExactKeys<TslValidationView>(
      s.validation,
      { checked_at: true, signature: true, error: true },
      `${label}.validation`,
    );
    assertTimestamp(validation.checked_at, `${label}.validation.checked_at`);
    inEnum(TSL_SIGNATURE_STATUSES, validation.signature, `${label}.validation.signature`);
    if (validation.error !== null) expect(validation.error.length).toBeGreaterThan(0);
    for (const k of [
      'providers',
      'services',
      'ca_qc_services',
      'qualified_esignature_services',
      'trusted_esignature_services',
    ] as const) {
      expect(typeof s[k], `${label}.${k} should be a number`).toBe('number');
    }
    return s;
  }

  function assertTslService(service: unknown, label: string): TslServiceSummaryView {
    const svc = assertExactKeys<TslServiceSummaryView>(
      service,
      {
        id: true,
        provider_id: true,
        provider_name: true,
        name: true,
        service_type: true,
        status: true,
        status_starting_time: true,
        status_starting_time_raw: true,
        ca_qc: true,
        qualified_for_esignatures: true,
        trusted_for_esignatures: true,
        additional_service_info: true,
        service_supply_points: true,
        history_count: true,
        identities: true,
      },
      label,
    );
    expect(svc.id).toMatch(/^svc-/);
    expect(svc.provider_id).toMatch(/^tsp-/);
    const status = assertExactKeys<TslServiceStatusView>(
      svc.status,
      { kind: true, uri: true },
      `${label}.status`,
    );
    inEnum(TSL_SERVICE_STATUS_KINDS, status.kind, `${label}.status.kind`);
    if (status.uri !== null) expect(status.uri.length).toBeGreaterThan(0);
    if (svc.status_starting_time !== null)
      assertTimestamp(svc.status_starting_time, `${label}.status_starting_time`);
    if (svc.status_starting_time_raw !== null)
      expect(svc.status_starting_time_raw.length).toBeGreaterThan(0);
    expect(typeof svc.ca_qc).toBe('boolean');
    expect(typeof svc.qualified_for_esignatures).toBe('boolean');
    expect(typeof svc.trusted_for_esignatures).toBe('boolean');
    expect(Array.isArray(svc.additional_service_info)).toBe(true);
    expect(Array.isArray(svc.service_supply_points)).toBe(true);
    expect(typeof svc.history_count).toBe('number');
    const identities = assertExactKeys<TslIdentitySummaryView>(
      svc.identities,
      { certificates: true, subject_names: true, subject_key_ids: true },
      `${label}.identities`,
    );
    expect(typeof identities.certificates).toBe('number');
    expect(Array.isArray(identities.subject_names)).toBe(true);
    expect(Array.isArray(identities.subject_key_ids)).toBe(true);
    return svc;
  }

  function assertTslProviderAnalysis(analysis: unknown, label: string): TslProviderAnalysisView {
    const a = assertExactKeys<TslProviderAnalysisView>(
      analysis,
      {
        services: true,
        granted_services: true,
        withdrawn_services: true,
        other_status_services: true,
        services_with_history: true,
        services_with_supply_points: true,
        ca_qc_services: true,
        qualified_esignature_services: true,
        trusted_esignature_services: true,
        duplicate_service_names: true,
      },
      label,
    );
    for (const k of [
      'services',
      'granted_services',
      'withdrawn_services',
      'other_status_services',
      'services_with_history',
      'services_with_supply_points',
      'ca_qc_services',
      'qualified_esignature_services',
      'trusted_esignature_services',
    ] as const) {
      expect(typeof a[k], `${label}.${k} should be a number`).toBe('number');
    }
    expect(Array.isArray(a.duplicate_service_names)).toBe(true);
    return a;
  }

  it('tsl.catalog.json → TslCatalogView (GET /v1/trust/catalog)', async () => {
    stubFetch(fixture('tsl.catalog.json'));
    const catalog: TslCatalogView = await api.getTrustCatalog();
    assertExactKeys<TslCatalogView>(catalog, { summary: true, providers: true }, 'TslCatalogView');
    assertTslSummary(catalog.summary, 'TslCatalogView.summary');
    expect(Array.isArray(catalog.providers)).toBe(true);
    expect(catalog.providers.length).toBeGreaterThan(0);
    for (const provider of catalog.providers) {
      const p = assertExactKeys<TslProviderView>(
        provider,
        {
          id: true,
          name: true,
          trade_names: true,
          information_uris: true,
          analysis: true,
          services: true,
        },
        'TslCatalogView.providers[]',
      );
      expect(p.id).toMatch(/^tsp-/);
      expect(p.name.length).toBeGreaterThan(0);
      expect(Array.isArray(p.trade_names)).toBe(true);
      expect(Array.isArray(p.information_uris)).toBe(true);
      assertTslProviderAnalysis(p.analysis, 'TslCatalogView.providers[].analysis');
      expect(Array.isArray(p.services)).toBe(true);
      for (const service of p.services) {
        const svc = assertTslService(service, 'TslCatalogView.providers[].services[]');
        expect(svc.provider_id).toBe(p.id);
      }
    }
  });

  function assertTsaSummary(summary: unknown, label: string): TsaSummaryView {
    const s = assertExactKeys<TsaSummaryView>(
      summary,
      {
        configured_url: true,
        status: true,
        status_message: true,
        profile: true,
        accepted_hash: true,
        timestamp: true,
        last_probe: true,
        tsl: true,
        records: true,
        granted_records: true,
        trusted_records: true,
        policy_analysis: true,
      },
      label,
    );
    if (s.configured_url !== null) expect(s.configured_url).toMatch(/^https?:\/\//);
    inEnum(TSA_STATUS_KINDS, s.status, `${label}.status`);
    expect(s.status_message.length, `${label}.status_message`).toBeGreaterThan(0);

    const profile = assertExactKeys<TsaProfileView>(
      s.profile,
      {
        protocol: true,
        hash_algorithm: true,
        request_content_type: true,
        response_content_type: true,
        nonce_policy: true,
        cert_req_default: true,
        accepted_policy: true,
      },
      `${label}.profile`,
    );
    expect(profile.protocol).toContain('RFC 3161');
    expect(profile.hash_algorithm).toBe('SHA-256');
    expect(typeof profile.cert_req_default).toBe('boolean');

    const accepted = assertExactKeys<TsaAcceptedHashView>(
      s.accepted_hash,
      { algorithm: true, input: true, digest: true },
      `${label}.accepted_hash`,
    );
    expect(accepted.algorithm).toBe('SHA-256');
    assertHex64(accepted.digest, `${label}.accepted_hash.digest`);

    if (s.timestamp !== null) {
      const ts = assertExactKeys<TsaTimestampMetadataView>(
        s.timestamp,
        {
          gen_time: true,
          policy: true,
          serial_number: true,
          token_sha256: true,
          token_bytes: true,
          tsa_certificate_embedded: true,
        },
        `${label}.timestamp`,
      );
      assertTimestamp(ts.gen_time, `${label}.timestamp.gen_time`);
      expect(ts.policy).toMatch(/^\d+(?:\.\d+)+$/);
      expect(ts.serial_number).toMatch(/^[0-9a-f]+$/);
      assertHex64(ts.token_sha256, `${label}.timestamp.token_sha256`);
      expect(typeof ts.token_bytes).toBe('number');
      expect(typeof ts.tsa_certificate_embedded).toBe('boolean');
    }

    const probe = assertExactKeys<TsaProbeView>(
      s.last_probe,
      {
        kind: true,
        status: true,
        checked_at: true,
        request_der_sha256: true,
        response_der_sha256: true,
        request_matches_fixture: true,
        error: true,
      },
      `${label}.last_probe`,
    );
    inEnum(TSA_PROBE_KINDS, probe.kind, `${label}.last_probe.kind`);
    inEnum(TSA_PROBE_STATUSES, probe.status, `${label}.last_probe.status`);
    assertTimestamp(probe.checked_at, `${label}.last_probe.checked_at`);
    assertHex64(probe.request_der_sha256, `${label}.last_probe.request_der_sha256`);
    assertHex64(probe.response_der_sha256, `${label}.last_probe.response_der_sha256`);
    expect(typeof probe.request_matches_fixture).toBe('boolean');
    if (probe.error !== null) expect(probe.error.length).toBeGreaterThan(0);

    const tsl = assertExactKeys<TsaTslDiagnosticsView>(
      s.tsl,
      { source: true, signature: true, error: true },
      `${label}.tsl`,
    );
    assertExactKeys<TslSourceView>(
      tsl.source,
      { kind: true, path: true, note: true },
      `${label}.tsl.source`,
    );
    inEnum(TSL_SIGNATURE_STATUSES, tsl.signature, `${label}.tsl.signature`);
    if (tsl.error !== null) expect(tsl.error.length).toBeGreaterThan(0);

    for (const k of ['records', 'granted_records', 'trusted_records'] as const) {
      expect(typeof s[k], `${label}.${k} should be a number`).toBe('number');
    }
    const policy = assertExactKeys<TsaPolicyAnalysisView>(
      s.policy_analysis,
      {
        accepted_policy: true,
        fixture_policy: true,
        fixture_policy_accepted: true,
        qualified_timestamp_records: true,
        trusted_qualified_timestamp_records: true,
        advisory: true,
      },
      `${label}.policy_analysis`,
    );
    expect(policy.accepted_policy.length).toBeGreaterThan(0);
    if (policy.fixture_policy !== null) expect(policy.fixture_policy).toMatch(/^\d+(?:\.\d+)+$/);
    expect(typeof policy.fixture_policy_accepted).toBe('boolean');
    expect(typeof policy.qualified_timestamp_records).toBe('number');
    expect(typeof policy.trusted_qualified_timestamp_records).toBe('number');
    expect(typeof policy.advisory).toBe('boolean');
    return s;
  }

  function assertTsaRecord(record: unknown, label: string): TsaRecordView {
    const r = assertExactKeys<TsaRecordView>(
      record,
      {
        id: true,
        provider_id: true,
        provider_name: true,
        name: true,
        service_type: true,
        status: true,
        status_starting_time: true,
        status_starting_time_raw: true,
        qualified_timestamp_service: true,
        granted: true,
        effective: true,
        trusted: true,
        additional_service_info: true,
        service_supply_points: true,
        history_count: true,
        identities: true,
        analysis: true,
      },
      label,
    );
    expect(r.id.length, `${label}.id`).toBeGreaterThan(0);
    expect(r.provider_id.length, `${label}.provider_id`).toBeGreaterThan(0);
    expect(r.provider_name.length, `${label}.provider_name`).toBeGreaterThan(0);
    expect(r.service_type, `${label}.service_type should be a TSA service`).toContain('/TSA');
    const status = assertExactKeys<TslServiceStatusView>(
      r.status,
      { kind: true, uri: true },
      `${label}.status`,
    );
    inEnum(TSL_SERVICE_STATUS_KINDS, status.kind, `${label}.status.kind`);
    if (r.status_starting_time !== null)
      assertTimestamp(r.status_starting_time, `${label}.status_starting_time`);
    if (r.status_starting_time_raw !== null)
      expect(r.status_starting_time_raw.length).toBeGreaterThan(0);
    for (const k of ['qualified_timestamp_service', 'granted', 'effective', 'trusted'] as const) {
      expect(typeof r[k], `${label}.${k} should be boolean`).toBe('boolean');
    }
    expect(Array.isArray(r.additional_service_info)).toBe(true);
    expect(Array.isArray(r.service_supply_points)).toBe(true);
    expect(typeof r.history_count).toBe('number');
    assertExactKeys<TslIdentitySummaryView>(
      r.identities,
      { certificates: true, subject_names: true, subject_key_ids: true },
      `${label}.identities`,
    );
    const analysis = assertExactKeys<TsaRecordAnalysisView>(
      r.analysis,
      { classification: true, trust_basis: true, blocking_reasons: true },
      `${label}.analysis`,
    );
    expect(analysis.classification.length).toBeGreaterThan(0);
    expect(analysis.trust_basis.length).toBeGreaterThan(0);
    expect(Array.isArray(analysis.blocking_reasons)).toBe(true);
    return r;
  }

  it('tsa.status.json → TsaCatalogView (GET /v1/trust/tsa)', async () => {
    stubFetch(fixture('tsa.status.json'));
    const catalog: TsaCatalogView = await api.getTsaCatalog();
    assertExactKeys<TsaCatalogView>(catalog, { summary: true, records: true }, 'TsaCatalogView');
    const summary = assertTsaSummary(catalog.summary, 'TsaCatalogView.summary');
    expect(Array.isArray(catalog.records)).toBe(true);
    expect(catalog.records.length).toBe(summary.records);
    for (const record of catalog.records) {
      assertTsaRecord(record, 'TsaCatalogView.records[]');
    }
  });

  it('law.manifest.json → LawEntryView[] (GET /v1/law)', async () => {
    stubFetch(fixture('law.manifest.json'));
    // `getLawManifest` returns the bare array (or the tolerant `{ entries }` form); the
    // fixture is the canonical bare `[LawEntryView]`.
    const manifest = await api.getLawManifest();
    expect(Array.isArray(manifest), 'law manifest fixture is a bare array').toBe(true);
    const entries = manifest as LawEntryView[];
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      const e = assertExactKeys<LawEntryView>(
        entry,
        {
          id: true,
          title: true,
          ref: true,
          articles: true,
          why: true,
          official_url: true,
          pdf_url: true,
          last_amended: true,
          reviewed_on: true,
          stored: true,
          stored_digest: true,
          stored_bytes: true,
          retrieved_at: true,
        },
        'LawEntryView',
      );
      expect(e.id).not.toHaveLength(0);
      expect(Array.isArray(e.articles)).toBe(true);
      assertIsoDate(e.reviewed_on, 'LawEntryView.reviewed_on');
      expect(typeof e.stored).toBe('boolean');
      // Store state is consistent: a stored entry carries its digest/bytes/timestamp.
      if (e.stored) {
        expect(e.stored_digest, 'stored entry has a digest').not.toBeNull();
        if (e.stored_digest !== null) assertHex64(e.stored_digest, 'LawEntryView.stored_digest');
        expect(typeof e.stored_bytes).toBe('number');
        if (e.retrieved_at !== null) assertTimestamp(e.retrieved_at, 'LawEntryView.retrieved_at');
      }
    }
  });

  // A shared shape check for a corpus article — reused by the diploma-detail and single-article
  // fixtures. Verifies the authenticity contract on the wire: `verification` is a known variant,
  // `verified` matches it, and the source's optional citation fields are permitted-but-not-required
  // (omitted while `Pending`), with `complete` always present.
  function assertLawArticle(article: unknown, label: string): LawArticleView {
    const a = assertExactKeys<LawArticleView>(
      article,
      {
        diploma_id: true,
        number: true,
        label: true,
        heading: true,
        body: true,
        verification: true,
        verified: true,
        source: true,
      },
      label,
      // `cross_refs` is omitted from the wire when empty (skip_serializing_if).
      ['cross_refs'],
    );
    expect(a.diploma_id.length, `${label}.diploma_id`).toBeGreaterThan(0);
    expect(a.number.length, `${label}.number`).toBeGreaterThan(0);
    inEnum(LAW_VERIFICATIONS, a.verification, `${label}.verification`);
    expect(typeof a.verified, `${label}.verified`).toBe('boolean');
    // The `verified` boolean mirrors the `verification` enum exactly.
    expect(a.verified).toBe(a.verification === 'Verified');
    // A `Pending` article never presents an un-sourced body — it renders the loud marker.
    if (!a.verified) {
      expect(a.body, `${label} pending body is the unverified marker`).toContain('NÃO VERIFICADO');
    } else {
      expect(a.body.trim().length, `${label} verified body is non-empty`).toBeGreaterThan(0);
    }
    if (a.cross_refs !== undefined) expect(Array.isArray(a.cross_refs)).toBe(true);
    const source = assertExactKeys<LawSourceView>(
      a.source,
      { diploma: true, article: true, complete: true },
      `${label}.source`,
      ['dr_reference', 'dr_date', 'url', 'source_digest', 'retrieved_at'],
    );
    expect(typeof source.complete, `${label}.source.complete`).toBe('boolean');
    // A complete source cites a real origin (diploma + article + dr_reference + url) — the
    // precondition for a Verified article; an incomplete one omits those authenticity fields.
    if (source.complete) {
      expect(source.dr_reference, `${label}.source.dr_reference (complete)`).toBeTruthy();
      expect(source.url, `${label}.source.url (complete)`).toBeTruthy();
    }
    // A Verified article must cite a complete source.
    if (a.verified) expect(source.complete, `${label} verified ⇒ complete source`).toBe(true);
    return a;
  }

  // The required-key map for a diploma SUMMARY, reused by the corpus list and the diploma header.
  const DIPLOMA_SUMMARY_KEYS = {
    id: true,
    kind: true,
    number: true,
    title: true,
    ref: true,
    official_url: true,
    article_count: true,
    verified_count: true,
    pending_count: true,
  } as const;

  function assertDiplomaSummary<T extends LawDiplomaSummaryView>(
    obj: unknown,
    requiredKeys: Record<RequiredKeys<T>, true>,
    label: string,
    optionalKeys: readonly OptionalKeys<T>[],
  ): T {
    const d = assertExactKeys<T>(obj, requiredKeys, label, optionalKeys);
    inEnum(LAW_DIPLOMA_KINDS, d.kind, `${label}.kind`);
    for (const k of ['article_count', 'verified_count', 'pending_count'] as const) {
      expect(typeof d[k], `${label}.${k}`).toBe('number');
    }
    // The counts partition the diploma: verified + pending = total.
    expect(d.verified_count + d.pending_count, `${label} counts partition`).toBe(d.article_count);
    return d;
  }

  it('law.corpus.json → LawCorpusView (GET /v1/law/corpus)', async () => {
    stubFetch(fixture('law.corpus.json'));
    const corpus: LawCorpusView = await api.getLawCorpus();
    assertExactKeys<LawCorpusView>(
      corpus,
      {
        schema_version: true,
        generated_at: true,
        source_note: true,
        digest: true,
        origin: true,
        counts: true,
        diplomas: true,
      },
      'LawCorpusView',
      // `provenance` is present only on an obtained corpus; the embedded corpus omits it.
      ['provenance'],
    );
    expect(typeof corpus.schema_version).toBe('number');
    assertTimestamp(corpus.generated_at, 'LawCorpusView.generated_at');
    assertHex64(corpus.digest, 'LawCorpusView.digest');
    inEnum(['Embedded', 'Cache'], corpus.origin, 'LawCorpusView.origin');
    const counts = assertExactKeys<LawCounts>(
      corpus.counts,
      { diplomas: true, articles: true, verified: true, pending: true },
      'LawCorpusView.counts',
    );
    for (const [k, v] of Object.entries(counts)) {
      expect(typeof v, `LawCorpusView.counts.${k}`).toBe('number');
    }
    // The corpus-wide counts partition every article into verified/pending.
    expect(counts.verified + counts.pending, 'counts partition').toBe(counts.articles);
    expect(Array.isArray(corpus.diplomas)).toBe(true);
    expect(corpus.diplomas.length).toBeGreaterThan(0);
    for (const d of corpus.diplomas) {
      assertDiplomaSummary<LawDiplomaSummaryView>(
        d,
        DIPLOMA_SUMMARY_KEYS,
        'LawCorpusView.diplomas[]',
        ['eli'],
      );
    }
  });

  it('law.diploma.json → LawDiplomaDetailView (GET /v1/law/corpus/{diploma})', async () => {
    stubFetch(fixture('law.diploma.json'));
    const detail: LawDiplomaDetailView = await api.getLawDiploma('eidas-910-2014');
    // The summary is flattened onto the body, so the detail is a summary PLUS `articles`.
    const summary = assertDiplomaSummary<LawDiplomaDetailView>(
      detail,
      { ...DIPLOMA_SUMMARY_KEYS, articles: true },
      'LawDiplomaDetailView',
      ['eli'],
    );
    expect(summary.id).not.toHaveLength(0);
    expect(Array.isArray(detail.articles)).toBe(true);
    expect(detail.articles.length).toBeGreaterThan(0);
    for (const a of detail.articles) {
      const article = assertLawArticle(a, 'LawDiplomaDetailView.articles[]');
      // A diploma's articles denormalize their owning diploma id.
      expect(article.diploma_id).toBe(detail.id);
    }
  });

  it('law.article.json → LawArticleView (GET /v1/law/corpus/{diploma}/{article})', async () => {
    stubFetch(fixture('law.article.json'));
    const article: LawArticleView = await api.getLawArticle('csc', '63');
    const a = assertLawArticle(article, 'LawArticleView');
    // The single-article fixture pins the Pending shape: the marker body + an incomplete source.
    expect(a.verified).toBe(false);
    expect(a.source.complete).toBe(false);
  });

  it('law.search.json → LawSearchView (GET /v1/law/corpus/search)', async () => {
    stubFetch(fixture('law.search.json'));
    const search: LawSearchView = await api.searchLawCorpus('assinatura');
    assertExactKeys<LawSearchView>(
      search,
      { query: true, count: true, results: true },
      'LawSearchView',
    );
    expect(typeof search.query).toBe('string');
    expect(typeof search.count).toBe('number');
    expect(Array.isArray(search.results)).toBe(true);
    // `count` is the number of returned hits.
    expect(search.count).toBe(search.results.length);
    expect(search.results.length).toBeGreaterThan(0);
    for (const hit of search.results) {
      const h = assertExactKeys<LawSearchHitView>(
        hit,
        {
          diploma_id: true,
          diploma_title: true,
          number: true,
          label: true,
          heading: true,
          snippet: true,
          verification: true,
          verified: true,
        },
        'LawSearchView.results[]',
      );
      expect(h.diploma_id.length, 'hit.diploma_id').toBeGreaterThan(0);
      expect(h.diploma_title.length, 'hit.diploma_title').toBeGreaterThan(0);
      expect(h.snippet.length, 'hit.snippet').toBeGreaterThan(0);
      inEnum(LAW_VERIFICATIONS, h.verification, 'hit.verification');
      expect(h.verified).toBe(h.verification === 'Verified');
    }
  });

  it('backup.manifest.json → BackupManifest (POST /v1/backup)', async () => {
    stubFetch(fixture('backup.manifest.json'));
    const manifest: BackupManifest = await api.backup();
    assertExactKeys<BackupManifest>(
      manifest,
      {
        path: true,
        bytes: true,
        created_at: true,
        app_version: true,
        store_schema_version: true,
        ledger_length: true,
        ledger_head: true,
        ledger_verified: true,
        files: true,
      },
      'BackupManifest',
    );
    expect(manifest.path).not.toHaveLength(0);
    expect(typeof manifest.bytes).toBe('number');
    assertTimestamp(manifest.created_at, 'BackupManifest.created_at');
    expect(manifest.app_version).not.toHaveLength(0);
    expect(typeof manifest.store_schema_version).toBe('number');
    expect(typeof manifest.ledger_length).toBe('number');
    // Empty-ledger head is null; otherwise a 64-hex chain head.
    if (manifest.ledger_head !== null)
      assertHex64(manifest.ledger_head, 'BackupManifest.ledger_head');
    expect(typeof manifest.ledger_verified).toBe('boolean');
    expect(Array.isArray(manifest.files)).toBe(true);
    expect(manifest.files.length).toBeGreaterThan(0);
    for (const file of manifest.files) {
      const f = assertExactKeys<BackupFile>(
        file,
        { name: true, sha256: true, bytes: true },
        'BackupManifest.files[]',
      );
      expect(f.name).not.toHaveLength(0);
      assertHex64(f.sha256, 'BackupManifest.files[].sha256');
      expect(typeof f.bytes).toBe('number');
    }
  });

  it('user.json → UserView (POST/GET /v1/users)', async () => {
    stubFetch(fixture('user.json'));
    const user: UserView = await api.getUser('6d5e4f00-0000-4000-8000-000000000005');
    assertExactKeys<UserView>(
      user,
      {
        id: true,
        username: true,
        display_name: true,
        created_at: true,
        active: true,
        has_secret: true,
        has_attestation_key: true,
        has_recovery_phrase: true,
      },
      'UserView',
      // Fingerprint is emitted only when an attestation key is set (t29).
      ['attestation_key_fingerprint'],
    );
    expect(typeof user.has_secret).toBe('boolean');
    expect(typeof user.has_attestation_key).toBe('boolean');
    expect(user.username).toMatch(/^[a-z0-9._-]+$/);
    expect(typeof user.active).toBe('boolean');
    assertTimestamp(user.created_at, 'UserView.created_at');
    // Security invariant (§ contracts README): no password material on the wire.
    expect(user).not.toHaveProperty('password_hash');
    expect(user).not.toHaveProperty('password');
  });

  it('user.dsr-export.json → UserDsrExport (GET /v1/privacy/users/{id}/export)', async () => {
    stubFetch(fixture('user.dsr-export.json'));
    const exported: UserDsrExport = await api.exportUserDsr('6d5e4f00-0000-4000-8000-000000000005');
    assertExactKeys<UserDsrExport>(
      exported,
      {
        exported_at: true,
        scope: true,
        format_version: true,
        redaction_notes: true,
        exclusions: true,
        user: true,
        ledger_event_refs: true,
      },
      'UserDsrExport',
    );
    assertTimestamp(exported.exported_at, 'UserDsrExport.exported_at');
    expect(exported.scope).toMatch(/^user:/);
    expect(exported.format_version).toBeGreaterThanOrEqual(1);
    expect(exported.redaction_notes.length).toBeGreaterThan(0);
    expect(exported.exclusions).toContain('password_hash');

    const user = assertExactKeys<UserDsrExportUser>(
      exported.user,
      {
        id: true,
        username: true,
        display_name: true,
        created_at: true,
        active: true,
        has_secret: true,
        has_attestation_key: true,
        has_recovery_phrase: true,
        role_assignments: true,
      },
      'UserDsrExport.user',
      ['attestation_key_fingerprint'],
    );
    assertTimestamp(user.created_at, 'UserDsrExport.user.created_at');
    expect(user).not.toHaveProperty('password_hash');
    expect(user).not.toHaveProperty('password');
    expect(user).not.toHaveProperty('recovery_phrase');

    expect(Array.isArray(user.role_assignments)).toBe(true);
    expect(user.role_assignments.length).toBeGreaterThan(0);
    for (const assignment of user.role_assignments) {
      const a = assertExactKeys<UserDsrRoleAssignment>(
        assignment,
        { role_id: true, scope: true, permissions: true },
        'UserDsrExport.user.role_assignments[]',
        ['role_name'],
      );
      expect(a.role_id.length).toBeGreaterThan(0);
      assertPermissionScope(a.scope, 'UserDsrExport.user.role_assignments[].scope');
      expect(Array.isArray(a.permissions)).toBe(true);
      for (const permission of a.permissions) {
        expect(permission).toMatch(/^[a-z]+(?:\.[a-z]+)+$/);
      }
    }

    expect(Array.isArray(exported.ledger_event_refs)).toBe(true);
    expect(exported.ledger_event_refs.length).toBeGreaterThan(0);
    for (const ref of exported.ledger_event_refs) {
      const event = assertExactKeys<LedgerEventView>(
        ref,
        {
          id: true,
          seq: true,
          actor: true,
          justification: true,
          timestamp: true,
          scope: true,
          kind: true,
          payload_digest: true,
          prev_hash: true,
          hash: true,
          chains: true,
          attestation: true,
        },
        'UserDsrExport.ledger_event_refs[]',
      );
      assertTimestamp(event.timestamp, 'UserDsrExport.ledger_event_refs[].timestamp');
      assertHex64(event.payload_digest, 'UserDsrExport.ledger_event_refs[].payload_digest');
      assertHex64(event.prev_hash, 'UserDsrExport.ledger_event_refs[].prev_hash');
      assertHex64(event.hash, 'UserDsrExport.ledger_event_refs[].hash');
      expect(event).not.toHaveProperty('payload');
    }
  });

  it('user.dsr-requests.json → DsrRequestView[] (GET /v1/privacy/users/{id}/dsr-requests)', async () => {
    stubFetch(fixture('user.dsr-requests.json'));
    const requests: DsrRequestView[] = await api.listUserDsrRequests(
      '6d5e4f00-0000-4000-8000-000000000005',
    );
    expect(Array.isArray(requests)).toBe(true);
    expect(requests.length).toBeGreaterThan(1);
    for (const request of requests) {
      const r = assertExactKeys<DsrRequestView>(
        request,
        {
          id: true,
          subject_user_id: true,
          request_type: true,
          status: true,
          created_at: true,
          created_by: true,
        },
        'DsrRequestView',
        [
          'completed_at',
          'completed_by',
          'outcome',
          'executed_at',
          'executed_by',
          'execution_notes',
          'affected_records',
          'retention_review',
          'legal_basis_review',
        ],
      );
      inEnum(DSR_REQUEST_TYPES, r.request_type, 'DsrRequestView.request_type');
      inEnum(DSR_REQUEST_STATUSES, r.status, 'DsrRequestView.status');
      assertTimestamp(r.created_at, 'DsrRequestView.created_at');
      expect(r.created_by.length).toBeGreaterThan(0);
      if (r.outcome !== undefined) {
        inEnum(DSR_REQUEST_OUTCOMES, r.outcome, 'DsrRequestView.outcome');
      }
      if (r.executed_at !== undefined) assertTimestamp(r.executed_at, 'DsrRequestView.executed_at');
      if (r.executed_by !== undefined) {
        expect(
          r.executed_by.length,
          'DsrRequestView.executed_by should be non-empty',
        ).toBeGreaterThan(0);
      }
      if (r.execution_notes !== undefined) {
        expect(
          r.execution_notes.length,
          'DsrRequestView.execution_notes should be non-empty',
        ).toBeGreaterThan(0);
      }
      if (r.retention_review !== undefined) {
        expect(
          r.retention_review.length,
          'DsrRequestView.retention_review should be non-empty',
        ).toBeGreaterThan(0);
      }
      if (r.legal_basis_review !== undefined) {
        expect(
          r.legal_basis_review.length,
          'DsrRequestView.legal_basis_review should be non-empty',
        ).toBeGreaterThan(0);
      }
      if (r.affected_records !== undefined) {
        expect(
          Array.isArray(r.affected_records),
          'DsrRequestView.affected_records should be an array',
        ).toBe(true);
        for (const affected of r.affected_records) {
          const a = assertExactKeys<{ collection: string; action: string; count: number }>(
            affected,
            { collection: true, action: true, count: true },
            'DsrRequestView.affected_records[]',
          );
          expect(a.collection.length, 'affected collection should be non-empty').toBeGreaterThan(0);
          expect(a.action.length, 'affected action should be non-empty').toBeGreaterThan(0);
          expect(Number.isInteger(a.count), 'affected count should be an integer').toBe(true);
          expect(a.count, 'affected count should not be negative').toBeGreaterThanOrEqual(0);
        }
      }
      if (r.status === 'completed') {
        expect(r.completed_at).toBeTruthy();
        expect(r.completed_by).toBeTruthy();
        assertTimestamp(r.completed_at as string, 'DsrRequestView.completed_at');
      } else {
        expect(r.completed_at).toBeUndefined();
        expect(r.completed_by).toBeUndefined();
      }
    }
  });

  it('privacy.processors.json → ProcessorRecordView[] (GET /v1/privacy/processors)', async () => {
    stubFetch(fixture('privacy.processors.json'));
    const processors: ProcessorRecordView[] = await api.listProcessorRecords();
    expect(Array.isArray(processors)).toBe(true);
    expect(processors.length).toBeGreaterThan(0);
    assertProcessorRecord(processors[0], 'ProcessorRecordView');
  });

  it('privacy.dpias.json → DpiaRecordView[] (GET /v1/privacy/dpias)', async () => {
    stubFetch(fixture('privacy.dpias.json'));
    const dpias: DpiaRecordView[] = await api.listDpiaRecords();
    expect(Array.isArray(dpias)).toBe(true);
    expect(dpias.length).toBeGreaterThan(0);
    assertDpiaRecord(dpias[0], 'DpiaRecordView');
  });

  it('retention.policies.json → RetentionPolicyView[] (GET /v1/privacy/retention-policies)', async () => {
    stubFetch(fixture('retention.policies.json'));
    const policies: RetentionPolicyView[] = await api.listRetentionPolicies();
    expect(Array.isArray(policies)).toBe(true);
    expect(policies.length).toBeGreaterThan(0);
    const policy = assertRetentionPolicy(policies[0], 'RetentionPolicyView');
    expect(policy.retention_period).toMatch(/^P/);
    expect(policy.active).toBe(true);
  });

  it('session.json → SessionView (GET /v1/session, populated)', async () => {
    stubFetch(fixture('session.json'));
    const session: SessionView = await api.getSession();
    // `permissions` is the first-paint RBAC embed (t64-E3) — always present (empty when
    // signed out), so it is a REQUIRED key alongside `user`.
    assertExactKeys<SessionView>(session, { user: true, permissions: true }, 'SessionView');
    expect(session.user, 'populated session carries a user').not.toBeNull();
    const user = assertExactKeys<UserView>(
      session.user,
      {
        id: true,
        username: true,
        display_name: true,
        created_at: true,
        active: true,
        has_secret: true,
        has_attestation_key: true,
        has_recovery_phrase: true,
      },
      'SessionView.user',
      ['attestation_key_fingerprint'],
    );
    expect(user).not.toHaveProperty('password_hash');

    // The embedded effective grants (t64-E3, FROZEN for E5): each a `(permission, scope,
    // source)` triple; `scope` is a `kind`-tagged union; `source` ∈ {role, delegation}.
    expect(Array.isArray(session.permissions), 'SessionView.permissions is an array').toBe(true);
    for (const grant of session.permissions) {
      const g = assertExactKeys<PermissionGrant>(
        grant,
        { permission: true, scope: true, source: true },
        'SessionView.permissions[]',
      );
      expect(typeof g.permission, 'grant.permission is a string').toBe('string');
      expect(g.permission.length, 'grant.permission is non-empty').toBeGreaterThan(0);
      inEnum(PERMISSION_SOURCES, g.source, 'SessionView.permissions[].source');
      // `scope` is the `kind`-tagged union: global carries no id; entity/book carry a uuid.
      inEnum(['global', 'entity', 'book'], g.scope.kind, 'SessionView.permissions[].scope.kind');
      if (g.scope.kind === 'global') {
        assertExactKeys<{ kind: 'global' }>(g.scope, { kind: true }, 'scope(global)');
      } else {
        const scoped = assertExactKeys<{ kind: string; id: string }>(
          g.scope,
          { kind: true, id: true },
          `scope(${g.scope.kind})`,
        );
        expect(typeof scoped.id, 'scoped grant carries an id').toBe('string');
      }
    }
  });

  it('session.roster.json → SessionRoster (GET /v1/session/roster, unauth)', async () => {
    stubFetch(fixture('session.roster.json'));
    const roster: SessionRoster = await api.getSessionRoster();
    assertExactKeys<SessionRoster>(
      roster,
      { onboarding_required: true, users: true },
      'SessionRoster',
    );
    expect(typeof roster.onboarding_required).toBe('boolean');
    expect(Array.isArray(roster.users)).toBe(true);
    for (const u of roster.users) {
      // The roster user object is deliberately minimal — EXACTLY these four keys, no
      // secret material / fingerprint / created_at / active (t45-e1 freeze).
      const ru = assertExactKeys<RosterUser>(
        u,
        { id: true, username: true, display_name: true, has_secret: true },
        'SessionRoster.users[]',
      );
      expect(ru.username).toMatch(/^[a-z0-9._-]+$/);
      expect(typeof ru.has_secret).toBe('boolean');
      expect(u).not.toHaveProperty('active');
      expect(u).not.toHaveProperty('has_attestation_key');
      expect(u).not.toHaveProperty('attestation_key_fingerprint');
      expect(u).not.toHaveProperty('created_at');
    }
  });

  it('session.password-policy.json → PasswordPolicyView (GET /v1/session/password-policy)', async () => {
    stubFetch(fixture('session.password-policy.json'));
    const policy: PasswordPolicyView = await api.getPasswordPolicy();
    assertExactKeys<PasswordPolicyView>(
      policy,
      {
        min_length: true,
        require_lowercase: true,
        require_uppercase: true,
        require_digit: true,
        require_special: true,
        forbid_username: true,
        forbid_common: true,
        max_identical_run: true,
        max_sequential_run: true,
        allow_weak_passwords: true,
        rules: true,
      },
      'PasswordPolicyView',
    );
    expect(policy.min_length).toBeGreaterThanOrEqual(10);
    expect(typeof policy.require_lowercase).toBe('boolean');
    expect(typeof policy.require_uppercase).toBe('boolean');
    expect(typeof policy.require_digit).toBe('boolean');
    expect(typeof policy.require_special).toBe('boolean');
    expect(typeof policy.forbid_username).toBe('boolean');
    expect(typeof policy.forbid_common).toBe('boolean');
    expect(policy.max_identical_run).toBeGreaterThanOrEqual(2);
    expect(policy.max_sequential_run).toBeGreaterThanOrEqual(2);
    expect(typeof policy.allow_weak_passwords).toBe('boolean');
    expect(Array.isArray(policy.rules)).toBe(true);
    expect(policy.rules.length).toBe(PASSWORD_POLICY_RULE_CODES.length);
    for (const rule of policy.rules) {
      const r = assertExactKeys<PasswordRuleView>(
        rule,
        { code: true, requirement: true },
        'PasswordPolicyView.rules[]',
      );
      inEnum(PASSWORD_POLICY_RULE_CODES, r.code, 'PasswordPolicyView.rules[].code');
      expect(r.requirement.length).toBeGreaterThan(0);
    }
  });

  it('api-key.list.json → ApiKeyView[] (GET /v1/api-keys)', async () => {
    stubFetch(fixture('api-key.list.json'));
    const keys: ApiKeyView[] = await api.listApiKeys();
    expect(Array.isArray(keys), 'API-key list should be an array').toBe(true);
    expect(keys.length).toBeGreaterThan(0);
    assertApiKeyView(keys[0], 'ApiKeyView');
  });

  it('api-key.create.json → ApiKeyCreated (POST /v1/api-keys)', async () => {
    stubFetch(fixture('api-key.create.json'), 201);
    const created: ApiKeyCreated = await api.createApiKey({
      name: 'Ledger export',
      grant: {
        kind: 'permissions',
        permissions: ['ledger.read'],
        scope: { kind: 'global' },
      },
      expires_at: '2026-12-31T23:59:59Z',
      rate_limit: { rpm: 120, burst: 10 },
    });
    assertApiKeyCreated(created, 'ApiKeyCreated');
  });

  it('api-key.revoke.json → ApiKeyView (DELETE /v1/api-keys/{id})', async () => {
    stubFetch(fixture('api-key.revoke.json'));
    const revoked: ApiKeyView = await api.revokeApiKey('7a6b5c40-0000-4000-8000-000000000065');
    assertApiKeyView(revoked, 'ApiKeyRevoked');
    expect(revoked.revoked).toBe(true);
    expect(revoked.active).toBe(false);
  });

  it('api-key.rotate.json → ApiKeyCreated (POST /v1/api-keys/{id}/rotate)', async () => {
    stubFetch(fixture('api-key.rotate.json'));
    const rotated: ApiKeyCreated = await api.rotateApiKey('7a6b5c40-0000-4000-8000-000000000065');
    assertApiKeyCreated(rotated, 'ApiKeyRotated');
    expect(rotated.revoked).toBe(false);
    expect(rotated.active).toBe(true);
  });
});

// --- Cross-cutting guards ------------------------------------------------------

describe('contract fixtures — cross-cutting guarantees', () => {
  it('every fixture is real and non-empty (the wire bytes a client must parse)', () => {
    const names = Object.keys(rawFixtures).map((p) => p.split('/').pop());
    const markdownNames = Object.keys(rawMarkdownFixtures).map((p) => p.split('/').pop());
    // The canonical fixtures the README inventories.
    for (const expected of [
      'entity.json',
      'book.json',
      'act.sealed.json',
      'ledger.events.json',
      'dashboard.json',
      'settings.json',
      'registry.extract.json',
      'cae.entry.json',
      'cae.catalog.json',
      'cae.updates.json',
      'cae.sections.json',
      'cae.children.json',
      'tsl.catalog.json',
      'law.manifest.json',
      'law.corpus.json',
      'law.diploma.json',
      'law.article.json',
      'law.search.json',
      'backup.manifest.json',
      'user.json',
      'session.json',
      'session.roster.json',
      'session.password-policy.json',
      'user.dsr-export.json',
      'user.dsr-requests.json',
      'privacy.processors.json',
      'privacy.dpias.json',
      'retention.policies.json',
      'paper-book.import.json',
      'api-key.list.json',
      'api-key.create.json',
      'api-key.revoke.json',
      'api-key.rotate.json',
      'tsa.status.json',
    ]) {
      expect(names, `contracts/ should include ${expected}`).toContain(expected);
    }
    expect(markdownNames, 'contracts/ should include act.working-copy.md').toContain(
      'act.working-copy.md',
    );
    for (const [path, text] of Object.entries(rawFixtures)) {
      expect(text.length, `${path} should be non-empty`).toBeGreaterThan(0);
      expect(() => JSON.parse(text), `${path} should be valid JSON`).not.toThrow();
    }
    for (const [path, text] of Object.entries(rawMarkdownFixtures)) {
      expect(text.length, `${path} should be non-empty`).toBeGreaterThan(0);
    }
    expect(markdownFixture('act.working-copy.md')).toContain('WORKING COPY');
  });

  it('no fixture leaks a full código de acesso or password material', () => {
    for (const [path, text] of Object.entries({ ...rawFixtures, ...rawMarkdownFixtures })) {
      expect(text, `${path} must not carry a password_hash field`).not.toMatch(
        /"password_hash"\s*:/,
      );
      expect(text, `${path} must not carry an API-key verifier`).not.toContain('key_hash');
      // The only access code representation allowed on the wire is the mask.
      expect(text, `${path} must not carry a raw access_code field`).not.toMatch(
        /"access_code"\s*:/,
      );
    }
  });

  it('a stale-server HTML shell for a contract route is a typed error, not a parse crash', async () => {
    // The regression the whole suite exists to keep caught: the SPA index.html served
    // where JSON is due must surface as a clear ApiError, never a raw JSON.parse throw.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('<!doctype html><title>Chancela</title>', {
          status: 200,
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        }),
      ),
    );
    const err = await api.getEntity('any').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).message).toContain('HTML em vez de JSON');
  });
});
