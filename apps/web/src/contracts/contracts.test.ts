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
  DATA_PAYLOAD_ESTIMATE_METHODS,
  DATA_PERSISTENCE_MODES,
  DATA_USAGE_BASES,
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
  PLATFORM_EMITTED_LOG_LEVELS,
  PERMISSION_SOURCES,
  PLATFORM_LOG_LEVELS,
  PLATFORM_SERVICE_ACTIONS,
  PRIVACY_ADVISORY_REVIEW_STATUSES,
  PRIVACY_RECORD_STATUSES,
  PRIVACY_RISK_LEVELS,
  RETENTION_DISPOSAL_ACTIONS,
  RETENTION_CANDIDATE_DISPOSITIONS,
  RETENTION_EVIDENCE_STATES,
  RETENTION_EXECUTION_DECISION_STATES,
  RETENTION_EXECUTION_STATUSES,
  RETENTION_POLICY_STATUSES,
  RETENTION_REVIEW_CLOSURE_DECISIONS,
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
  type ActManualSignatureOriginalReference,
  type ActMesa,
  type ActSealMetadata,
  type ActView,
  type AiSettings,
  type AppearanceSettings,
  type BackupFile,
  type BackupManifest,
  type BackupRecoveryDrillIsolatedRestoreVerification,
  type BackupRecoveryDrillList,
  type BackupRecoveryDrillManifestEvidence,
  type BackupRecoveryDrillReceipt,
  type BackupRecoveryFreshnessReview,
  type BackupRecoveryPolicySettings,
  type BookView,
  type BreachPlaybookEvidenceReceipt,
  type BreachPlaybookView,
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
  type DataManagementSettings,
  type DataDirStatus,
  type DataPayloadStats,
  type DataPermissionCheck,
  type DataPermissionStatus,
  type DataPersistenceStatus,
  type DataStatusResponse,
  type DataUsageConcern,
  type DataUsageStatus,
  type DocumentSettings,
  type DpiaAdvisoryReviewSummary,
  type DpiaEvidenceReceipt,
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
  type PaperBookCanonicalConversionPreflight,
  type PaperBookCanonicalConversionPreflightBlocker,
  type PaperBookCanonicalConversionPreflightEvidence,
  type PaperBookImportClassification,
  type PaperBookImportDateSpan,
  type PaperBookImportFinding,
  type PaperBookImportIdentity,
  type PaperBookContinuationRecommendation,
  type PaperBookLinkingEvidence,
  PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES,
  type PaperBookOcrConversionDossierView,
  type PaperBookOcrConversionExecutionArtifactView,
  type PaperBookOcrDraftCanonicalDraftResponse,
  type PaperBookOcrDraftPageSpanView,
  type PaperBookOcrDraftView,
  type PaperBookOcrEngineView,
  type PaperBookOcrRunView,
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
  type PlatformLogEntry,
  type PlatformLogRetentionMetadata,
  type PlatformLogsResponse,
  type PlatformLoggingSettings,
  type PlatformServiceControlSettings,
  type PlatformServiceLastAction,
  type PlatformServiceStatus,
  type PlatformServicesResponse,
  type PlatformSettings,
  type PrivacyAdvisoryReviewSummary,
  type ProcessorRecordView,
  type RegistryAnnotationView,
  type RegistryEventView,
  type RegistryExtractView,
  type RegistryOfficerView,
  type RegistryProvenanceView,
  type RegistryAutoUpdateSettings,
  type RetainedExportCleanupSettings,
  type RosterUser,
  type SessionRoster,
  type SessionView,
  type Settings,
  type RetentionDueCandidate,
  type RetentionDueCandidateFinding,
  type RetentionDueCandidatePriorExecution,
  type RetentionDueCandidatesReport,
  type RetentionDueCandidatesSuppressionSummary,
  type RetentionCandidateResolutionRecord,
  type RetentionCandidateResolutionSnapshot,
  type RetentionCandidateResolutionSummary,
  type RetentionPolicyView,
  type RetentionExecutionApproval,
  type RetentionExecutionBlockerMetadata,
  type RetentionExecutionRecord,
  type RetentionExecutionRequestedPolicy,
  type RetentionExecutionResult,
  type RetentionExecutionTargetEvidence,
  type RetentionLegalHoldBlocker,
  type RetentionMatchedRecordsSummary,
  type RetentionOperatorEvidence,
  type RetentionOperatorWorkflow,
  type RetentionReviewClosureEvidence,
  type RetentionRequiredApproval,
  type RetentionWorkflowBlocker,
  type TransferControlEvidenceReceipt,
  type TransferControlView,
  type SigningCmdSettings,
  type SigningProviderMetadata,
  type SigningSettings,
  type TrustRefreshCadence,
  type TrustRefreshSettings,
  type TslCatalogView,
  type TslIdentitySummaryView,
  type TslProviderAnalysisView,
  type TslProviderView,
  type TslRefreshStatusView,
  type TslServiceStatusView,
  type TslServiceSummaryView,
  type TslSourceSettings,
  type TslSourceView,
  type TslSummaryView,
  type TslValidationView,
  type TsaAcceptedHashView,
  type TsaCatalogView,
  type TsaPolicyAnalysisView,
  type TsaProbeView,
  type TsaProviderSettings,
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
  type WorkflowReminderSettings,
  type WorkflowReminderSourceSettings,
  type WorkflowSettings,
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

function assertDataPermissionCheck(obj: unknown, label: string): DataPermissionCheck {
  const check = assertExactKeys<DataPermissionCheck>(
    obj,
    { ok: true, checked: true, message: true },
    label,
  );
  expect(typeof check.ok, `${label}.ok should be boolean`).toBe('boolean');
  expect(typeof check.checked, `${label}.checked should be boolean`).toBe('boolean');
  expect(typeof check.message, `${label}.message should be string`).toBe('string');
  expect(check.message.length, `${label}.message should be non-empty`).toBeGreaterThan(0);
  return check;
}

function assertDataUsageConcern(obj: unknown, label: string): DataUsageConcern {
  const concern = assertExactKeys<DataUsageConcern>(
    obj,
    {
      id: true,
      label: true,
      bytes: true,
      basis: true,
      exact: true,
      file_count: true,
      directory_count: true,
      relative_roots: true,
    },
    label,
    ['kind', 'row_count', 'payload_stats'],
  );
  expect(concern.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  if (concern.kind !== undefined) {
    expect(concern.kind.length, `${label}.kind should be non-empty`).toBeGreaterThan(0);
  }
  expect(concern.label.length, `${label}.label should be non-empty`).toBeGreaterThan(0);
  expect(Number.isInteger(concern.bytes), `${label}.bytes should be an integer`).toBe(true);
  expect(concern.bytes, `${label}.bytes should be non-negative`).toBeGreaterThanOrEqual(0);
  inEnum(DATA_USAGE_BASES, concern.basis, `${label}.basis`);
  expect(typeof concern.exact, `${label}.exact should be boolean`).toBe('boolean');
  expect(Number.isInteger(concern.file_count), `${label}.file_count should be integer`).toBe(true);
  expect(
    Number.isInteger(concern.directory_count),
    `${label}.directory_count should be integer`,
  ).toBe(true);
  if (concern.row_count !== undefined) {
    expect(Number.isInteger(concern.row_count), `${label}.row_count should be integer`).toBe(true);
  }
  if (concern.payload_stats !== undefined) {
    assertDataPayloadStats(concern.payload_stats, `${label}.payload_stats`);
  }
  expect(Array.isArray(concern.relative_roots), `${label}.relative_roots should be array`).toBe(
    true,
  );
  for (const root of concern.relative_roots) {
    expect(root.length, `${label}.relative_roots[] should be non-empty`).toBeGreaterThan(0);
  }
  return concern;
}

function assertDataPayloadStats(obj: unknown, label: string): DataPayloadStats {
  const stats = assertExactKeys<DataPayloadStats>(
    obj,
    {
      table_name: true,
      estimated_payload_bytes: true,
      row_count: true,
      average_bytes_per_row: true,
      estimate_method: true,
      estimate_basis: true,
    },
    label,
  );
  expect(stats.table_name.length, `${label}.table_name should be non-empty`).toBeGreaterThan(0);
  expect(
    Number.isInteger(stats.estimated_payload_bytes),
    `${label}.estimated_payload_bytes should be integer`,
  ).toBe(true);
  expect(
    stats.estimated_payload_bytes,
    `${label}.estimated_payload_bytes should be non-negative`,
  ).toBeGreaterThanOrEqual(0);
  expect(Number.isInteger(stats.row_count), `${label}.row_count should be integer`).toBe(true);
  expect(stats.row_count, `${label}.row_count should be non-negative`).toBeGreaterThanOrEqual(0);
  if (stats.average_bytes_per_row !== null) {
    expect(
      Number.isInteger(stats.average_bytes_per_row),
      `${label}.average_bytes_per_row should be integer or null`,
    ).toBe(true);
    expect(
      stats.average_bytes_per_row,
      `${label}.average_bytes_per_row should be non-negative`,
    ).toBeGreaterThanOrEqual(0);
  }
  inEnum(
    DATA_PAYLOAD_ESTIMATE_METHODS,
    stats.estimate_method,
    `${label}.estimate_method`,
  );
  inEnum(DATA_USAGE_BASES, stats.estimate_basis, `${label}.estimate_basis`);
  return stats;
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
      evidence_receipts: true,
      advisory_review: true,
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
  expect(Array.isArray(record.evidence_receipts), `${label}.evidence_receipts`).toBe(true);
  expect(record.evidence_receipts.length, `${label}.evidence_receipts`).toBeGreaterThan(0);
  assertDpiaEvidenceReceipt(record.evidence_receipts[0], `${label}.evidence_receipts[]`);
  assertDpiaAdvisoryReview(record.advisory_review, `${label}.advisory_review`);
  return record;
}

function assertDpiaEvidenceReceipt(obj: unknown, label: string): DpiaEvidenceReceipt {
  const receipt = assertExactKeys<DpiaEvidenceReceipt>(
    obj,
    {
      id: true,
      evidence_type: true,
      recorded_at: true,
      recorded_by: true,
      authority_filing_completed: true,
      legal_review_accepted: true,
      legal_certification_completed: true,
      external_delivery_completed: true,
      dpia_completed: true,
      compliance_certification_completed: true,
    },
    label,
    ['occurred_at', 'notes'],
  );
  expect(['review', 'drill'], `${label}.evidence_type`).toContain(receipt.evidence_type);
  assertTimestamp(receipt.recorded_at, `${label}.recorded_at`);
  if (receipt.occurred_at) assertTimestamp(receipt.occurred_at, `${label}.occurred_at`);
  expect(receipt.authority_filing_completed, `${label}.authority_filing_completed`).toBe(false);
  expect(receipt.legal_review_accepted, `${label}.legal_review_accepted`).toBe(false);
  expect(receipt.legal_certification_completed, `${label}.legal_certification_completed`).toBe(
    false,
  );
  expect(receipt.external_delivery_completed, `${label}.external_delivery_completed`).toBe(false);
  expect(receipt.dpia_completed, `${label}.dpia_completed`).toBe(false);
  expect(
    receipt.compliance_certification_completed,
    `${label}.compliance_certification_completed`,
  ).toBe(false);
  return receipt;
}

function assertBreachEvidenceReceipt(obj: unknown, label: string): BreachPlaybookEvidenceReceipt {
  const receipt = assertExactKeys<BreachPlaybookEvidenceReceipt>(
    obj,
    {
      id: true,
      evidence_type: true,
      recorded_at: true,
      recorded_by: true,
      authority_notified: true,
      subjects_notified: true,
    },
    label,
    ['occurred_at', 'notes'],
  );
  expect(['review', 'drill'], `${label}.evidence_type`).toContain(receipt.evidence_type);
  assertTimestamp(receipt.recorded_at, `${label}.recorded_at`);
  if (receipt.occurred_at) assertTimestamp(receipt.occurred_at, `${label}.occurred_at`);
  expect(receipt.authority_notified, `${label}.authority_notified`).toBe(false);
  expect(receipt.subjects_notified, `${label}.subjects_notified`).toBe(false);
  return receipt;
}

function assertPrivacyAdvisoryReview(
  obj: unknown,
  label: string,
  extraKeys: readonly string[] = [],
): PrivacyAdvisoryReviewSummary {
  const summary = assertExactKeys<PrivacyAdvisoryReviewSummary>(
    obj,
    {
      status: true,
      review_interval_days: true,
      receipt_count: true,
      review_receipt_count: true,
      drill_receipt_count: true,
      local_advisory_only: true,
      authority_notification_claimed: true,
      subject_notification_claimed: true,
      transfer_approval_claimed: true,
      transfer_execution_claimed: true,
      external_delivery_configured: true,
      legal_completion_claimed: true,
    },
    label,
    [
      'last_reviewed_at',
      'last_drill_at',
      'next_review_due_at',
      'days_until_due',
      ...extraKeys,
    ] as readonly OptionalKeys<PrivacyAdvisoryReviewSummary>[],
  );
  inEnum(PRIVACY_ADVISORY_REVIEW_STATUSES, summary.status, `${label}.status`);
  expect(summary.review_interval_days, `${label}.review_interval_days`).toBeGreaterThan(0);
  expect(summary.receipt_count, `${label}.receipt_count`).toBeGreaterThanOrEqual(0);
  expect(summary.review_receipt_count, `${label}.review_receipt_count`).toBeGreaterThanOrEqual(0);
  expect(summary.drill_receipt_count, `${label}.drill_receipt_count`).toBeGreaterThanOrEqual(0);
  if (summary.last_reviewed_at)
    assertTimestamp(summary.last_reviewed_at, `${label}.last_reviewed_at`);
  if (summary.last_drill_at) assertTimestamp(summary.last_drill_at, `${label}.last_drill_at`);
  if (summary.next_review_due_at)
    assertIsoDate(summary.next_review_due_at, `${label}.next_review_due_at`);
  if (summary.days_until_due !== undefined) {
    expect(Number.isInteger(summary.days_until_due), `${label}.days_until_due`).toBe(true);
  }
  expect(summary.local_advisory_only, `${label}.local_advisory_only`).toBe(true);
  expect(summary.authority_notification_claimed, `${label}.authority_notification_claimed`).toBe(
    false,
  );
  expect(summary.subject_notification_claimed, `${label}.subject_notification_claimed`).toBe(false);
  expect(summary.transfer_approval_claimed, `${label}.transfer_approval_claimed`).toBe(false);
  expect(summary.transfer_execution_claimed, `${label}.transfer_execution_claimed`).toBe(false);
  expect(summary.external_delivery_configured, `${label}.external_delivery_configured`).toBe(false);
  expect(summary.legal_completion_claimed, `${label}.legal_completion_claimed`).toBe(false);
  return summary;
}

function assertDpiaAdvisoryReview(obj: unknown, label: string): DpiaAdvisoryReviewSummary {
  const summary = assertPrivacyAdvisoryReview(obj, label, [
    'authority_filing_claimed',
    'legal_acceptance_claimed',
    'legal_certification_claimed',
    'external_delivery_claimed',
    'completion_claimed',
    'compliance_certification_claimed',
  ]) as DpiaAdvisoryReviewSummary;
  const dpiaSummary = assertExactKeys<DpiaAdvisoryReviewSummary>(
    obj,
    {
      status: true,
      review_interval_days: true,
      receipt_count: true,
      review_receipt_count: true,
      drill_receipt_count: true,
      local_advisory_only: true,
      authority_notification_claimed: true,
      subject_notification_claimed: true,
      transfer_approval_claimed: true,
      transfer_execution_claimed: true,
      external_delivery_configured: true,
      legal_completion_claimed: true,
      authority_filing_claimed: true,
      legal_acceptance_claimed: true,
      legal_certification_claimed: true,
      external_delivery_claimed: true,
      completion_claimed: true,
      compliance_certification_claimed: true,
    },
    label,
    ['last_reviewed_at', 'last_drill_at', 'next_review_due_at', 'days_until_due'],
  );
  expect(dpiaSummary.authority_filing_claimed, `${label}.authority_filing_claimed`).toBe(false);
  expect(dpiaSummary.legal_acceptance_claimed, `${label}.legal_acceptance_claimed`).toBe(false);
  expect(dpiaSummary.legal_certification_claimed, `${label}.legal_certification_claimed`).toBe(
    false,
  );
  expect(dpiaSummary.external_delivery_claimed, `${label}.external_delivery_claimed`).toBe(false);
  expect(dpiaSummary.completion_claimed, `${label}.completion_claimed`).toBe(false);
  expect(
    dpiaSummary.compliance_certification_claimed,
    `${label}.compliance_certification_claimed`,
  ).toBe(false);
  return summary;
}

function assertBreachPlaybook(obj: unknown, label: string): BreachPlaybookView {
  const record = assertExactKeys<BreachPlaybookView>(
    obj,
    {
      id: true,
      title: true,
      scope: true,
      detection_channels: true,
      containment_steps: true,
      notification_roles: true,
      risk_level: true,
      status: true,
      evidence_receipts: true,
      advisory_review: true,
      created_at: true,
      created_by: true,
      updated_at: true,
      updated_by: true,
    },
    label,
    ['authority_notification_window', 'subject_notification_guidance', 'review_notes'],
  );
  expect(record.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(record.title.length, `${label}.title should be non-empty`).toBeGreaterThan(0);
  expect(record.scope.length, `${label}.scope should be non-empty`).toBeGreaterThan(0);
  expect(Array.isArray(record.detection_channels), `${label}.detection_channels`).toBe(true);
  expect(record.detection_channels.length, `${label}.detection_channels`).toBeGreaterThan(0);
  expect(Array.isArray(record.containment_steps), `${label}.containment_steps`).toBe(true);
  expect(record.containment_steps.length, `${label}.containment_steps`).toBeGreaterThan(0);
  expect(Array.isArray(record.notification_roles), `${label}.notification_roles`).toBe(true);
  inEnum(PRIVACY_RISK_LEVELS, record.risk_level, `${label}.risk_level`);
  inEnum(PRIVACY_RECORD_STATUSES, record.status, `${label}.status`);
  expect(Array.isArray(record.evidence_receipts), `${label}.evidence_receipts`).toBe(true);
  expect(record.evidence_receipts.length, `${label}.evidence_receipts`).toBeGreaterThan(0);
  assertBreachEvidenceReceipt(record.evidence_receipts[0], `${label}.evidence_receipts[]`);
  assertPrivacyAdvisoryReview(record.advisory_review, `${label}.advisory_review`);
  assertTimestamp(record.created_at, `${label}.created_at`);
  assertTimestamp(record.updated_at, `${label}.updated_at`);
  return record;
}

function assertTransferEvidenceReceipt(
  obj: unknown,
  label: string,
): TransferControlEvidenceReceipt {
  const receipt = assertExactKeys<TransferControlEvidenceReceipt>(
    obj,
    {
      id: true,
      recorded_at: true,
      recorded_by: true,
      transfer_approved: true,
      data_transfer_executed: true,
    },
    label,
    ['reviewed_at', 'notes'],
  );
  assertTimestamp(receipt.recorded_at, `${label}.recorded_at`);
  if (receipt.reviewed_at) assertTimestamp(receipt.reviewed_at, `${label}.reviewed_at`);
  expect(receipt.transfer_approved, `${label}.transfer_approved`).toBe(false);
  expect(receipt.data_transfer_executed, `${label}.data_transfer_executed`).toBe(false);
  return receipt;
}

function assertTransferControl(obj: unknown, label: string): TransferControlView {
  const record = assertExactKeys<TransferControlView>(
    obj,
    {
      id: true,
      name: true,
      purpose: true,
      legal_basis: true,
      data_categories: true,
      recipient: true,
      destination_country: true,
      transfer_mechanism: true,
      safeguards: true,
      risk_level: true,
      status: true,
      evidence_receipts: true,
      advisory_review: true,
      created_at: true,
      created_by: true,
      updated_at: true,
      updated_by: true,
    },
    label,
    ['review_notes'],
  );
  expect(record.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(record.name.length, `${label}.name should be non-empty`).toBeGreaterThan(0);
  expect(record.recipient.length, `${label}.recipient should be non-empty`).toBeGreaterThan(0);
  expect(record.destination_country.length, `${label}.destination_country`).toBeGreaterThan(0);
  expect(record.transfer_mechanism.length, `${label}.transfer_mechanism`).toBeGreaterThan(0);
  expect(Array.isArray(record.data_categories), `${label}.data_categories`).toBe(true);
  expect(record.data_categories.length, `${label}.data_categories`).toBeGreaterThan(0);
  expect(Array.isArray(record.safeguards), `${label}.safeguards`).toBe(true);
  expect(record.safeguards.length, `${label}.safeguards`).toBeGreaterThan(0);
  inEnum(PRIVACY_RISK_LEVELS, record.risk_level, `${label}.risk_level`);
  inEnum(PRIVACY_RECORD_STATUSES, record.status, `${label}.status`);
  expect(Array.isArray(record.evidence_receipts), `${label}.evidence_receipts`).toBe(true);
  expect(record.evidence_receipts.length, `${label}.evidence_receipts`).toBeGreaterThan(0);
  assertTransferEvidenceReceipt(record.evidence_receipts[0], `${label}.evidence_receipts[]`);
  assertPrivacyAdvisoryReview(record.advisory_review, `${label}.advisory_review`);
  assertTimestamp(record.created_at, `${label}.created_at`);
  assertTimestamp(record.updated_at, `${label}.updated_at`);
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

function assertRetentionDueCandidateFinding(
  obj: unknown,
  label: string,
): RetentionDueCandidateFinding {
  if (typeof obj === 'string') {
    expect(obj.length, `${label} should be non-empty`).toBeGreaterThan(0);
    return obj;
  }
  const finding = assertExactKeys<Exclude<RetentionDueCandidateFinding, string>>(obj, {}, label, [
    'code',
    'message',
    'severity',
  ]);
  expect(
    Boolean(finding.code || finding.message || finding.severity),
    `${label} should include at least one field`,
  ).toBe(true);
  return finding;
}

const RETENTION_DUE_CANDIDATE_PRIOR_NEXT_STEPS = {
  bounded_archive_recorded:
    'Prior bounded archive evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.',
  bounded_no_action_recorded:
    'Prior bounded no-action evidence is available for review; this due-candidate scan is read-only and requires separate governance approval before any operational action.',
} as const;

const RETENTION_DUE_CANDIDATE_PRIOR_UNSAFE_NEXT_STEP_TERMS = [
  'deletion',
  'anonymization',
  'gdpr',
  'legal disposal',
  'legal completion',
  'legally complete',
  'dispatch',
  'full erasure',
  'completed',
  'resolved',
] as const;

const RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE =
  'Due candidates with prior safe bounded archive/no-action evidence are omitted from the active candidate list; execution history remains queryable for review.';

const RETENTION_REVIEW_CLOSURE_OVERCLAIM_TERMS = [
  'destructive disposal completed',
  'full erasure completed',
  'legal hold mutated',
  'retention policy mutated',
  'legally complete',
  'legal disposal complete',
] as const;

function assertRetentionDueCandidatePriorExecution(
  obj: unknown,
  label: string,
): RetentionDueCandidatePriorExecution {
  const priorExecution = assertExactKeys<RetentionDueCandidatePriorExecution>(
    obj,
    {
      execution_id: true,
      execution_status: true,
      outcome: true,
      evidence_state: true,
      evidence_next_step: true,
      requested_at: true,
      bounded_executor: true,
      targets_acted_count: true,
      destructive_disposal_completed: true,
      full_erasure_completed: true,
      next_step: true,
    },
    label,
    ['executed_at'],
  );
  expect(
    priorExecution.execution_id.length,
    `${label}.execution_id should be non-empty`,
  ).toBeGreaterThan(0);
  expect(priorExecution.execution_status, `${label}.status`).toBe('executed');
  inEnum(
    ['bounded_archive_recorded', 'bounded_no_action_recorded'],
    priorExecution.outcome,
    `${label}.outcome`,
  );
  expect(priorExecution.evidence_state, `${label}.evidence_state tracks outcome`).toBe(
    priorExecution.outcome,
  );
  expect(priorExecution.evidence_next_step, `${label}.evidence_next_step should be canonical`).toBe(
    RETENTION_DUE_CANDIDATE_PRIOR_NEXT_STEPS[
      priorExecution.outcome as keyof typeof RETENTION_DUE_CANDIDATE_PRIOR_NEXT_STEPS
    ],
  );
  assertTimestamp(priorExecution.requested_at, `${label}.requested_at`);
  if (priorExecution.executed_at !== undefined) {
    assertTimestamp(priorExecution.executed_at, `${label}.executed_at`);
  }
  expect(priorExecution.bounded_executor, `${label}.bounded_executor`).toBe(true);
  expect(typeof priorExecution.targets_acted_count, `${label}.targets_acted_count`).toBe('number');
  expect(priorExecution.destructive_disposal_completed, `${label}.destructive flag`).toBe(false);
  expect(priorExecution.full_erasure_completed, `${label}.erasure flag`).toBe(false);
  expect(priorExecution.next_step, `${label}.next_step should be canonical`).toBe(
    RETENTION_DUE_CANDIDATE_PRIOR_NEXT_STEPS[
      priorExecution.outcome as keyof typeof RETENTION_DUE_CANDIDATE_PRIOR_NEXT_STEPS
    ],
  );
  const normalizedNextStep = priorExecution.next_step.toLowerCase();
  RETENTION_DUE_CANDIDATE_PRIOR_UNSAFE_NEXT_STEP_TERMS.forEach((term) => {
    expect(normalizedNextStep, `${label}.next_step should not include ${term}`).not.toContain(term);
  });
  return priorExecution;
}

function assertRetentionCandidateResolutionSummary(
  obj: unknown,
  label: string,
): RetentionCandidateResolutionSummary {
  const summary = assertExactKeys<RetentionCandidateResolutionSummary>(
    obj,
    {
      id: true,
      candidate_fingerprint: true,
      recorded_at: true,
      recorded_by: true,
      disposition: true,
      evidence_count: true,
      evidence_only: true,
      destructive_disposal_completed: true,
      disposal_completed: true,
      full_erasure_completed: true,
      erasure_completed: true,
      legal_hold_mutated: true,
      legal_hold_resolved: true,
      retention_policy_mutated: true,
      retention_policy_changed: true,
      legal_completion_claimed: true,
      legal_disposal_completed: true,
      next_step: true,
    },
    label,
    ['note'],
  );
  expect(summary.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(summary.candidate_fingerprint, `${label}.candidate_fingerprint`).toMatch(/^[0-9a-f]{64}$/);
  assertTimestamp(summary.recorded_at, `${label}.recorded_at`);
  expect(summary.recorded_by.length, `${label}.recorded_by`).toBeGreaterThan(0);
  inEnum(RETENTION_CANDIDATE_DISPOSITIONS, summary.disposition, `${label}.disposition`);
  expect(Number.isInteger(summary.evidence_count), `${label}.evidence_count`).toBe(true);
  expect(summary.evidence_only, `${label}.evidence_only`).toBe(true);
  expect(summary.destructive_disposal_completed, `${label}.destructive flag`).toBe(false);
  expect(summary.disposal_completed, `${label}.disposal flag`).toBe(false);
  expect(summary.full_erasure_completed, `${label}.erasure flag`).toBe(false);
  expect(summary.erasure_completed, `${label}.erasure flag`).toBe(false);
  expect(summary.legal_hold_mutated, `${label}.legal hold flag`).toBe(false);
  expect(summary.legal_hold_resolved, `${label}.legal hold resolution flag`).toBe(false);
  expect(summary.retention_policy_mutated, `${label}.policy flag`).toBe(false);
  expect(summary.retention_policy_changed, `${label}.policy change flag`).toBe(false);
  expect(summary.legal_completion_claimed, `${label}.legal completion flag`).toBe(false);
  expect(summary.legal_disposal_completed, `${label}.legal disposal flag`).toBe(false);
  expect(summary.next_step.length, `${label}.next_step`).toBeGreaterThan(0);
  if (summary.note !== undefined) {
    expect(summary.note.length, `${label}.note`).toBeGreaterThan(0);
  }
  return summary;
}

function assertRetentionDueCandidate(obj: unknown, label: string): RetentionDueCandidate {
  const candidate = assertExactKeys<RetentionDueCandidate>(
    obj,
    {
      candidate_id: true,
      candidate_fingerprint: true,
      scope: true,
      category: true,
      record_id: true,
      book_id: true,
      entity_id: true,
      closing_date: true,
      due_date: true,
      overdue: true,
      policy_id: true,
      policy_name: true,
      schedule_id: true,
      retention_period: true,
      disposal_action: true,
      destructive_action: true,
      legal_hold_blockers: true,
      required_approvals: true,
      blockers: true,
      findings: true,
      outcome: true,
      status: true,
      candidate_evidence_state: true,
      evidence_next_step: true,
      would_execute: true,
      destructive_disposal_completed: true,
      full_erasure_completed: true,
      candidate_resolution_record_count: true,
      next_step: true,
    },
    label,
    ['prior_execution', 'latest_resolution'],
  );
  expect(
    candidate.candidate_id.length,
    `${label}.candidate_id should be non-empty`,
  ).toBeGreaterThan(0);
  expect(candidate.candidate_fingerprint, `${label}.candidate_fingerprint`).toMatch(
    /^[0-9a-f]{64}$/,
  );
  expect(candidate.scope.length, `${label}.scope should be non-empty`).toBeGreaterThan(0);
  expect(candidate.category.length, `${label}.category should be non-empty`).toBeGreaterThan(0);
  expect(candidate.record_id.length, `${label}.record_id should be non-empty`).toBeGreaterThan(0);
  expect(candidate.book_id.length, `${label}.book_id should be non-empty`).toBeGreaterThan(0);
  expect(candidate.entity_id.length, `${label}.entity_id should be non-empty`).toBeGreaterThan(0);
  expect(
    candidate.closing_date.length,
    `${label}.closing_date should be non-empty`,
  ).toBeGreaterThan(0);
  if (candidate.due_date !== null) {
    expect(candidate.due_date.length, `${label}.due_date should be non-empty`).toBeGreaterThan(0);
  }
  expect(typeof candidate.overdue, `${label}.overdue should be boolean`).toBe('boolean');
  expect(candidate.policy_id.length, `${label}.policy_id should be non-empty`).toBeGreaterThan(0);
  expect(candidate.policy_name.length, `${label}.policy_name should be non-empty`).toBeGreaterThan(
    0,
  );
  expect(candidate.schedule_id.length, `${label}.schedule_id should be non-empty`).toBeGreaterThan(
    0,
  );
  expect(
    candidate.retention_period.length,
    `${label}.retention_period should be non-empty`,
  ).toBeGreaterThan(0);
  expect(
    candidate.disposal_action.length,
    `${label}.disposal_action should be non-empty`,
  ).toBeGreaterThan(0);
  expect(typeof candidate.destructive_action, `${label}.destructive_action`).toBe('boolean');
  expect(Array.isArray(candidate.legal_hold_blockers), `${label}.legal_hold_blockers`).toBe(true);
  expect(Array.isArray(candidate.required_approvals), `${label}.required_approvals`).toBe(true);
  expect(Array.isArray(candidate.blockers), `${label}.blockers`).toBe(true);
  expect(Array.isArray(candidate.findings), `${label}.findings`).toBe(true);
  candidate.findings.forEach((finding, i) =>
    assertRetentionDueCandidateFinding(finding, `${label}.findings[${i}]`),
  );
  expect(candidate.outcome.length, `${label}.outcome should be non-empty`).toBeGreaterThan(0);
  expect(candidate.status.length, `${label}.status should be non-empty`).toBeGreaterThan(0);
  inEnum(
    RETENTION_EVIDENCE_STATES,
    candidate.candidate_evidence_state,
    `${label}.candidate_evidence_state`,
  );
  expect(
    candidate.evidence_next_step.length,
    `${label}.evidence_next_step should be non-empty`,
  ).toBeGreaterThan(0);
  expect(candidate.would_execute, `${label}.would_execute is pinned false`).toBe(false);
  expect(
    candidate.destructive_disposal_completed,
    `${label}.destructive_disposal_completed is pinned false`,
  ).toBe(false);
  expect(candidate.full_erasure_completed, `${label}.full_erasure_completed is pinned false`).toBe(
    false,
  );
  if (candidate.prior_execution !== undefined) {
    assertRetentionDueCandidatePriorExecution(
      candidate.prior_execution,
      `${label}.prior_execution`,
    );
  }
  expect(
    Number.isInteger(candidate.candidate_resolution_record_count),
    `${label}.candidate_resolution_record_count`,
  ).toBe(true);
  expect(
    candidate.candidate_resolution_record_count,
    `${label}.candidate_resolution_record_count`,
  ).toBeGreaterThanOrEqual(0);
  if (candidate.latest_resolution !== undefined) {
    assertRetentionCandidateResolutionSummary(
      candidate.latest_resolution,
      `${label}.latest_resolution`,
    );
    expect(
      candidate.candidate_resolution_record_count,
      `${label}.candidate_resolution_record_count should include latest_resolution`,
    ).toBeGreaterThan(0);
  }
  expect(candidate.next_step.length, `${label}.next_step should be non-empty`).toBeGreaterThan(0);
  return candidate;
}

function assertRetentionDueCandidatesSuppressionSummary(
  obj: unknown,
  label: string,
): RetentionDueCandidatesSuppressionSummary {
  const summary = assertExactKeys<RetentionDueCandidatesSuppressionSummary>(
    obj,
    {
      suppressed_by_bounded_evidence_count: true,
      note: true,
    },
    label,
  );
  expect(
    Number.isInteger(summary.suppressed_by_bounded_evidence_count),
    `${label}.suppressed_by_bounded_evidence_count should be integer`,
  ).toBe(true);
  expect(
    summary.suppressed_by_bounded_evidence_count,
    `${label}.suppressed_by_bounded_evidence_count should be non-negative`,
  ).toBeGreaterThanOrEqual(0);
  expect(summary.note, `${label}.note should use review-only wording`).toBe(
    RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE,
  );
  expect(summary.note.toLowerCase(), `${label}.note should remain review-oriented`).toContain(
    'review',
  );
  const normalizedNote = summary.note.toLowerCase();
  RETENTION_DUE_CANDIDATE_PRIOR_UNSAFE_NEXT_STEP_TERMS.forEach((term) => {
    expect(normalizedNote, `${label}.note should not include ${term}`).not.toContain(term);
  });
  return summary;
}

function assertRetentionDueCandidatesReport(
  obj: unknown,
  label: string,
): RetentionDueCandidatesReport {
  const report = assertExactKeys<RetentionDueCandidatesReport>(
    obj,
    {
      generated_at: true,
      scope: true,
      category: true,
      candidate_count: true,
      suppressed_candidate_count: true,
      suppressed_by_bounded_evidence_count: true,
      candidate_resolution_record_count: true,
      candidates_with_resolution_count: true,
      candidates: true,
    },
    label,
    ['suppression_summary'],
  );
  assertTimestamp(report.generated_at, `${label}.generated_at`);
  expect(report.scope, `${label}.scope`).toBe('book_archive');
  expect(report.category, `${label}.category`).toBe('documents');
  expect(Number.isInteger(report.candidate_count), `${label}.candidate_count`).toBe(true);
  expect(
    Number.isInteger(report.suppressed_candidate_count),
    `${label}.suppressed_candidate_count`,
  ).toBe(true);
  expect(
    Number.isInteger(report.suppressed_by_bounded_evidence_count),
    `${label}.suppressed_by_bounded_evidence_count`,
  ).toBe(true);
  expect(
    Number.isInteger(report.candidate_resolution_record_count),
    `${label}.candidate_resolution_record_count`,
  ).toBe(true);
  expect(
    Number.isInteger(report.candidates_with_resolution_count),
    `${label}.candidates_with_resolution_count`,
  ).toBe(true);
  expect(
    report.candidate_count,
    `${label}.candidate_count counts active unsuppressed candidates only`,
  ).toBe(report.candidates.length);
  expect(
    report.suppressed_candidate_count,
    `${label}.suppressed_candidate_count`,
  ).toBeGreaterThanOrEqual(0);
  expect(
    report.suppressed_by_bounded_evidence_count,
    `${label}.suppressed_by_bounded_evidence_count`,
  ).toBeGreaterThanOrEqual(0);
  expect(
    report.suppressed_candidate_count,
    `${label}.suppressed_candidate_count should cover bounded-evidence suppressions`,
  ).toBeGreaterThanOrEqual(report.suppressed_by_bounded_evidence_count);
  expect(
    report.candidate_resolution_record_count,
    `${label}.candidate_resolution_record_count`,
  ).toBeGreaterThanOrEqual(report.candidates_with_resolution_count);
  if (report.suppressed_candidate_count > 0) {
    expect(report.suppression_summary, `${label}.suppression_summary`).toBeDefined();
    const summary = assertRetentionDueCandidatesSuppressionSummary(
      report.suppression_summary,
      `${label}.suppression_summary`,
    );
    expect(
      summary.suppressed_by_bounded_evidence_count,
      `${label}.suppression_summary count mirrors report`,
    ).toBe(report.suppressed_by_bounded_evidence_count);
  } else {
    expect(report.suppression_summary, `${label}.suppression_summary`).toBeUndefined();
  }
  report.candidates.forEach((candidate, i) =>
    assertRetentionDueCandidate(candidate, `${label}.candidates[${i}]`),
  );
  return report;
}

function assertRetentionCandidateResolutionSnapshot(
  obj: unknown,
  label: string,
): RetentionCandidateResolutionSnapshot {
  const snapshot = assertExactKeys<RetentionCandidateResolutionSnapshot>(
    obj,
    {
      candidate_id: true,
      candidate_fingerprint: true,
      scope: true,
      category: true,
      record_id: true,
      book_id: true,
      entity_id: true,
      closing_date: true,
      overdue: true,
      policy_id: true,
      policy_name: true,
      schedule_id: true,
      retention_period: true,
      disposal_action: true,
      destructive_action: true,
      outcome: true,
      status: true,
      candidate_evidence_state: true,
      legal_hold_blocker_count: true,
      required_approval_count: true,
      blocker_count: true,
      finding_count: true,
    },
    label,
    ['due_date'],
  );
  expect(snapshot.candidate_id.length, `${label}.candidate_id`).toBeGreaterThan(0);
  expect(snapshot.candidate_fingerprint, `${label}.candidate_fingerprint`).toMatch(
    /^[0-9a-f]{64}$/,
  );
  inEnum(RETENTION_DISPOSAL_ACTIONS, snapshot.disposal_action, `${label}.disposal_action`);
  inEnum(
    RETENTION_EVIDENCE_STATES,
    snapshot.candidate_evidence_state,
    `${label}.candidate_evidence_state`,
  );
  for (const field of [
    'legal_hold_blocker_count',
    'required_approval_count',
    'blocker_count',
    'finding_count',
  ] as const) {
    expect(Number.isInteger(snapshot[field]), `${label}.${field}`).toBe(true);
    expect(snapshot[field], `${label}.${field}`).toBeGreaterThanOrEqual(0);
  }
  return snapshot;
}

function assertRetentionCandidateResolutionRecord(
  obj: unknown,
  label: string,
): RetentionCandidateResolutionRecord {
  const record = assertExactKeys<RetentionCandidateResolutionRecord>(
    obj,
    {
      id: true,
      candidate_id: true,
      candidate_fingerprint: true,
      recorded_at: true,
      recorded_by: true,
      disposition: true,
      evidence: true,
      evidence_count: true,
      candidate: true,
      evidence_only: true,
      destructive_disposal_completed: true,
      disposal_completed: true,
      full_erasure_completed: true,
      erasure_completed: true,
      legal_hold_mutated: true,
      legal_hold_resolved: true,
      retention_policy_mutated: true,
      retention_policy_changed: true,
      legal_completion_claimed: true,
      legal_disposal_completed: true,
      next_step: true,
    },
    label,
    ['note'],
  );
  assertRetentionCandidateResolutionSummary(
    {
      id: record.id,
      candidate_fingerprint: record.candidate_fingerprint,
      recorded_at: record.recorded_at,
      recorded_by: record.recorded_by,
      disposition: record.disposition,
      evidence_count: record.evidence_count,
      ...(record.note !== undefined ? { note: record.note } : {}),
      evidence_only: record.evidence_only,
      destructive_disposal_completed: record.destructive_disposal_completed,
      disposal_completed: record.disposal_completed,
      full_erasure_completed: record.full_erasure_completed,
      erasure_completed: record.erasure_completed,
      legal_hold_mutated: record.legal_hold_mutated,
      legal_hold_resolved: record.legal_hold_resolved,
      retention_policy_mutated: record.retention_policy_mutated,
      retention_policy_changed: record.retention_policy_changed,
      legal_completion_claimed: record.legal_completion_claimed,
      legal_disposal_completed: record.legal_disposal_completed,
      next_step: record.next_step,
    },
    `${label}.summary`,
  );
  expect(record.candidate_id.length, `${label}.candidate_id`).toBeGreaterThan(0);
  expect(Array.isArray(record.evidence), `${label}.evidence`).toBe(true);
  expect(record.evidence_count, `${label}.evidence_count mirrors evidence`).toBe(
    record.evidence.length,
  );
  record.evidence.forEach((evidence, i) =>
    assertRetentionReviewClosureEvidence(evidence, `${label}.evidence[${i}]`),
  );
  const snapshot = assertRetentionCandidateResolutionSnapshot(record.candidate, `${label}.candidate`);
  expect(snapshot.candidate_id, `${label}.candidate.candidate_id`).toBe(record.candidate_id);
  expect(snapshot.candidate_fingerprint, `${label}.candidate.candidate_fingerprint`).toBe(
    record.candidate_fingerprint,
  );
  return record;
}

function assertRetentionExecutionRequestedPolicy(
  obj: unknown,
  label: string,
): RetentionExecutionRequestedPolicy {
  const policy = assertExactKeys<RetentionExecutionRequestedPolicy>(
    obj,
    {
      found: true,
      stale: true,
      matches_candidate: true,
      destructive_action: true,
    },
    label,
    [
      'id',
      'name',
      'scope',
      'category',
      'schedule_id',
      'retention_period',
      'disposal_action',
      'status',
      'active',
    ],
  );
  expect(typeof policy.found, `${label}.found should be boolean`).toBe('boolean');
  expect(typeof policy.stale, `${label}.stale should be boolean`).toBe('boolean');
  expect(typeof policy.matches_candidate, `${label}.matches_candidate should be boolean`).toBe(
    'boolean',
  );
  expect(typeof policy.destructive_action, `${label}.destructive_action should be boolean`).toBe(
    'boolean',
  );
  if (policy.disposal_action !== undefined) {
    inEnum(RETENTION_DISPOSAL_ACTIONS, policy.disposal_action, `${label}.disposal_action`);
  }
  if (policy.status !== undefined) {
    inEnum(RETENTION_POLICY_STATUSES, policy.status, `${label}.status`);
  }
  return policy;
}

function assertRetentionMatchedRecordsSummary(
  obj: unknown,
  label: string,
): RetentionMatchedRecordsSummary {
  const summary = assertExactKeys<RetentionMatchedRecordsSummary>(
    obj,
    {
      scope: true,
      category: true,
      record_count: true,
      policy_match_count: true,
      destructive_policy_count: true,
      policy_ids: true,
    },
    label,
    ['record_id'],
  );
  expect(summary.scope.length, `${label}.scope should be non-empty`).toBeGreaterThan(0);
  expect(summary.category.length, `${label}.category should be non-empty`).toBeGreaterThan(0);
  expect(
    summary.record_count,
    `${label}.record_count should be non-negative`,
  ).toBeGreaterThanOrEqual(0);
  expect(
    summary.policy_match_count,
    `${label}.policy_match_count should be non-negative`,
  ).toBeGreaterThanOrEqual(0);
  expect(Array.isArray(summary.policy_ids), `${label}.policy_ids should be an array`).toBe(true);
  return summary;
}

function assertRetentionWorkflowBlocker(obj: unknown, label: string): RetentionWorkflowBlocker {
  const blocker = assertExactKeys<RetentionWorkflowBlocker>(
    obj,
    { code: true, message: true },
    label,
    ['policy_id'],
  );
  expect(blocker.code.length, `${label}.code should be non-empty`).toBeGreaterThan(0);
  expect(blocker.message.length, `${label}.message should be non-empty`).toBeGreaterThan(0);
  return blocker;
}

function assertRetentionRequiredApproval(obj: unknown, label: string): RetentionRequiredApproval {
  const approval = assertExactKeys<RetentionRequiredApproval>(
    obj,
    { code: true, required_from: true, reason: true },
    label,
  );
  expect(approval.code.length, `${label}.code should be non-empty`).toBeGreaterThan(0);
  expect(
    approval.required_from.length,
    `${label}.required_from should be non-empty`,
  ).toBeGreaterThan(0);
  expect(approval.reason.length, `${label}.reason should be non-empty`).toBeGreaterThan(0);
  return approval;
}

function assertRetentionOperatorWorkflow(obj: unknown, label: string): RetentionOperatorWorkflow {
  const workflow = assertExactKeys<RetentionOperatorWorkflow>(
    obj,
    { status: true, blockers: true, required_approvals: true, next_step: true },
    label,
  );
  inEnum(['blocked', 'awaiting_manual_review'], workflow.status, `${label}.status`);
  expect(Array.isArray(workflow.blockers), `${label}.blockers should be an array`).toBe(true);
  workflow.blockers.forEach((blocker, i) =>
    assertRetentionWorkflowBlocker(blocker, `${label}.blockers[${i}]`),
  );
  expect(
    Array.isArray(workflow.required_approvals),
    `${label}.required_approvals should be an array`,
  ).toBe(true);
  workflow.required_approvals.forEach((approval, i) =>
    assertRetentionRequiredApproval(approval, `${label}.required_approvals[${i}]`),
  );
  expect(workflow.next_step.length, `${label}.next_step should be non-empty`).toBeGreaterThan(0);
  return workflow;
}

function assertRetentionOperatorEvidence(obj: unknown, label: string): RetentionOperatorEvidence {
  const evidence = assertExactKeys<RetentionOperatorEvidence>(
    obj,
    { label: true, value: true },
    label,
  );
  expect(evidence.label.length, `${label}.label should be non-empty`).toBeGreaterThan(0);
  expect(evidence.value.length, `${label}.value should be non-empty`).toBeGreaterThan(0);
  return evidence;
}

function assertRetentionReviewClosureEvidence(
  obj: unknown,
  label: string,
): RetentionReviewClosureEvidence {
  const evidence = assertExactKeys<RetentionReviewClosureEvidence>(
    obj,
    { label: true, value: true },
    label,
  );
  expect(evidence.label.length, `${label}.label should be non-empty`).toBeGreaterThan(0);
  expect(evidence.value.length, `${label}.value should be non-empty`).toBeGreaterThan(0);
  const normalized = `${evidence.label} ${evidence.value}`.toLowerCase();
  RETENTION_REVIEW_CLOSURE_OVERCLAIM_TERMS.forEach((term) => {
    expect(normalized, `${label} should not overclaim ${term}`).not.toContain(term);
  });
  return evidence;
}

function assertRetentionExecutionApproval(obj: unknown, label: string): RetentionExecutionApproval {
  const approval = assertExactKeys<RetentionExecutionApproval>(
    obj,
    {
      approval_reference: true,
      policy_id: true,
      disposal_action: true,
      approved_by: true,
    },
    label,
    ['approved_at'],
  );
  expect(
    approval.approval_reference.length,
    `${label}.approval_reference should be non-empty`,
  ).toBeGreaterThan(0);
  expect(approval.policy_id.length, `${label}.policy_id should be non-empty`).toBeGreaterThan(0);
  inEnum(RETENTION_DISPOSAL_ACTIONS, approval.disposal_action, `${label}.disposal_action`);
  expect(approval.approved_by.length, `${label}.approved_by should be non-empty`).toBeGreaterThan(
    0,
  );
  if (approval.approved_at !== undefined)
    assertTimestamp(approval.approved_at, `${label}.approved_at`);
  return approval;
}

function assertRetentionExecutionTargetEvidence(
  obj: unknown,
  label: string,
): RetentionExecutionTargetEvidence {
  const target = assertExactKeys<RetentionExecutionTargetEvidence>(
    obj,
    { target_type: true, target_id: true, action: true, reason_code: true, detail: true },
    label,
  );
  expect(target.target_type.length, `${label}.target_type should be non-empty`).toBeGreaterThan(0);
  expect(target.target_id.length, `${label}.target_id should be non-empty`).toBeGreaterThan(0);
  expect(target.action.length, `${label}.action should be non-empty`).toBeGreaterThan(0);
  expect(target.reason_code.length, `${label}.reason_code should be non-empty`).toBeGreaterThan(0);
  expect(target.detail.length, `${label}.detail should be non-empty`).toBeGreaterThan(0);
  return target;
}

function assertRetentionExecutionBlockerMetadata(
  obj: unknown,
  label: string,
): RetentionExecutionBlockerMetadata {
  const blocker = assertExactKeys<RetentionExecutionBlockerMetadata>(
    obj,
    { code: true, detail: true },
    label,
    ['policy_id'],
  );
  expect(blocker.code.length, `${label}.code should be non-empty`).toBeGreaterThan(0);
  expect(blocker.detail.length, `${label}.detail should be non-empty`).toBeGreaterThan(0);
  return blocker;
}

function assertRetentionExecutionResult(obj: unknown, label: string): RetentionExecutionResult {
  const result = assertExactKeys<RetentionExecutionResult>(
    obj,
    {
      bounded_executor: true,
      targets_considered: true,
      targets_acted: true,
      targets_skipped: true,
      reason_codes: true,
      next_step: true,
      destructive_disposal_completed: true,
      full_erasure_completed: true,
      blocker_metadata: true,
    },
    label,
    ['executed_at', 'executed_by'],
  );
  expect(result.bounded_executor, `${label}.bounded_executor should be true`).toBe(true);
  expect(Array.isArray(result.targets_considered), `${label}.targets_considered`).toBe(true);
  result.targets_considered.forEach((target, i) =>
    assertRetentionExecutionTargetEvidence(target, `${label}.targets_considered[${i}]`),
  );
  expect(Array.isArray(result.targets_acted), `${label}.targets_acted`).toBe(true);
  result.targets_acted.forEach((target, i) =>
    assertRetentionExecutionTargetEvidence(target, `${label}.targets_acted[${i}]`),
  );
  expect(Array.isArray(result.targets_skipped), `${label}.targets_skipped`).toBe(true);
  result.targets_skipped.forEach((target, i) =>
    assertRetentionExecutionTargetEvidence(target, `${label}.targets_skipped[${i}]`),
  );
  expect(Array.isArray(result.reason_codes), `${label}.reason_codes`).toBe(true);
  expect(result.next_step.length, `${label}.next_step should be non-empty`).toBeGreaterThan(0);
  expect(
    result.destructive_disposal_completed,
    `${label}.destructive_disposal_completed should be false`,
  ).toBe(false);
  expect(result.full_erasure_completed, `${label}.full_erasure_completed should be false`).toBe(
    false,
  );
  result.blocker_metadata.forEach((blocker, i) =>
    assertRetentionExecutionBlockerMetadata(blocker, `${label}.blocker_metadata[${i}]`),
  );
  if (result.executed_at !== undefined) assertTimestamp(result.executed_at, `${label}.executed_at`);
  return result;
}

function assertRetentionLegalHoldBlocker(obj: unknown, label: string): RetentionLegalHoldBlocker {
  const blocker = assertExactKeys<RetentionLegalHoldBlocker>(
    obj,
    { policy_id: true, name: true, schedule_id: true, retention_period: true, reason: true },
    label,
  );
  expect(blocker.policy_id.length, `${label}.policy_id should be non-empty`).toBeGreaterThan(0);
  expect(blocker.name.length, `${label}.name should be non-empty`).toBeGreaterThan(0);
  expect(blocker.reason.length, `${label}.reason should be non-empty`).toBeGreaterThan(0);
  return blocker;
}

function assertRetentionExecutionRecord(obj: unknown, label: string): RetentionExecutionRecord {
  const record = assertExactKeys<RetentionExecutionRecord>(
    obj,
    {
      id: true,
      requested_at: true,
      actor: true,
      execution_intent: true,
      execution_status: true,
      operator_review_decision: true,
      decision_state: true,
      review_closure_evidence: true,
      destructive_disposal_completed: true,
      full_erasure_completed: true,
      legal_hold_mutated: true,
      retention_policy_mutated: true,
      requested_policy: true,
      candidate: true,
      matched_records_summary: true,
      legal_hold_blockers: true,
      audit_evidence: true,
      outcome: true,
      block_reason: true,
      evidence_state: true,
      evidence_next_step: true,
      workflow: true,
      execution_result: true,
      would_execute: true,
    },
    label,
    [
      'operator_notes',
      'approval',
      'review_closure_decision',
      'review_closed_by',
      'review_closed_at',
      'review_closure_note',
    ],
  );
  expect(record.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  assertTimestamp(record.requested_at, `${label}.requested_at`);
  expect(record.actor.length, `${label}.actor should be non-empty`).toBeGreaterThan(0);
  inEnum(
    ['review_only', 'execute_supported'],
    record.execution_intent,
    `${label}.execution_intent`,
  );
  inEnum(RETENTION_EXECUTION_STATUSES, record.execution_status, `${label}.execution_status`);
  inEnum(
    ['review_required', 'blocked', 'execution_recorded'],
    record.operator_review_decision,
    `${label}.operator_review_decision`,
  );
  inEnum(RETENTION_EXECUTION_DECISION_STATES, record.decision_state, `${label}.decision_state`);
  expect(Array.isArray(record.review_closure_evidence), `${label}.review_closure_evidence`).toBe(
    true,
  );
  record.review_closure_evidence.forEach((evidence, i) =>
    assertRetentionReviewClosureEvidence(evidence, `${label}.review_closure_evidence[${i}]`),
  );
  expect(
    record.destructive_disposal_completed,
    `${label}.destructive_disposal_completed should be false`,
  ).toBe(false);
  expect(record.full_erasure_completed, `${label}.full_erasure_completed should be false`).toBe(
    false,
  );
  expect(record.legal_hold_mutated, `${label}.legal_hold_mutated should be false`).toBe(false);
  expect(record.retention_policy_mutated, `${label}.retention_policy_mutated should be false`).toBe(
    false,
  );
  if (record.review_closure_decision !== undefined) {
    inEnum(
      RETENTION_REVIEW_CLOSURE_DECISIONS,
      record.review_closure_decision,
      `${label}.review_closure_decision`,
    );
  }
  if (record.review_closed_at !== undefined) {
    assertTimestamp(record.review_closed_at, `${label}.review_closed_at`);
  }
  if (record.review_closed_by !== undefined) {
    expect(
      record.review_closed_by.length,
      `${label}.review_closed_by should be non-empty`,
    ).toBeGreaterThan(0);
  }
  if (record.review_closure_note !== undefined) {
    expect(
      record.review_closure_note.length,
      `${label}.review_closure_note should be non-empty`,
    ).toBeGreaterThan(0);
    const normalizedNote = record.review_closure_note.toLowerCase();
    RETENTION_REVIEW_CLOSURE_OVERCLAIM_TERMS.forEach((term) => {
      expect(
        normalizedNote,
        `${label}.review_closure_note should not overclaim ${term}`,
      ).not.toContain(term);
    });
  }
  if (record.decision_state === 'review_closed') {
    expect(
      record.review_closure_decision,
      `${label}.review_closure_decision should be present when closed`,
    ).toBeDefined();
    expect(
      record.review_closed_by,
      `${label}.review_closed_by should be present when closed`,
    ).toBeDefined();
    expect(
      record.review_closed_by?.length,
      `${label}.review_closed_by should be non-empty when closed`,
    ).toBeGreaterThan(0);
    expect(
      record.review_closed_at,
      `${label}.review_closed_at should be present when closed`,
    ).toBeDefined();
    if (record.review_closed_at !== undefined) {
      assertTimestamp(record.review_closed_at, `${label}.review_closed_at`);
    }
    expect(
      record.review_closure_note !== undefined || record.review_closure_evidence.length > 0,
      `${label}.review closure needs note or evidence`,
    ).toBe(true);
  } else {
    expect(record.review_closure_decision, `${label}.open closure decision`).toBeUndefined();
    expect(record.review_closed_by, `${label}.open closure actor`).toBeUndefined();
    expect(record.review_closed_at, `${label}.open closure timestamp`).toBeUndefined();
    expect(record.review_closure_note, `${label}.open closure note`).toBeUndefined();
    expect(record.review_closure_evidence, `${label}.open closure evidence`).toHaveLength(0);
  }
  assertRetentionExecutionRequestedPolicy(record.requested_policy, `${label}.requested_policy`);
  expect(
    record.candidate.scope.length,
    `${label}.candidate.scope should be non-empty`,
  ).toBeGreaterThan(0);
  expect(
    record.candidate.category.length,
    `${label}.candidate.category should be non-empty`,
  ).toBeGreaterThan(0);
  assertRetentionMatchedRecordsSummary(
    record.matched_records_summary,
    `${label}.matched_records_summary`,
  );
  record.legal_hold_blockers.forEach((blocker, i) =>
    assertRetentionLegalHoldBlocker(blocker, `${label}.legal_hold_blockers[${i}]`),
  );
  record.audit_evidence.forEach((evidence, i) =>
    assertRetentionOperatorEvidence(evidence, `${label}.audit_evidence[${i}]`),
  );
  if (record.approval !== undefined)
    assertRetentionExecutionApproval(record.approval, `${label}.approval`);
  inEnum(
    [
      'blocked_missing_policy',
      'blocked_stale_policy',
      'blocked_policy_mismatch',
      'blocked_legal_hold',
      'blocked_destructive_action',
      'blocked_approval_mismatch',
      'blocked_missing_target',
      'manual_review_required',
      'bounded_archive_recorded',
      'bounded_no_action_recorded',
      'already_executed',
    ],
    record.outcome,
    `${label}.outcome`,
  );
  expect(record.block_reason.length, `${label}.block_reason should be non-empty`).toBeGreaterThan(
    0,
  );
  inEnum(RETENTION_EVIDENCE_STATES, record.evidence_state, `${label}.evidence_state`);
  expect(
    record.evidence_next_step.length,
    `${label}.evidence_next_step should be non-empty`,
  ).toBeGreaterThan(0);
  assertRetentionOperatorWorkflow(record.workflow, `${label}.workflow`);
  assertRetentionExecutionResult(record.execution_result, `${label}.execution_result`);
  expect(typeof record.would_execute, `${label}.would_execute should be boolean`).toBe('boolean');
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

function assertPlatformLogEntry(obj: unknown, label: string): PlatformLogEntry {
  const entry = assertExactKeys<PlatformLogEntry>(
    obj,
    {
      id: true,
      seq: true,
      timestamp: true,
      service_id: true,
      level: true,
      target: true,
      message: true,
    },
    label,
    ['context'],
  );
  expect(entry.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(Number.isInteger(entry.seq), `${label}.seq should be an integer`).toBe(true);
  expect(entry.seq, `${label}.seq should be positive`).toBeGreaterThan(0);
  assertTimestamp(entry.timestamp, `${label}.timestamp`);
  inEnum(['app', 'api', 'mcp_stdio'], entry.service_id, `${label}.service_id`);
  inEnum(PLATFORM_EMITTED_LOG_LEVELS, entry.level, `${label}.level`);
  expect(entry.target.length, `${label}.target should be non-empty`).toBeGreaterThan(0);
  expect(entry.message.length, `${label}.message should be non-empty`).toBeGreaterThan(0);
  return entry;
}

function assertPlatformLogRetentionMetadata(
  obj: unknown,
  label: string,
): PlatformLogRetentionMetadata {
  const retention = assertExactKeys<PlatformLogRetentionMetadata>(
    obj,
    {
      retention_limit: true,
      retained_count: true,
      oldest_seq: true,
      newest_seq: true,
      dropped_before_seq: true,
      durable: true,
      basis: true,
      source: true,
    },
    label,
  );
  expect(
    Number.isInteger(retention.retention_limit),
    `${label}.retention_limit should be an integer`,
  ).toBe(true);
  expect(retention.retention_limit, `${label}.retention_limit should be positive`).toBeGreaterThan(
    0,
  );
  expect(
    Number.isInteger(retention.retained_count),
    `${label}.retained_count should be an integer`,
  ).toBe(true);
  expect(
    retention.retained_count,
    `${label}.retained_count should be non-negative`,
  ).toBeGreaterThanOrEqual(0);
  expect(
    retention.retained_count,
    `${label}.retained_count should not exceed limit`,
  ).toBeLessThanOrEqual(retention.retention_limit);
  for (const field of ['oldest_seq', 'newest_seq', 'dropped_before_seq'] as const) {
    const value = retention[field];
    expect(
      value === null || Number.isInteger(value),
      `${label}.${field} should be null or an integer`,
    ).toBe(true);
    if (value !== null) {
      expect(value, `${label}.${field} should be positive when present`).toBeGreaterThan(0);
    }
  }
  expect(typeof retention.durable, `${label}.durable should be boolean`).toBe('boolean');
  inEnum(['data_dir', 'memory'], retention.basis, `${label}.basis`);
  inEnum(['platform-logs.json', 'process_memory'], retention.source, `${label}.source`);
  return retention;
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
      canonical_conversion_preflight: true,
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
  const preflight = assertExactKeys<PaperBookCanonicalConversionPreflight>(
    report.canonical_conversion_preflight,
    {
      status: true,
      preflight_requested: true,
      scope: true,
      evidence_source: true,
      evidence: true,
      blockers: true,
      allowed_next_action: true,
      raw_ocr_text_in_report: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signature_created: true,
      signing_requested: true,
      signature_validity_claimed: true,
      qualified_signature_claimed: true,
      legal_validity_claimed: true,
    },
    `${label}.canonical_conversion_preflight`,
  );
  inEnum(
    ['not_attempted', 'blocked', 'allowed'],
    preflight.status,
    `${label}.canonical_conversion_preflight.status`,
  );
  expect(preflight.scope).toBe('ocr_to_canonical_conversion_preflight');
  const preflightEvidence = assertExactKeys<PaperBookCanonicalConversionPreflightEvidence>(
    preflight.evidence,
    {
      ocr_text_present: true,
      ocr_text_digest: true,
      operator_review_recorded: true,
      candidate_digest_present: true,
      package_fixity_recorded: true,
      source_page_range_valid: true,
      source_page_range: true,
      page_range_reviewed: true,
      legal_acceptance_recorded: true,
    },
    `${label}.canonical_conversion_preflight.evidence`,
  );
  if (preflightEvidence.ocr_text_digest) {
    assertHex64(
      preflightEvidence.ocr_text_digest,
      `${label}.canonical_conversion_preflight.evidence.ocr_text_digest`,
    );
  }
  expect(preflightEvidence.source_page_range).toEqual(sourcePageRange);
  for (const blocker of preflight.blockers) {
    const item = assertExactKeys<PaperBookCanonicalConversionPreflightBlocker>(
      blocker,
      { code: true, field: true, message: true },
      `${label}.canonical_conversion_preflight.blocker`,
    );
    expect(item.code.length).toBeGreaterThan(0);
    expect(item.field.length).toBeGreaterThan(0);
    expect(item.message.length).toBeGreaterThan(0);
  }
  expect(preflight.raw_ocr_text_in_report).toBe(false);
  expect(preflight.canonical_act_created).toBe(false);
  expect(preflight.canonical_document_created).toBe(false);
  expect(preflight.signature_created).toBe(false);
  expect(preflight.signing_requested).toBe(false);
  expect(preflight.signature_validity_claimed).toBe(false);
  expect(preflight.qualified_signature_claimed).toBe(false);
  expect(preflight.legal_validity_claimed).toBe(false);
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

function assertPaperBookOcrDraft(obj: unknown, label: string): PaperBookOcrDraftView {
  const draft = assertExactKeys<PaperBookOcrDraftView>(
    obj,
    {
      draft_id: true,
      import_id: true,
      extracted_text: true,
      text_digest: true,
      page_spans: true,
      confidence: true,
      engine: true,
      created_at: true,
      created_by: true,
      review_status: true,
      reviewed_at: true,
      reviewed_by: true,
      review_note: true,
      superseded_by: true,
      draft_notice: true,
      non_canonical: true,
      authoritative_text_claimed: true,
      canonical_minutes_claimed: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signature_created: true,
      legal_validity_claimed: true,
      legal_notice: true,
    },
    label,
  );
  expect(draft.draft_id.length, `${label}.draft_id should be non-empty`).toBeGreaterThan(0);
  expect(draft.import_id.length, `${label}.import_id should be non-empty`).toBeGreaterThan(0);
  if (draft.extracted_text !== null) {
    expect(
      draft.extracted_text.length,
      `${label}.extracted_text should be non-empty`,
    ).toBeGreaterThan(0);
  }
  if (draft.text_digest !== null) assertHex64(draft.text_digest, `${label}.text_digest`);
  expect(
    draft.extracted_text !== null || draft.text_digest !== null,
    `${label} should carry text or digest evidence`,
  ).toBe(true);
  expect(Array.isArray(draft.page_spans), `${label}.page_spans should be array`).toBe(true);
  expect(draft.page_spans.length, `${label}.page_spans should be non-empty`).toBeGreaterThan(0);
  for (const span of draft.page_spans) {
    const item = assertExactKeys<PaperBookOcrDraftPageSpanView>(
      span,
      { start_page: true, end_page: true },
      `${label}.page_spans[]`,
    );
    expect(item.start_page, `${label}.page_spans[].start_page positive`).toBeGreaterThan(0);
    expect(item.end_page, `${label}.page_spans[].end_page ordered`).toBeGreaterThanOrEqual(
      item.start_page,
    );
  }
  if (draft.confidence !== null) {
    expect(draft.confidence, `${label}.confidence lower bound`).toBeGreaterThanOrEqual(0);
    expect(draft.confidence, `${label}.confidence upper bound`).toBeLessThanOrEqual(1);
  }
  const engine = assertExactKeys<PaperBookOcrEngineView>(
    draft.engine,
    { name: true, version: true },
    `${label}.engine`,
  );
  expect(engine.name.length, `${label}.engine.name should be non-empty`).toBeGreaterThan(0);
  assertTimestamp(draft.created_at, `${label}.created_at`);
  expect(draft.created_by.length, `${label}.created_by should be non-empty`).toBeGreaterThan(0);
  inEnum(PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES, draft.review_status, `${label}.review_status`);
  if (draft.reviewed_at !== null) assertTimestamp(draft.reviewed_at, `${label}.reviewed_at`);
  expect(draft.draft_notice).toContain('non-authoritative');
  expect(draft.draft_notice).toContain('not canonical minutes');
  expect(draft.non_canonical).toBe(true);
  expect(draft.authoritative_text_claimed).toBe(false);
  expect(draft.canonical_minutes_claimed).toBe(false);
  expect(draft.canonical_act_created).toBe(false);
  expect(draft.canonical_document_created).toBe(false);
  expect(draft.signature_created).toBe(false);
  expect(draft.legal_validity_claimed).toBe(false);
  expect(JSON.stringify(draft)).not.toContain('qualified_signature_claimed":true');
  return draft;
}

const PAPER_BOOK_CANONICAL_DRAFT_RAW_OCR_TEXT =
  'Deliberacao importada por OCR para revisao humana.';

function assertFalseFlags(obj: unknown, label: string, keys: readonly string[]): void {
  const record = obj as Record<string, unknown>;
  for (const key of keys) {
    expect(record, `${label} should expose ${key}`).toHaveProperty(key);
    expect(record[key], `${label}.${key} must remain false`).toBe(false);
  }
}

function assertPaperBookSourcePageSpans(
  spans: unknown,
  label: string,
): PaperBookOcrDraftPageSpanView[] {
  expect(Array.isArray(spans), `${label} should be array`).toBe(true);
  const typed = spans as unknown[];
  expect(typed.length, `${label} should be non-empty`).toBeGreaterThan(0);
  return typed.map((span, index) => {
    const item = assertExactKeys<PaperBookOcrDraftPageSpanView>(
      span,
      { start_page: true, end_page: true },
      `${label}[${index}]`,
    );
    expect(item.start_page, `${label}[${index}].start_page positive`).toBeGreaterThan(0);
    expect(item.end_page, `${label}[${index}].end_page ordered`).toBeGreaterThanOrEqual(
      item.start_page,
    );
    return item;
  });
}

function assertPaperBookActView(obj: unknown, label: string): ActView {
  const act = assertExactKeys<ActView>(
    obj,
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
    label,
    ['convening', 'ai_provenance'],
  );
  expect(act.id.length, `${label}.id should be non-empty`).toBeGreaterThan(0);
  expect(act.book_id.length, `${label}.book_id should be non-empty`).toBeGreaterThan(0);
  inEnum(MEETING_CHANNELS, act.channel, `${label}.channel`);
  inEnum(ACT_STATES, act.state, `${label}.state`);
  if (act.meeting_date) assertIsoDate(act.meeting_date, `${label}.meeting_date`);
  if (act.meeting_time) expect(act.meeting_time).toMatch(/^\d{2}:\d{2}$/);
  assertExactKeys<ActMesa>(act.mesa, { presidente: true, secretarios: true }, `${label}.mesa`);
  expect(Array.isArray(act.agenda), `${label}.agenda should be array`).toBe(true);
  expect(Array.isArray(act.referenced_documents), `${label}.referenced_documents`).toBe(true);
  expect(Array.isArray(act.deliberation_items), `${label}.deliberation_items`).toBe(true);
  expect(Array.isArray(act.attachments), `${label}.attachments`).toBe(true);
  expect(Array.isArray(act.signatories), `${label}.signatories`).toBe(true);
  if (act.payload_digest) assertHex64(act.payload_digest, `${label}.payload_digest`);
  return act;
}

function assertPaperBookOcrConversionExecutionArtifact(
  obj: unknown,
  label: string,
  forbiddenRawText = PAPER_BOOK_CANONICAL_DRAFT_RAW_OCR_TEXT,
): PaperBookOcrConversionExecutionArtifactView {
  const artifact = assertExactKeys<PaperBookOcrConversionExecutionArtifactView>(
    obj,
    {
      artifact_id: true,
      import_id: true,
      draft_id: true,
      dossier_id: true,
      source_text_digest: true,
      source_page_spans: true,
      source_review_status: true,
      source_reviewed_at: true,
      source_reviewed_by: true,
      target_act_id: true,
      target_act_state: true,
      mutable_draft_act_created: true,
      created_at: true,
      created_by: true,
      artifact_notice: true,
      reviewed_conversion_execution_artifact: true,
      non_canonical: true,
      canonical_conversion_claimed: true,
      canonical_minutes_claimed: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signed_document_created: true,
      archive_package_created: true,
      archive_certification_claimed: true,
      pdfa_created: true,
      pdfua_created: true,
      signature_created: true,
      seal_created: true,
      legal_validity_claimed: true,
      source_extracted_text_in_artifact: true,
      source_extracted_text_in_ledger_event: true,
      legal_notice: true,
    },
    label,
  );
  expect(artifact.artifact_id.length, `${label}.artifact_id should be non-empty`).toBeGreaterThan(
    0,
  );
  expect(artifact.import_id.length, `${label}.import_id should be non-empty`).toBeGreaterThan(0);
  expect(artifact.draft_id.length, `${label}.draft_id should be non-empty`).toBeGreaterThan(0);
  if (artifact.dossier_id !== null) {
    expect(artifact.dossier_id.length, `${label}.dossier_id should be non-empty`).toBeGreaterThan(
      0,
    );
  }
  if (artifact.source_text_digest !== null) {
    assertHex64(artifact.source_text_digest, `${label}.source_text_digest`);
  }
  assertPaperBookSourcePageSpans(artifact.source_page_spans, `${label}.source_page_spans`);
  inEnum(PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES, artifact.source_review_status, `${label}.status`);
  if (artifact.source_reviewed_at !== null) {
    assertTimestamp(artifact.source_reviewed_at, `${label}.source_reviewed_at`);
  }
  expect(
    artifact.target_act_id.length,
    `${label}.target_act_id should be non-empty`,
  ).toBeGreaterThan(0);
  expect(artifact.target_act_state).toBe('Draft');
  expect(artifact.mutable_draft_act_created).toBe(true);
  assertTimestamp(artifact.created_at, `${label}.created_at`);
  expect(artifact.created_by.length, `${label}.created_by should be non-empty`).toBeGreaterThan(0);
  expect(artifact.artifact_notice).toContain('not a canonical or legal conversion');
  expect(artifact.artifact_notice).toContain('PDF/UA');
  expect(artifact.reviewed_conversion_execution_artifact).toBe(true);
  expect(artifact.non_canonical).toBe(true);
  assertFalseFlags(artifact, label, [
    'canonical_conversion_claimed',
    'canonical_minutes_claimed',
    'canonical_act_created',
    'canonical_document_created',
    'signed_document_created',
    'archive_package_created',
    'archive_certification_claimed',
    'pdfa_created',
    'pdfua_created',
    'signature_created',
    'seal_created',
    'legal_validity_claimed',
    'source_extracted_text_in_artifact',
    'source_extracted_text_in_ledger_event',
  ]);
  expect(artifact, `${label} must not expose extracted_text`).not.toHaveProperty('extracted_text');
  expect(JSON.stringify(artifact), `${label} must not include raw OCR text`).not.toContain(
    forbiddenRawText,
  );
  return artifact;
}

function assertPaperBookOcrDraftCanonicalDraftResponse(
  obj: unknown,
  label: string,
): PaperBookOcrDraftCanonicalDraftResponse {
  const response = assertExactKeys<PaperBookOcrDraftCanonicalDraftResponse>(
    obj,
    {
      import_id: true,
      draft_id: true,
      act: true,
      draft_act_created: true,
      act_state: true,
      notice: true,
      ocr_text_copied_to_deliberations: true,
      ocr_text_in_ledger_event: true,
      non_canonical: true,
      authoritative_text_claimed: true,
      canonical_conversion_claimed: true,
      canonical_minutes_claimed: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signed_document_created: true,
      archive_package_created: true,
      archive_certification_claimed: true,
      pdfa_created: true,
      pdfua_created: true,
      signature_created: true,
      seal_created: true,
      legal_validity_claimed: true,
      legal_notice: true,
    },
    label,
    ['conversion_execution_artifact'],
  );
  expect(response.import_id.length, `${label}.import_id should be non-empty`).toBeGreaterThan(0);
  expect(response.draft_id.length, `${label}.draft_id should be non-empty`).toBeGreaterThan(0);
  const act = assertPaperBookActView(response.act, `${label}.act`);
  expect(act.state).toBe('Draft');
  expect(response.draft_act_created).toBe(true);
  expect(response.act_state).toBe('Draft');
  expect(response.notice).toContain('No canonical document');
  expect(response.ocr_text_copied_to_deliberations).toBe(true);
  expect(response.non_canonical).toBe(true);
  assertFalseFlags(response, label, [
    'ocr_text_in_ledger_event',
    'authoritative_text_claimed',
    'canonical_conversion_claimed',
    'canonical_minutes_claimed',
    'canonical_act_created',
    'canonical_document_created',
    'signed_document_created',
    'archive_package_created',
    'archive_certification_claimed',
    'pdfa_created',
    'pdfua_created',
    'signature_created',
    'seal_created',
    'legal_validity_claimed',
  ]);
  expect(response.conversion_execution_artifact).toBeTruthy();
  const artifact = assertPaperBookOcrConversionExecutionArtifact(
    response.conversion_execution_artifact,
    `${label}.conversion_execution_artifact`,
  );
  expect(artifact.import_id).toBe(response.import_id);
  expect(artifact.draft_id).toBe(response.draft_id);
  expect(artifact.target_act_id).toBe(act.id);
  return response;
}

function assertPaperBookOcrConversionDossier(
  obj: unknown,
  label: string,
  forbiddenRawText = PAPER_BOOK_CANONICAL_DRAFT_RAW_OCR_TEXT,
): PaperBookOcrConversionDossierView {
  const dossier = assertExactKeys<PaperBookOcrConversionDossierView>(
    obj,
    {
      dossier_id: true,
      import_id: true,
      draft_id: true,
      source_text_digest: true,
      source_page_spans: true,
      source_review_status: true,
      source_reviewed_at: true,
      source_reviewed_by: true,
      created_at: true,
      created_by: true,
      dossier_notice: true,
      metadata_only: true,
      non_canonical: true,
      act_created: true,
      canonical_act_created: true,
      canonical_minutes_claimed: true,
      canonical_document_created: true,
      signed_document_created: true,
      archive_package_created: true,
      pdfa_created: true,
      pdfua_created: true,
      signature_created: true,
      seal_created: true,
      legal_validity_claimed: true,
      source_extracted_text_in_response: true,
      source_extracted_text_in_ledger_event: true,
      legal_notice: true,
    },
    label,
    ['conversion_execution_artifacts', 'archive_certification_claimed'],
  );
  expect(dossier.dossier_id.length, `${label}.dossier_id should be non-empty`).toBeGreaterThan(0);
  expect(dossier.import_id.length, `${label}.import_id should be non-empty`).toBeGreaterThan(0);
  expect(dossier.draft_id.length, `${label}.draft_id should be non-empty`).toBeGreaterThan(0);
  if (dossier.source_text_digest !== null) {
    assertHex64(dossier.source_text_digest, `${label}.source_text_digest`);
  }
  assertPaperBookSourcePageSpans(dossier.source_page_spans, `${label}.source_page_spans`);
  inEnum(PAPER_BOOK_OCR_DRAFT_REVIEW_STATUSES, dossier.source_review_status, `${label}.status`);
  if (dossier.source_reviewed_at !== null) {
    assertTimestamp(dossier.source_reviewed_at, `${label}.source_reviewed_at`);
  }
  assertTimestamp(dossier.created_at, `${label}.created_at`);
  expect(dossier.created_by.length, `${label}.created_by should be non-empty`).toBeGreaterThan(0);
  expect(dossier.dossier_notice).toContain('metadata-only');
  expect(dossier.dossier_notice).toContain('PDF/UA');
  expect(dossier.metadata_only).toBe(true);
  expect(dossier.non_canonical).toBe(true);
  assertFalseFlags(dossier, label, [
    'act_created',
    'canonical_act_created',
    'canonical_minutes_claimed',
    'canonical_document_created',
    'signed_document_created',
    'archive_package_created',
    'archive_certification_claimed',
    'pdfa_created',
    'pdfua_created',
    'signature_created',
    'seal_created',
    'legal_validity_claimed',
    'source_extracted_text_in_response',
    'source_extracted_text_in_ledger_event',
  ]);
  expect(dossier, `${label} must not expose extracted_text`).not.toHaveProperty('extracted_text');
  expect(JSON.stringify(dossier), `${label} must not include raw OCR text`).not.toContain(
    forbiddenRawText,
  );
  expect(Array.isArray(dossier.conversion_execution_artifacts)).toBe(true);
  expect(dossier.conversion_execution_artifacts?.length).toBeGreaterThan(0);
  for (const artifact of dossier.conversion_execution_artifacts ?? []) {
    const item = assertPaperBookOcrConversionExecutionArtifact(
      artifact,
      `${label}.conversion_execution_artifacts[]`,
      forbiddenRawText,
    );
    expect(item.import_id).toBe(dossier.import_id);
    expect(item.draft_id).toBe(dossier.draft_id);
    expect(item.dossier_id).toBe(dossier.dossier_id);
  }
  return dossier;
}

function assertPaperBookOcrRun(obj: unknown, label: string): PaperBookOcrRunView {
  const result = assertExactKeys<PaperBookOcrRunView>(
    obj,
    {
      import_id: true,
      previous_ocr_status: true,
      ocr_status: true,
      command_configured: true,
      command_exit_success: true,
      command_exit_code: true,
      timed_out: true,
      failure_reason: true,
      stdout_bytes_captured: true,
      stdout_truncated: true,
      engine: true,
      draft: true,
      status_notice: true,
      draft_notice: true,
      non_canonical: true,
      authoritative_text_claimed: true,
      canonical_minutes_claimed: true,
      canonical_act_created: true,
      canonical_document_created: true,
      signature_created: true,
      legal_validity_claimed: true,
      legal_notice: true,
    },
    label,
  );
  expect(result.import_id.length, `${label}.import_id should be non-empty`).toBeGreaterThan(0);
  expect(result.previous_ocr_status).toBe('not_run');
  expect(result.ocr_status).toBe('completed');
  expect(result.command_configured).toBe(true);
  expect(result.command_exit_success).toBe(true);
  expect(result.command_exit_code).toBe(0);
  expect(result.timed_out).toBe(false);
  expect(result.failure_reason).toBeNull();
  expect(result.stdout_bytes_captured).toBeGreaterThan(0);
  const engine = assertExactKeys<PaperBookOcrEngineView>(
    result.engine,
    { name: true, version: true },
    `${label}.engine`,
  );
  expect(engine.name.length, `${label}.engine.name should be non-empty`).toBeGreaterThan(0);
  expect(result.draft_notice).toContain('non-authoritative');
  expect(result.draft_notice).toContain('not canonical minutes');
  expect(result.non_canonical).toBe(true);
  expect(result.authoritative_text_claimed).toBe(false);
  expect(result.canonical_minutes_claimed).toBe(false);
  expect(result.canonical_act_created).toBe(false);
  expect(result.canonical_document_created).toBe(false);
  expect(result.signature_created).toBe(false);
  expect(result.legal_validity_claimed).toBe(false);
  expect(result.draft).not.toBeNull();
  assertPaperBookOcrDraft(result.draft, `${label}.draft`);
  expect(JSON.stringify(result)).not.toContain('canonical_act_created":true');
  expect(JSON.stringify(result)).not.toContain('canonical_document_created":true');
  expect(JSON.stringify(result)).not.toContain('signature_created":true');
  expect(JSON.stringify(result)).not.toContain('legal_validity_claimed":true');
  return result;
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
      ['required_signatory_records_abertura', 'required_signatory_records_encerramento'],
    );
    inEnum(BOOK_KINDS, book.kind, 'BookView.kind');
    inEnum(['Created', 'Open', 'Closed'], book.state, 'BookView.state');
    if (book.numbering_scheme) inEnum(NUMBERING_SCHEMES, book.numbering_scheme, 'numbering_scheme');
    if (book.opening_date) assertIsoDate(book.opening_date, 'BookView.opening_date');
    expect(typeof book.last_ata_number).toBe('number');
    expect(Array.isArray(book.required_signatories_abertura)).toBe(true);
    expect(Array.isArray(book.required_signatory_records_abertura)).toBe(true);
    expect(book.required_signatory_records_abertura?.[0]).toMatchObject({
      name: expect.any(String),
      capacity: null,
      email: null,
    });
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
        ['manual_signature_original_reference'],
      );
      expect(sealMetadata.rule_pack_id.length).toBeGreaterThan(0);
      expect(sealMetadata.version.length).toBeGreaterThan(0);
      inEnum(
        ['CommercialCompany', 'Condominium', 'Association', 'Foundation', 'Cooperative'],
        sealMetadata.family,
        'ActView.seal_metadata.family',
      );
      inEnum(ENTITY_KINDS, sealMetadata.profile, 'ActView.seal_metadata.profile');
      if (sealMetadata.manual_signature_original_reference) {
        const reference = assertExactKeys<ActManualSignatureOriginalReference>(
          sealMetadata.manual_signature_original_reference,
          { storage_reference: true },
          'ActView.seal_metadata.manual_signature_original_reference',
          ['custodian', 'note'],
        );
        expect(reference.storage_reference.trim().length).toBeGreaterThan(0);
      }
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
        evidence_family: true,
        classification: true,
        imported_at: true,
        imported_by: true,
        operator_review_status: true,
        operator_reviewed_at: true,
        operator_reviewed_by: true,
        operator_review_note: true,
        acknowledged_guardrail_ids: true,
        operator_review_notice: true,
        review_history: true,
        non_canonical: true,
        requires_ocr_review: true,
        canonical_record_status: true,
        signed_artifact_status: true,
        review_guardrail_checklist: true,
        canonical_conversion_status: true,
        canonical_conversion_performed: true,
        canonical_conversion_preflight: true,
        legal_acceptance_claimed: true,
        preservation_policy: true,
        legal_notice: true,
        bytes_download: true,
      },
      'ImportedDocumentView',
    );
    assertHex64(doc.sha256, 'ImportedDocumentView.sha256');
    assertTimestamp(doc.imported_at, 'ImportedDocumentView.imported_at');
    expect(doc.detected_content_type).toBe('image/png');
    expect(doc.evidence_family).toBe('image');
    expect(doc.canonical_conversion_preflight.status).toBe('not_attempted');
    expect(doc.canonical_conversion_preflight.canonical_conversion_performed).toBe(false);
    expect(doc.canonical_conversion_preflight.canonical_pdfa_generated).toBe(false);
    expect(doc.canonical_conversion_preflight.external_provider_contacted).toBe(false);
    expect(doc.classification).toBe('image_non_canonical_evidence');
    expect(doc.non_canonical).toBe(true);
    expect(doc.operator_review_status).toBe('reviewed_non_canonical_original_only');
    expect(doc.operator_review_note).toContain('non-canonical technical evidence');
    expect(doc.acknowledged_guardrail_ids).toContain(
      'preserved_original_bytes_remain_non_canonical_evidence',
    );
    expect(doc.review_history).toHaveLength(2);
    expect(doc.review_history?.map((entry) => entry.decision_index)).toEqual([1, 2]);
    expect(doc.review_history?.map((entry) => entry.review_status)).toEqual([
      'rejected_non_canonical_evidence',
      'reviewed_non_canonical_original_only',
    ]);
    expect(doc.review_history?.[0].review_note).toContain('retained for audit');
    expect(doc.review_history?.[1].review_note).toContain('technical evidence only');
    for (const entry of doc.review_history ?? []) {
      expect(entry.acknowledged_guardrail_ids).toContain('canonical_pdfa_record_is_not_replaced');
      expect(entry.bytes_in_payload).toBe(false);
      expect(entry.ocr_performed).toBe(false);
      expect(entry.canonical_conversion_performed).toBe(false);
      expect(entry.canonical_pdfa_generated).toBe(false);
      expect(entry.signed_artifact_created_or_validated).toBe(false);
      expect(entry.legal_acceptance_claimed).toBe(false);
      expect(entry.certification_claimed).toBe(false);
    }
    expect(doc.canonical_record_status).toBe('not_canonical_record');
    expect(doc.signed_artifact_status).toBe('not_signed_artifact');
    expect(doc.canonical_conversion_performed).toBe(false);
    expect(doc.legal_acceptance_claimed).toBe(false);
    expect(doc.preservation_policy?.legal_acceptance_claimed).toBe(false);
    expect(doc.bytes_download).toContain(`/v1/documents/imported/${doc.id}/bytes`);
    expect(JSON.stringify(doc)).not.toContain('%PDF');
    expect(JSON.stringify(doc)).not.toContain('access_code');
    expect(JSON.stringify(doc)).not.toContain('legal_validity_claimed":true');
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

  it('paper-book.ocr-draft.json → PaperBookOcrDraftView (POST /v1/books/paper-import/{id}/ocr-drafts)', async () => {
    stubFetch(fixture('paper-book.ocr-draft.json'), 201);
    const draft: PaperBookOcrDraftView = await api.createPaperBookImportOcrDraft(
      '11111111-1111-4111-8111-111111111111',
      {
        extracted_text: 'Livro de atas digitalizado.',
        text_digest: 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
        page_spans: [{ start_page: 1, end_page: 2 }],
        confidence: 0.87,
        engine_name: 'operator-supplied-ocr',
        engine_version: '1.0',
      },
    );
    assertPaperBookOcrDraft(draft, 'PaperBookOcrDraftView');
    expect(draft.legal_notice).toContain('non-canonical evidence only');
    expect(JSON.stringify(draft)).not.toContain('signature_created":true');
    expect(JSON.stringify(draft)).not.toContain('legal_validity_claimed":true');
  });

  it('paper-book.ocr-run.json → PaperBookOcrRunView (POST /v1/books/paper-import/{id}/ocr/run)', async () => {
    stubFetch(fixture('paper-book.ocr-run.json'));
    const result: PaperBookOcrRunView = await api.runPaperBookImportOcr(
      '11111111-1111-4111-8111-111111111111',
    );
    assertPaperBookOcrRun(result, 'PaperBookOcrRunView');
  });

  it('paper-book.ocr-canonical-draft.json → PaperBookOcrDraftCanonicalDraftResponse (POST /v1/books/paper-import/{id}/ocr-drafts/{draft_id}/canonical-draft)', async () => {
    stubFetch(fixture('paper-book.ocr-canonical-draft.json'), 201);
    const response: PaperBookOcrDraftCanonicalDraftResponse =
      await api.createPaperBookOcrDraftActDraft(
        '11111111-1111-4111-8111-111111111111',
        '33333333-3333-4333-8333-333333333333',
      );
    assertPaperBookOcrDraftCanonicalDraftResponse(
      response,
      'PaperBookOcrDraftCanonicalDraftResponse',
    );
  });

  it('paper-book.ocr-conversion-dossier.json → PaperBookOcrConversionDossierView (POST/GET conversion dossier)', async () => {
    const dossierFixture = fixture('paper-book.ocr-conversion-dossier.json');
    stubFetch(dossierFixture, 201);
    const created: PaperBookOcrConversionDossierView =
      await api.createPaperBookOcrConversionDossier(
        '11111111-1111-4111-8111-111111111111',
        '33333333-3333-4333-8333-333333333333',
      );
    assertPaperBookOcrConversionDossier(created, 'PaperBookOcrConversionDossierView');

    stubFetch(`[${dossierFixture}]`);
    const listed: PaperBookOcrConversionDossierView[] =
      await api.listPaperBookOcrConversionDossiers('11111111-1111-4111-8111-111111111111');
    expect(listed.length).toBe(1);
    assertPaperBookOcrConversionDossier(listed[0], 'PaperBookOcrConversionDossierView[]');
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
    expect(dash.reminders.length).toBeGreaterThan(0);
    for (const [index, candidate] of dash.reminders.entries()) {
      const label = `Dashboard.reminders[${index}]`;
      const reminder = assertExactKeys<DashboardReminder>(
        candidate,
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
        label,
        ['params', 'law_refs', 'action', 'recommended_next_steps', 'i18n'],
      );
      if (reminder.due_date !== '') {
        assertIsoDate(reminder.due_date, `${label}.due_date`);
      }
      inEnum(['Advisory', 'Info', 'Warning'], reminder.severity, `${label}.severity`);
      inEnum(['Upcoming', 'DueSoon', 'Overdue', 'Pending'], reminder.status, `${label}.status`);
      expect(reminder.reason.length, `${label}.reason should be non-empty`).toBeGreaterThan(0);
      expect(reminder.entity_id.length, `${label}.entity_id should be non-empty`).toBeGreaterThan(
        0,
      );
      expect(
        reminder.entity_name.length,
        `${label}.entity_name should be non-empty`,
      ).toBeGreaterThan(0);
      expect(
        reminder.source_rule.length,
        `${label}.source_rule should be non-empty`,
      ).toBeGreaterThan(0);
      expect(
        reminder.source_profile.length,
        `${label}.source_profile should be non-empty`,
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
          `${label}.law_refs[0]`,
        );
      }
      if (reminder.action !== null && reminder.action !== undefined) {
        assertExactKeys<DashboardAction>(
          reminder.action,
          { kind: true, label_key: true, api_href: true, route: true },
          `${label}.action`,
        );
      }
      expect(Array.isArray(reminder.recommended_next_steps)).toBe(true);
      if (reminder.params !== undefined) {
        expect(typeof reminder.params, `${label}.params`).toBe('object');
        for (const [key, value] of Object.entries(reminder.params)) {
          expect(key.length, `${label}.params key should be non-empty`).toBeGreaterThan(0);
          expect(typeof value, `${label}.params.${key} should be string`).toBe('string');
        }
      }
      if (reminder.i18n !== null && reminder.i18n !== undefined) {
        const reminderI18n = assertExactKeys<DashboardI18n>(
          reminder.i18n,
          { title_key: true, body_key: true, action_key: true },
          `${label}.i18n`,
        );
        expect(reminderI18n.title_key.length).toBeGreaterThan(0);
        expect(reminderI18n.body_key.length).toBeGreaterThan(0);
      }
    }
    expect(
      dash.reminders.some(
        (reminder) =>
          reminder.source_rule === 'absent-owner-dispatch-evidence' &&
          reminder.due_date === '' &&
          reminder.status === 'Pending',
      ),
      'Dashboard.reminders should include a pending no-due-date generated absent-owner fixture',
    ).toBe(true);
    expect(
      dash.reminders.some(
        (reminder) =>
          reminder.source_rule === 'csc-art376-annual' &&
          reminder.source_profile === 'csc-commercial' &&
          reminder.due_date === '2026-03-31' &&
          reminder.params?.calendar_preset_support === 'supported' &&
          reminder.params?.preset_id === 'csc-art376-annual' &&
          reminder.params?.local_due_date_rule_configured === 'true' &&
          reminder.params?.local_due_date_calculated === 'true' &&
          reminder.params?.legal_deadline_calculated === 'true' &&
          reminder.params?.months_after_fiscal_year_end === '3' &&
          reminder.params?.fiscal_year_end === '12-31' &&
          reminder.params?.due_year === '2026' &&
          reminder.params?.due_basis === 'default_fiscal_year_end_missing_recorded_value' &&
          reminder.params?.local_advisory_only === 'true' &&
          reminder.params?.legal_calendar_authority_claimed === 'false' &&
          reminder.params?.external_delivery_claimed === 'false' &&
          reminder.params?.external_calendar_sync_claimed === 'false' &&
          reminder.params?.webhook_delivery_claimed === 'false' &&
          reminder.params?.workflow_completion_claimed === 'false' &&
          reminder.params?.compliance_status_claimed === 'false',
      ),
      'Dashboard.reminders should include supported profile-calendar local coverage metadata',
    ).toBe(true);
    expect(
      dash.reminders.some(
        (reminder) =>
          reminder.source_rule === 'condominio-annual' &&
          reminder.source_profile === 'condominio-dl268' &&
          reminder.due_date === '' &&
          reminder.status === 'Pending' &&
          reminder.params?.calendar_preset_support === 'unsupported' &&
          reminder.params?.local_due_date_rule_configured === 'false' &&
          reminder.params?.local_due_date_calculated === 'false' &&
          reminder.params?.legal_deadline_calculated === 'false' &&
          reminder.params?.legal_calendar_authority_claimed === 'false' &&
          reminder.params?.external_delivery_claimed === 'false' &&
          reminder.params?.external_calendar_sync_claimed === 'false' &&
          reminder.params?.webhook_delivery_claimed === 'false' &&
          reminder.params?.workflow_completion_claimed === 'false' &&
          reminder.params?.compliance_status_claimed === 'false' &&
          reminder.params?.unsupported_reason === 'missing_local_due_date_rule' &&
          reminder.params?.due_year === undefined &&
          reminder.params?.due_basis === undefined &&
          reminder.reason.includes('does not calculate a legal deadline'),
      ),
      'Dashboard.reminders should include a pending no-due-date unsupported profile-calendar advisory',
    ).toBe(true);
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
        workflow: true,
        data_management: true,
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
        tsl_sources: true,
        tsa_providers: true,
        require_qualified_for_seal: true,
        cmd: true,
        providers: true,
      },
      'Settings.signing',
    );
    inEnum(SIGNATURE_FAMILIES, signing.preferred_family, 'signing.preferred_family');
    expect(typeof signing.require_qualified_for_seal).toBe('boolean');
    expect(Array.isArray(signing.tsl_sources)).toBe(true);
    for (const source of signing.tsl_sources) {
      const row = assertExactKeys<TslSourceSettings>(
        source,
        {
          id: true,
          name: true,
          enabled: true,
          url: true,
          path: true,
          country: true,
          scheme: true,
          digest: true,
          timeout_seconds: true,
          max_bytes: true,
          refresh: true,
        },
        'Settings.signing.tsl_sources[]',
      );
      expect(typeof row.id).toBe('string');
      expect(typeof row.name).toBe('string');
      expect(typeof row.enabled).toBe('boolean');
      if (row.url !== null) expect(typeof row.url).toBe('string');
      if (row.path !== null) expect(typeof row.path).toBe('string');
      if (row.country !== null) expect(typeof row.country).toBe('string');
      if (row.scheme !== null) expect(typeof row.scheme).toBe('string');
      if (row.digest !== null) expect(typeof row.digest).toBe('string');
      expect(typeof row.timeout_seconds).toBe('number');
      expect(typeof row.max_bytes).toBe('number');
      const refresh = assertExactKeys<TrustRefreshSettings>(
        row.refresh,
        { enabled: true, cadence: true },
        'Settings.signing.tsl_sources[].refresh',
      );
      expect(typeof refresh.enabled).toBe('boolean');
      const cadence = assertExactKeys<TrustRefreshCadence>(
        refresh.cadence,
        { kind: true },
        'Settings.signing.tsl_sources[].refresh.cadence',
        ['hours', 'hour_utc'],
      );
      inEnum(
        ['manual', 'interval_hours', 'daily'],
        cadence.kind,
        'tsl_sources[].refresh.cadence.kind',
      );
      if (cadence.kind === 'interval_hours') expect(typeof cadence.hours).toBe('number');
      if (cadence.kind === 'daily') expect(typeof cadence.hour_utc).toBe('number');
    }
    expect(Array.isArray(signing.tsa_providers)).toBe(true);
    for (const provider of signing.tsa_providers) {
      const row = assertExactKeys<TsaProviderSettings>(
        provider,
        {
          id: true,
          name: true,
          enabled: true,
          url: true,
          path: true,
          default: true,
          policy: true,
          digest: true,
          timeout_seconds: true,
          max_bytes: true,
        },
        'Settings.signing.tsa_providers[]',
      );
      expect(typeof row.id).toBe('string');
      expect(typeof row.name).toBe('string');
      expect(typeof row.enabled).toBe('boolean');
      if (row.url !== null) expect(typeof row.url).toBe('string');
      if (row.path !== null) expect(typeof row.path).toBe('string');
      expect(typeof row.default).toBe('boolean');
      if (row.policy !== null) expect(typeof row.policy).toBe('string');
      expect(typeof row.digest).toBe('string');
      expect(typeof row.timeout_seconds).toBe('number');
      expect(typeof row.max_bytes).toBe('number');
    }
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
    const workflow = assertExactKeys<WorkflowSettings>(
      settings.workflow,
      { reminders: true },
      'Settings.workflow',
    );
    const reminders = assertExactKeys<WorkflowReminderSettings>(
      workflow.reminders,
      {
        enabled: true,
        dashboard_limit: true,
        due_soon_days: true,
        attendance_lookahead_days: true,
        sources: true,
      },
      'Settings.workflow.reminders',
    );
    expect(typeof reminders.enabled, 'Settings.workflow.reminders.enabled').toBe('boolean');
    expect(
      Number.isInteger(reminders.dashboard_limit),
      'Settings.workflow.reminders.dashboard_limit should be an integer',
    ).toBe(true);
    expect(reminders.dashboard_limit).toBeGreaterThanOrEqual(0);
    expect(reminders.dashboard_limit).toBeLessThanOrEqual(50);
    expect(
      Number.isInteger(reminders.due_soon_days),
      'Settings.workflow.reminders.due_soon_days should be an integer',
    ).toBe(true);
    expect(reminders.due_soon_days).toBeGreaterThanOrEqual(0);
    expect(reminders.due_soon_days).toBeLessThanOrEqual(365);
    expect(
      Number.isInteger(reminders.attendance_lookahead_days),
      'Settings.workflow.reminders.attendance_lookahead_days should be an integer',
    ).toBe(true);
    expect(reminders.attendance_lookahead_days).toBeGreaterThanOrEqual(0);
    expect(reminders.attendance_lookahead_days).toBeLessThanOrEqual(365);
    const sources = assertExactKeys<WorkflowReminderSourceSettings>(
      reminders.sources,
      {
        profile_calendar: true,
        act_follow_ups: true,
        attendance_hygiene: true,
        privacy_control_reviews: true,
      },
      'Settings.workflow.reminders.sources',
    );
    expect(typeof sources.profile_calendar).toBe('boolean');
    expect(typeof sources.act_follow_ups).toBe('boolean');
    expect(typeof sources.attendance_hygiene).toBe('boolean');
    expect(typeof sources.privacy_control_reviews).toBe('boolean');
    const dataManagement = assertExactKeys<DataManagementSettings>(
      settings.data_management,
      { retained_export_cleanup: true, backup_recovery: true },
      'Settings.data_management',
    );
    const retainedExportCleanup = assertExactKeys<RetainedExportCleanupSettings>(
      dataManagement.retained_export_cleanup,
      {
        minimum_age_days: true,
        keep_latest: true,
      },
      'Settings.data_management.retained_export_cleanup',
    );
    expect(
      Number.isInteger(retainedExportCleanup.minimum_age_days),
      'Settings.data_management.retained_export_cleanup.minimum_age_days should be an integer',
    ).toBe(true);
    expect(retainedExportCleanup.minimum_age_days).toBeGreaterThanOrEqual(0);
    expect(retainedExportCleanup.minimum_age_days).toBeLessThanOrEqual(3650);
    expect(
      Number.isInteger(retainedExportCleanup.keep_latest),
      'Settings.data_management.retained_export_cleanup.keep_latest should be an integer',
    ).toBe(true);
    expect(retainedExportCleanup.keep_latest).toBeGreaterThanOrEqual(0);
    expect(retainedExportCleanup.keep_latest).toBeLessThanOrEqual(100);
    const backupRecovery = assertExactKeys<BackupRecoveryPolicySettings>(
      dataManagement.backup_recovery,
      {
        max_drill_age_days: true,
        target_rpo_minutes: true,
        target_rto_minutes: true,
      },
      'Settings.data_management.backup_recovery',
    );
    expect(
      Number.isInteger(backupRecovery.max_drill_age_days),
      'Settings.data_management.backup_recovery.max_drill_age_days should be an integer',
    ).toBe(true);
    expect(backupRecovery.max_drill_age_days).toBeGreaterThanOrEqual(1);
    expect(backupRecovery.max_drill_age_days).toBeLessThanOrEqual(3650);
    expect(
      Number.isInteger(backupRecovery.target_rpo_minutes),
      'Settings.data_management.backup_recovery.target_rpo_minutes should be an integer',
    ).toBe(true);
    expect(backupRecovery.target_rpo_minutes).toBeGreaterThanOrEqual(1);
    expect(backupRecovery.target_rpo_minutes).toBeLessThanOrEqual(525600);
    expect(
      Number.isInteger(backupRecovery.target_rto_minutes),
      'Settings.data_management.backup_recovery.target_rto_minutes should be an integer',
    ).toBe(true);
    expect(backupRecovery.target_rto_minutes).toBeGreaterThanOrEqual(1);
    expect(backupRecovery.target_rto_minutes).toBeLessThanOrEqual(525600);
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

  it('platform.logs.json → PlatformLogsResponse (GET /v1/platform/logs)', async () => {
    stubFetch(fixture('platform.logs.json'));
    const response: PlatformLogsResponse = await api.listPlatformLogs({
      service_id: 'api',
      level: 'info',
      tail: 5,
    });
    const parsed = assertExactKeys<PlatformLogsResponse>(
      response,
      { logs: true, tail: true, order: true, retention: true, limitations: true },
      'PlatformLogsResponse',
    );
    expect(parsed.tail).toBe(5);
    expect(parsed.order).toBe('chronological');
    expect(Array.isArray(parsed.logs), 'PlatformLogsResponse.logs should be an array').toBe(true);
    expect(
      Array.isArray(parsed.limitations),
      'PlatformLogsResponse.limitations should be an array',
    ).toBe(true);
    expect(parsed.limitations.length).toBeGreaterThan(0);
    const retention = assertPlatformLogRetentionMetadata(
      parsed.retention,
      'PlatformLogsResponse.retention',
    );
    expect(retention).toMatchObject({
      retention_limit: 512,
      retained_count: 2,
      oldest_seq: 1,
      newest_seq: 2,
      dropped_before_seq: null,
      durable: false,
      basis: 'memory',
      source: 'process_memory',
    });
    const first = assertPlatformLogEntry(parsed.logs[0], 'PlatformLogsResponse.logs[0]');
    expect(first.context).toEqual({ service_count: 2 });
    const second = assertPlatformLogEntry(parsed.logs[1], 'PlatformLogsResponse.logs[1]');
    expect(second).not.toHaveProperty('context');
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

  it('backup.recovery-drill.json → BackupRecoveryDrillReceipt (POST /v1/backup/recovery-drills)', async () => {
    stubFetch(fixture('backup.recovery-drill.json'), 201);
    const receipt: BackupRecoveryDrillReceipt = await api.createBackupRecoveryDrill({
      archive: 'chancela-backup-20260710T103000Z.zip',
      passphrase: 'transient-test-key',
    });
    assertExactKeys<BackupRecoveryDrillReceipt>(
      receipt,
      {
        id: true,
        created_at: true,
        archive: true,
        preflight_ok: true,
        preflight_ready: true,
        encrypted: true,
        ledger_verified: true,
        manifest: true,
        isolated_restore_verified: true,
        isolated_restore_verification: true,
        restore_executed: true,
        live_db_swapped: true,
        sidecars_staged: true,
        ledger_restored_appended: true,
        data_deleted: true,
        offsite_custody_proven: true,
        legal_archive_certified: true,
      },
      'BackupRecoveryDrillReceipt',
      ['operator_notes', 'custody_location'],
    );
    expect(receipt.id).not.toHaveLength(0);
    assertTimestamp(receipt.created_at, 'BackupRecoveryDrillReceipt.created_at');
    expect(receipt.archive).not.toHaveLength(0);
    expect(typeof receipt.preflight_ok).toBe('boolean');
    expect(typeof receipt.preflight_ready).toBe('boolean');
    if (receipt.encrypted !== null) expect(typeof receipt.encrypted).toBe('boolean');
    expect(typeof receipt.ledger_verified).toBe('boolean');
    expect(receipt.isolated_restore_verified).toBe(true);
    const evidence = assertExactKeys<BackupRecoveryDrillManifestEvidence>(
      receipt.manifest,
      {
        schema: true,
        version: true,
        store_schema_version: true,
        ledger_length: true,
        ledger_verified: true,
        member_count: true,
        sidecar_member_count: true,
        db_member_present: true,
        total_member_bytes: true,
      },
      'BackupRecoveryDrillReceipt.manifest',
    );
    expect(evidence.schema).toBe('chancela-backup-manifest/v1');
    expect(typeof evidence.version).toBe('number');
    expect(typeof evidence.store_schema_version).toBe('number');
    expect(typeof evidence.ledger_length).toBe('number');
    expect(typeof evidence.ledger_verified).toBe('boolean');
    expect(typeof evidence.member_count).toBe('number');
    expect(typeof evidence.sidecar_member_count).toBe('number');
    expect(typeof evidence.db_member_present).toBe('boolean');
    expect(typeof evidence.total_member_bytes).toBe('number');
    const isolated = assertExactKeys<BackupRecoveryDrillIsolatedRestoreVerification>(
      receipt.isolated_restore_verification,
      {
        status: true,
        db_snapshot_materialized: true,
        db_snapshot_opened: true,
        state_loaded: true,
        ledger_verified: true,
        cleanup_verified: true,
        entity_count: true,
        book_count: true,
        act_count: true,
        sidecar_root_count: true,
        sidecar_materialized_file_count: true,
        sidecar_materialized_bytes: true,
        sqlcipher_encryption_verified: true,
        findings: true,
        errors: true,
        next_step: true,
      },
      'BackupRecoveryDrillReceipt.isolated_restore_verification',
    );
    expect(isolated.status).toBe('verified');
    expect(isolated.db_snapshot_materialized).toBe(true);
    expect(isolated.db_snapshot_opened).toBe(true);
    expect(isolated.state_loaded).toBe(true);
    expect(isolated.ledger_verified).toBe(true);
    expect(isolated.cleanup_verified).toBe(true);
    expect(typeof isolated.entity_count).toBe('number');
    expect(typeof isolated.book_count).toBe('number');
    expect(typeof isolated.act_count).toBe('number');
    expect(typeof isolated.sidecar_root_count).toBe('number');
    expect(typeof isolated.sidecar_materialized_file_count).toBe('number');
    expect(typeof isolated.sidecar_materialized_bytes).toBe('number');
    if (isolated.sqlcipher_encryption_verified !== null) {
      expect(typeof isolated.sqlcipher_encryption_verified).toBe('boolean');
    }
    expect(isolated.findings).toContain(
      'isolated database snapshot was materialized, opened, and loaded',
    );
    expect(isolated.findings).toContain('isolated snapshot ledger verified');
    expect(isolated.errors).toEqual([]);
    expect(isolated.next_step).toContain('preflight-only isolated snapshot evidence');
    expect(receipt.restore_executed).toBe(false);
    expect(receipt.live_db_swapped).toBe(false);
    expect(receipt.sidecars_staged).toBe(false);
    expect(receipt.ledger_restored_appended).toBe(false);
    expect(receipt.data_deleted).toBe(false);
    expect(receipt.offsite_custody_proven).toBe(false);
    expect(receipt.legal_archive_certified).toBe(false);
  });

  it('backup.recovery-drill-list.json → BackupRecoveryDrillList (GET /v1/backup/recovery-drills)', async () => {
    stubFetch(fixture('backup.recovery-drill-list.json'));
    const list: BackupRecoveryDrillList = await api.listBackupRecoveryDrills();
    assertExactKeys<BackupRecoveryDrillList>(
      list,
      {
        receipts: true,
        durable: true,
        max_receipts: true,
        freshness: true,
      },
      'BackupRecoveryDrillList',
    );
    expect(Array.isArray(list.receipts)).toBe(true);
    expect(list.receipts.length).toBeGreaterThan(0);
    expect(typeof list.durable).toBe('boolean');
    expect(typeof list.max_receipts).toBe('number');
    const freshness = assertExactKeys<BackupRecoveryFreshnessReview>(
      list.freshness,
      {
        generated_at: true,
        policy: true,
        status: true,
        latest_receipt_id: true,
        latest_receipt_at: true,
        latest_receipt_age_days: true,
        latest_receipt_preflight_ready: true,
        latest_receipt_isolated_restore_verified: true,
        restore_performed: true,
        db_swap_performed: true,
        offsite_custody_verified: true,
        rpo_rto_certified: true,
        production_backup_policy_certified: true,
      },
      'BackupRecoveryDrillList.freshness',
    );
    assertTimestamp(freshness.generated_at, 'BackupRecoveryDrillList.freshness.generated_at');
    expect(['no_receipt', 'fresh', 'stale', 'failed']).toContain(freshness.status);
    const policy = assertExactKeys<BackupRecoveryPolicySettings>(
      freshness.policy,
      {
        max_drill_age_days: true,
        target_rpo_minutes: true,
        target_rto_minutes: true,
      },
      'BackupRecoveryDrillList.freshness.policy',
    );
    expect(policy.max_drill_age_days).toBeGreaterThanOrEqual(1);
    expect(policy.target_rpo_minutes).toBeGreaterThanOrEqual(1);
    expect(policy.target_rto_minutes).toBeGreaterThanOrEqual(1);
    if (freshness.latest_receipt_at !== null) {
      assertTimestamp(freshness.latest_receipt_at, 'BackupRecoveryDrillList.latest_receipt_at');
    }
    if (freshness.latest_receipt_age_days !== null) {
      expect(freshness.latest_receipt_age_days).toBeGreaterThanOrEqual(0);
    }
    if (freshness.latest_receipt_preflight_ready !== null) {
      expect(typeof freshness.latest_receipt_preflight_ready).toBe('boolean');
    }
    if (freshness.latest_receipt_isolated_restore_verified !== null) {
      expect(typeof freshness.latest_receipt_isolated_restore_verified).toBe('boolean');
    }
    expect(freshness.restore_performed).toBe(false);
    expect(freshness.db_swap_performed).toBe(false);
    expect(freshness.offsite_custody_verified).toBe(false);
    expect(freshness.rpo_rto_certified).toBe(false);
    expect(freshness.production_backup_policy_certified).toBe(false);
  });

  it('data.status.json → DataStatusResponse (GET /v1/data/status)', async () => {
    stubFetch(fixture('data.status.json'));
    const status: DataStatusResponse = await api.dataStatus();
    assertExactKeys<DataStatusResponse>(
      status,
      {
        generated_at: true,
        persistence: true,
        data_dir: true,
        permissions: true,
        usage: true,
      },
      'DataStatusResponse',
    );
    assertTimestamp(status.generated_at, 'DataStatusResponse.generated_at');

    const persistence = assertExactKeys<DataPersistenceStatus>(
      status.persistence,
      {
        mode: true,
        data_dir_configured: true,
        durable_store_open: true,
        database_encryption_configured: true,
        store_schema_version: true,
        ledger_length: true,
        ledger_verified: true,
        degraded: true,
      },
      'DataStatusResponse.persistence',
    );
    inEnum(DATA_PERSISTENCE_MODES, persistence.mode, 'DataStatusResponse.persistence.mode');
    expect(typeof persistence.data_dir_configured).toBe('boolean');
    expect(typeof persistence.durable_store_open).toBe('boolean');
    expect(typeof persistence.database_encryption_configured).toBe('boolean');
    if (persistence.store_schema_version !== null) {
      expect(Number.isInteger(persistence.store_schema_version)).toBe(true);
    }
    expect(Number.isInteger(persistence.ledger_length)).toBe(true);
    if (persistence.ledger_verified !== null) {
      expect(typeof persistence.ledger_verified).toBe('boolean');
    }
    expect(typeof persistence.degraded).toBe('boolean');

    const dataDir = assertExactKeys<DataDirStatus>(
      status.data_dir,
      { path: true, exists: true, is_directory: true },
      'DataStatusResponse.data_dir',
    );
    if (dataDir.path !== null) expect(dataDir.path.length).toBeGreaterThan(0);
    if (dataDir.exists !== null) expect(typeof dataDir.exists).toBe('boolean');
    if (dataDir.is_directory !== null) expect(typeof dataDir.is_directory).toBe('boolean');

    const permissions = assertExactKeys<DataPermissionStatus>(
      status.permissions,
      {
        read_dir: true,
        create_file: true,
        write_file: true,
        delete_probe_file: true,
        sqlite_store_open: true,
      },
      'DataStatusResponse.permissions',
    );
    assertDataPermissionCheck(permissions.read_dir, 'DataStatusResponse.permissions.read_dir');
    assertDataPermissionCheck(
      permissions.create_file,
      'DataStatusResponse.permissions.create_file',
    );
    assertDataPermissionCheck(permissions.write_file, 'DataStatusResponse.permissions.write_file');
    assertDataPermissionCheck(
      permissions.delete_probe_file,
      'DataStatusResponse.permissions.delete_probe_file',
    );
    assertDataPermissionCheck(
      permissions.sqlite_store_open,
      'DataStatusResponse.permissions.sqlite_store_open',
    );

    const usage = assertExactKeys<DataUsageStatus>(
      status.usage,
      { total_bytes: true, filesystem: true, sqlite_logical: true, scan_errors: true },
      'DataStatusResponse.usage',
      ['sqlite_largest_payload_table'],
    );
    expect(Number.isInteger(usage.total_bytes), 'usage.total_bytes integer').toBe(true);
    expect(usage.total_bytes, 'usage.total_bytes non-negative').toBeGreaterThanOrEqual(0);
    expect(Array.isArray(usage.filesystem)).toBe(true);
    expect(Array.isArray(usage.sqlite_logical)).toBe(true);
    expect(Array.isArray(usage.scan_errors)).toBe(true);
    for (const concern of usage.filesystem) {
      assertDataUsageConcern(concern, 'DataStatusResponse.usage.filesystem[]');
    }
    for (const concern of usage.sqlite_logical) {
      assertDataUsageConcern(concern, 'DataStatusResponse.usage.sqlite_logical[]');
    }
    const tablePayload = usage.sqlite_logical.find(
      (concern) => concern.kind === 'sqlite_logical_table',
    );
    expect(tablePayload, 'fixture should include a SQLite table payload row').toBeTruthy();
    expect(tablePayload?.payload_stats?.estimate_method).toBe('local_loaded_payload_estimate');
    expect(tablePayload?.payload_stats?.estimate_basis).toBe('sqlite_logical_payload');
    expect(tablePayload?.payload_stats?.estimated_payload_bytes).toBe(tablePayload?.bytes);
    expect(tablePayload?.payload_stats?.row_count).toBe(tablePayload?.row_count);
    if (usage.sqlite_largest_payload_table !== undefined) {
      const largest = assertDataPayloadStats(
        usage.sqlite_largest_payload_table,
        'DataStatusResponse.usage.sqlite_largest_payload_table',
      );
      expect(largest.estimate_method).toBe('local_loaded_payload_estimate');
      expect(largest.estimate_basis).toBe('sqlite_logical_payload');
    }
    for (const error of usage.scan_errors) {
      expect(error.length, 'DataStatusResponse.usage.scan_errors[] non-empty').toBeGreaterThan(0);
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

  it('privacy.breach-playbooks.json → BreachPlaybookView[] (GET /v1/privacy/breach-playbooks)', async () => {
    stubFetch(fixture('privacy.breach-playbooks.json'));
    const playbooks: BreachPlaybookView[] = await api.listBreachPlaybooks();
    expect(Array.isArray(playbooks)).toBe(true);
    expect(playbooks.length).toBeGreaterThan(0);
    assertBreachPlaybook(playbooks[0], 'BreachPlaybookView');
  });

  it('privacy.transfer-controls.json → TransferControlView[] (GET /v1/privacy/transfer-controls)', async () => {
    stubFetch(fixture('privacy.transfer-controls.json'));
    const controls: TransferControlView[] = await api.listTransferControls();
    expect(Array.isArray(controls)).toBe(true);
    expect(controls.length).toBeGreaterThan(0);
    assertTransferControl(controls[0], 'TransferControlView');
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

  it('retention.due-candidates.json → RetentionDueCandidatesReport (GET /v1/privacy/retention-due-candidates)', async () => {
    stubFetch(fixture('retention.due-candidates.json'));
    const report: RetentionDueCandidatesReport = await api.listRetentionDueCandidates();
    assertRetentionDueCandidatesReport(report, 'RetentionDueCandidatesReport');
    expect(report.candidate_count).toBe(1);
    expect(report.candidates).toHaveLength(1);
    expect(report.candidates[0].candidate_id).toBe('retention-candidate-unsupported');
    expect(report.suppressed_candidate_count).toBe(2);
    expect(report.suppressed_by_bounded_evidence_count).toBe(2);
    expect(report.suppression_summary?.note).toBe(RETENTION_DUE_SUPPRESSION_SUMMARY_NOTE);
    expect(report.candidates[0].would_execute).toBe(false);
  });

  it('retention.candidate-resolutions.json → RetentionCandidateResolutionRecord[] (GET /v1/privacy/retention-candidate-resolutions)', async () => {
    stubFetch(fixture('retention.candidate-resolutions.json'));
    const records: RetentionCandidateResolutionRecord[] =
      await api.listRetentionCandidateResolutions();
    expect(Array.isArray(records)).toBe(true);
    expect(records.length).toBeGreaterThan(0);
    const record = assertRetentionCandidateResolutionRecord(
      records[0],
      'RetentionCandidateResolutionRecord',
    );
    expect(record.disposition).toBe('blocked_follow_up');
    expect(record.evidence_only).toBe(true);
  });

  it('retention.executions.json → RetentionExecutionRecord[] (GET /v1/privacy/retention-executions)', async () => {
    stubFetch(fixture('retention.executions.json'));
    const executions: RetentionExecutionRecord[] = await api.listRetentionExecutions();
    expect(Array.isArray(executions)).toBe(true);
    expect(executions.length).toBeGreaterThan(0);
    const blocked = assertRetentionExecutionRecord(executions[0], 'RetentionExecutionRecord');
    expect(blocked.execution_status).toBe('blocked');
    expect(blocked.workflow.blockers.length).toBeGreaterThan(0);
    expect(blocked.decision_state).toBe('review_closed');
    expect(blocked.review_closure_decision).toBe('blocked_evidence_acknowledged');
    expect(blocked.legal_hold_mutated).toBe(false);
    expect(blocked.retention_policy_mutated).toBe(false);
    expect(blocked.execution_result.destructive_disposal_completed).toBe(false);
    expect(blocked.execution_result.full_erasure_completed).toBe(false);
    const executed = assertRetentionExecutionRecord(executions[1], 'RetentionExecutionRecord[1]');
    expect(executed.execution_status).toBe('executed');
    expect(executed.approval?.approval_reference).toBe('privacy-board-42');
    expect(executed.review_closure_decision).toBe('bounded_evidence_acknowledged');
    const openNoAction = assertRetentionExecutionRecord(
      executions[2],
      'RetentionExecutionRecord[2]',
    );
    expect(openNoAction.decision_state).toBe('open');
    const reviewClosed = assertRetentionExecutionRecord(
      executions[3],
      'RetentionExecutionRecord[3]',
    );
    expect(reviewClosed.review_closure_decision).toBe('review_evidence_acknowledged');
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
      'backup.recovery-drill.json',
      'backup.recovery-drill-list.json',
      'data.status.json',
      'user.json',
      'session.json',
      'session.roster.json',
      'session.password-policy.json',
      'user.dsr-export.json',
      'user.dsr-requests.json',
      'privacy.processors.json',
      'privacy.dpias.json',
      'privacy.breach-playbooks.json',
      'privacy.transfer-controls.json',
      'retention.policies.json',
      'retention.due-candidates.json',
      'retention.candidate-resolutions.json',
      'retention.executions.json',
      'paper-book.import.json',
      'paper-book.ocr-draft.json',
      'paper-book.ocr-run.json',
      'paper-book.ocr-canonical-draft.json',
      'paper-book.ocr-conversion-dossier.json',
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
