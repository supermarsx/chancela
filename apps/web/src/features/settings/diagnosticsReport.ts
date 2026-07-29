/**
 * DIAGNOSTICS REPORT (t/diagnostics) — the one structure the Administração › Diagnóstico screen and
 * its plain-text export are BOTH derived from.
 *
 * ─── WHY A MODEL RATHER THAN A COMPONENT ───────────────────────────────────────────────────────
 *
 * The screen and the `.txt` must never disagree. If the panel rendered its rows in JSX and a second
 * function re-walked the same query results to build the text, a section added to one would be
 * silently missing from the other — and the copy someone pastes into a support ticket is precisely
 * the artefact nobody re-reads against the screen. So {@link buildDiagnosticsReport} produces the
 * whole report as data, `DiagnosticsSection.tsx` renders that data, and
 * {@link renderDiagnosticsText} serialises the same data. Adding a row is one edit in one place.
 *
 * ─── THREE RULES THIS MODULE ENFORCES, NOT DOCUMENTS ───────────────────────────────────────────
 *
 * 1. **No secret ever reaches the report.** The env rows come from the already-masked
 *    `GET /v1/platform/env` (`env_overrides_handler::build_view` nulls `effective_value`,
 *    `override_value` and `default_value` for every `secret` var). This module does NOT trust that:
 *    {@link envVarRows} re-checks `v.secret` and emits only `configured` for a secret var, so a
 *    server that regressed and echoed `CHANCELA_DB_KEY` still cannot leak it into a clipboard, a
 *    printer or a file. `diagnosticsReport.test.ts` proves it with a fixture that carries values on
 *    Tier B rows.
 * 2. **No personal data.** Every field that names a person is dropped at the boundary rather than
 *    filtered later: delivery rows are aggregated to counts by status / failure stage / failure
 *    kind and their `recipient` and `user_id` never enter the model; credential entry `label`s
 *    (operator-typed free text) become counts; server-authored prose (`message`, `last_error`,
 *    `first_break.message`) is reduced to a presence flag, because prose is where a document title
 *    or an address would arrive if one ever did.
 * 3. **Never a status that was not read.** {@link DiagnosticValue} has no "assumed" arm. A datum is
 *    a value actually read, an explicit `unknown`, or an explicit `error` carrying the code. A
 *    source that was refused, failed or was never queried says so in its own
 *    {@link DiagnosticSourceState}, on screen and in the export.
 *
 * ─── THE TEXT FORMAT ───────────────────────────────────────────────────────────────────────────
 *
 * Machine identifiers, never prose: `storage.persistence.mode = postgres`. The export is therefore
 * the same document in all fourteen locales, which is the point — an operator in Helsinki and the
 * person reading the ticket in Lisbon compare the same bytes. Field ids are stable and the key
 * column is padded to a CONSTANT width (not the longest key present), so adding a long row cannot
 * reflow every other line of a diff.
 */
import type {
  DataStatusResponse,
  EmailDeliveryView,
  EmailStatusView,
  HealthResponse,
  IntegrityReportView,
  PlatformServicesResponse,
  ProviderCredentialsListView,
  SearchStatusResponse,
  ServerEnvResponse,
  ServerEnvVarView,
  TslSummaryView,
  ZkStorageStatus,
} from '../../api/types';
import type { MessageKey } from '../../i18n';
import type { BuildProvenance } from './buildProvenance';

// --- Value + source model -------------------------------------------------------

/**
 * One field's value. There is deliberately no arm meaning "fine" or "healthy" — a row is a datum
 * that was read, an explicit unknown, or an explicit error.
 */
export type DiagnosticValue =
  /** A machine token rendered verbatim in every locale (an enum value, a version, an id). */
  | { kind: 'text'; text: string }
  | { kind: 'bool'; value: boolean }
  | { kind: 'count'; value: number }
  /** The Tier-B shape: whether something is set, never what it is set to. */
  | { kind: 'configured'; value: boolean }
  /** Read successfully, and the field is genuinely unset. Distinct from `unknown`. */
  | { kind: 'unset' }
  /** Not read. The row exists so its absence is visible rather than inferred from a missing row. */
  | { kind: 'unknown' }
  /** Read and failed. `code` is a stable machine token (an HTTP status, or a short reason). */
  | { kind: 'error'; code: string };

/** Whether a whole source answered, and how it failed when it did not. */
export type DiagnosticSourceState =
  | { kind: 'ok' }
  | { kind: 'loading' }
  /** Deliberately not queried — the reason is a stable machine token, not a sentence. */
  | { kind: 'not_checked'; reason: string }
  | { kind: 'forbidden' }
  | { kind: 'error'; code: string };

/** One `field = value` line. `id` is the machine field path and is never translated. */
export interface DiagnosticRow {
  id: string;
  value: DiagnosticValue;
}

export interface DiagnosticSection {
  /** Stable machine id — the `[section]` header in the text and the row `data-section` on screen. */
  id: string;
  /** The on-screen card title. The export never uses it, so the file stays locale-independent. */
  titleKey: MessageKey;
  source: DiagnosticSourceState;
  rows: DiagnosticRow[];
}

export interface DiagnosticsReport {
  /** ISO 8601 with an explicit offset — a wall clock with no zone is not a moment in time. */
  generatedAt: string;
  sections: DiagnosticSection[];
}

// --- Source inputs --------------------------------------------------------------

/** One upstream query, already reduced to "what state is it in" plus "what did it return". */
export interface DiagnosticsSource<T> {
  state: DiagnosticSourceState;
  data: T | undefined;
}

/** A source that was never wired to a query at all (see `NOT_COVERED` below). */
export const sourceNotChecked = (reason: string): DiagnosticSourceState => ({
  kind: 'not_checked',
  reason,
});

/**
 * Everything the report is built from. Collected by the panel and passed in whole, so the builder
 * is pure and the tests can feed fixtures — including hostile ones — with no React and no network.
 */
export interface DiagnosticsInput {
  /** The instant the report was generated, as a `Date`. */
  generatedAt: Date;
  /** The active UI locale tag, e.g. `pt-PT`. */
  locale: string;
  /** The IANA zone the timestamps were rendered in, or `null` when `Intl` could not resolve one. */
  timeZone: string | null;
  /** `__APP_VERSION__` via `UI_VERSION`. */
  uiVersion: string;
  /** `BUILD_COMMIT` — `null` on a build made without a repository behind it. */
  build: BuildProvenance | null;
  /** Whether the app is running inside the Tauri shell rather than a browser tab. */
  desktop: boolean;
  /** The host this instance is served from — the filename's instance discriminator. */
  host: string;
  health: DiagnosticsSource<HealthResponse>;
  services: DiagnosticsSource<PlatformServicesResponse>;
  env: DiagnosticsSource<ServerEnvResponse>;
  storage: DiagnosticsSource<DataStatusResponse>;
  zk: DiagnosticsSource<ZkStorageStatus>;
  ledger: DiagnosticsSource<IntegrityReportView>;
  search: DiagnosticsSource<SearchStatusResponse>;
  trust: DiagnosticsSource<TslSummaryView>;
  email: DiagnosticsSource<EmailStatusView>;
  deliveries: DiagnosticsSource<EmailDeliveryView[]>;
  credentials: DiagnosticsSource<ProviderCredentialsListView>;
  /** The settings document's `schema_version`, and nothing else from that document (see below). */
  settingsSchemaVersion: DiagnosticsSource<number>;
}

// --- Small value constructors ---------------------------------------------------

const text = (value: string): DiagnosticValue => ({ kind: 'text', text: value });
const bool = (value: boolean): DiagnosticValue => ({ kind: 'bool', value });
const count = (value: number): DiagnosticValue => ({ kind: 'count', value });
const configured = (value: boolean): DiagnosticValue => ({ kind: 'configured', value });
const unknown: DiagnosticValue = { kind: 'unknown' };
const unset: DiagnosticValue = { kind: 'unset' };

/** A nullable machine token: a value, or the explicit "read, and it is unset". */
const optionalText = (value: string | null | undefined): DiagnosticValue =>
  value === null || value === undefined || value === '' ? unset : text(value);

/** A nullable number, kept distinct from `unknown`: absent means read-and-unset. */
const optionalCount = (value: number | null | undefined): DiagnosticValue =>
  value === null || value === undefined ? unset : count(value);

/** A nullable boolean. `ledger_verified: null` means "not verified", which is not `false`. */
const optionalBool = (value: boolean | null | undefined): DiagnosticValue =>
  value === null || value === undefined ? unknown : bool(value);

/**
 * Server-authored prose reduced to a presence flag.
 *
 * `search.last_error`, `data.permissions.*.message` and `ledger.first_break.message` are sentences
 * the server composes. None is known to carry personal data today — and none is guaranteed not to
 * tomorrow, which is the wrong side of the line for a file that leaves the building. The row says
 * whether there IS a message; the operator reads it on the panel that owns it.
 */
const prosePresence = (value: string | null | undefined): DiagnosticValue =>
  bool(value !== null && value !== undefined && value !== '');

/** Every row of a section that could not be read at all: one honest `unknown` per declared field. */
function unknownRows(ids: readonly string[]): DiagnosticRow[] {
  return ids.map((id) => ({ id, value: unknown }));
}

/** Whether a source answered. A section with no data renders its declared fields as `unknown`. */
const answered = <T>(source: DiagnosticsSource<T>): source is DiagnosticsSource<T> & { data: T } =>
  source.state.kind === 'ok' && source.data !== undefined;

// --- Section builders -----------------------------------------------------------

/**
 * The self-describing head. Everything here is known to the client without a request, so the
 * section's own state is always `ok`; the one row that needs the server (`settings.schema_version`)
 * carries its own `unknown`/`error` instead of dragging the header into a failed state.
 */
function reportSection(input: DiagnosticsInput): DiagnosticSection {
  const build = input.build;
  return {
    id: 'report',
    titleKey: 'settings.diagnostics.section.report',
    source: { kind: 'ok' },
    rows: [
      { id: 'report.generated_at', value: text(isoWithOffset(input.generatedAt)) },
      { id: 'report.generated_at_utc', value: text(input.generatedAt.toISOString()) },
      { id: 'report.time_zone', value: optionalText(input.timeZone) },
      { id: 'report.locale', value: text(input.locale) },
      { id: 'report.host', value: text(input.host) },
      { id: 'report.runtime', value: text(input.desktop ? 'desktop' : 'browser') },
      { id: 'report.ui_version', value: text(input.uiVersion) },
      // Build provenance degrades honestly: a Docker/tarball build has no repository behind it and
      // `describeBuildCommit` returns null. The rows say `absent` rather than showing a placeholder
      // that reads like a hash (see buildProvenance.ts).
      { id: 'report.build.provenance', value: text(build === null ? 'absent' : 'available') },
      { id: 'report.build.commit', value: build === null ? unset : text(build.hash) },
      { id: 'report.build.commit_short', value: build === null ? unset : text(build.shortHash) },
      { id: 'report.build.committed_at', value: build === null ? unset : text(build.committedAt) },
      { id: 'report.build.codename', value: build === null ? unset : text(build.codename) },
      { id: 'report.settings.schema_version', value: scalarRow(input.settingsSchemaVersion) },
    ],
  };
}

/** A one-row source: its own state collapses into the single value, so a 403 shows as an error. */
function scalarRow(source: DiagnosticsSource<number>): DiagnosticValue {
  if (source.state.kind === 'forbidden') return { kind: 'error', code: 'forbidden' };
  if (source.state.kind === 'error') return { kind: 'error', code: source.state.code };
  if (!answered(source)) return unknown;
  return count(source.data);
}

const HEALTH_FIELDS = [
  'health.status',
  'health.version',
  'health.version_matches_ui',
  'health.integrity',
  'health.degraded',
] as const;

function healthSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.health;
  if (!answered(source)) {
    return {
      id: 'health',
      titleKey: 'settings.diagnostics.section.health',
      source: source.state,
      rows: unknownRows(HEALTH_FIELDS),
    };
  }
  const health = source.data;
  return {
    id: 'health',
    titleKey: 'settings.diagnostics.section.health',
    source: source.state,
    rows: [
      { id: 'health.status', value: optionalText(health.status) },
      { id: 'health.version', value: optionalText(health.version) },
      {
        id: 'health.version_matches_ui',
        // A skew usually means a stale server binary — the condition that makes a `/v1` route fall
        // through to the SPA shell (see api/versionCheck.ts). Unknown when the server sent no
        // version at all, never optimistically "matches".
        value:
          health.version === undefined || health.version === ''
            ? unknown
            : bool(health.version === input.uiVersion),
      },
      { id: 'health.integrity', value: optionalText(health.integrity) },
      { id: 'health.degraded', value: optionalBool(health.degraded) },
    ],
  };
}

function servicesSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.services;
  if (!answered(source)) {
    return {
      id: 'platform_services',
      titleKey: 'settings.diagnostics.section.services',
      source: source.state,
      rows: unknownRows(['platform_services.count']),
    };
  }
  const services = source.data.services;
  const rows: DiagnosticRow[] = [{ id: 'platform_services.count', value: count(services.length) }];
  for (const service of services) {
    // `service.label` is server-composed display copy; the id is the machine identifier and the
    // only thing worth quoting in a ticket. `limitations` are honest prose about what the control
    // plane cannot do — counted here, read in full on the Serviços panel.
    const prefix = `platform_services.${service.id}`;
    rows.push(
      { id: `${prefix}.kind`, value: text(service.kind) },
      { id: `${prefix}.configured`, value: bool(service.configured) },
      { id: `${prefix}.enabled`, value: bool(service.enabled) },
      { id: `${prefix}.desired_state`, value: text(service.desired_state) },
      { id: `${prefix}.runtime_status`, value: text(service.actual_runtime_status) },
      { id: `${prefix}.logging_level`, value: text(service.logging_level) },
      { id: `${prefix}.limitation_count`, value: count(service.limitations.length) },
    );
  }
  return {
    id: 'platform_services',
    titleKey: 'settings.diagnostics.section.services',
    source: source.state,
    rows,
  };
}

/**
 * One environment variable's rows.
 *
 * THE SECRET BOUNDARY. `secret` vars get `configured` and nothing else — not the effective value,
 * not the stored override, not the code default. The server already masks all three, so this is
 * belt AND braces: the report is built from the SPEC's secret flag rather than from whether the
 * payload happened to be empty, which is the same discipline `build_view` applies server-side to a
 * hand-corrupted override file. That covers `CHANCELA_DB_KEY`, `DATABASE_URL`, `REDIS_URL`,
 * `CHANCELA_CREDENTIAL_KEY`, `CHANCELA_SEARCH_DATABASE_URL`, `CHANCELA_MCP_API_KEY`, the SCAP/CMD
 * secrets and the dynamic `CHANCELA_CSC_<PROVIDER>_*` / `CHANCELA_CONNECTOR_SECRET_*` families,
 * because the classification travels with each row instead of being restated here as a name list
 * that could drift from the registry.
 */
function envVarRows(v: ServerEnvVarView): DiagnosticRow[] {
  const prefix = `env.var.${v.name}`;
  const rows: DiagnosticRow[] = [
    { id: `${prefix}.tier`, value: text(v.tier) },
    { id: `${prefix}.group`, value: text(v.group) },
    { id: `${prefix}.source`, value: text(v.source) },
    { id: `${prefix}.configured`, value: configured(v.configured) },
  ];
  if (v.secret) return rows;
  rows.push(
    { id: `${prefix}.value`, value: optionalText(v.effective_value) },
    { id: `${prefix}.override`, value: optionalText(v.override_value) },
    { id: `${prefix}.default`, value: optionalText(v.default_value) },
    { id: `${prefix}.restart_pending`, value: bool(v.restart_pending) },
  );
  return rows;
}

function envSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.env;
  if (!answered(source)) {
    return {
      id: 'env',
      titleKey: 'settings.diagnostics.section.env',
      source: source.state,
      rows: unknownRows(['env.var_count', 'env.restart_pending']),
    };
  }
  const env = source.data;
  const vars = [...env.vars].sort((left, right) => (left.name < right.name ? -1 : 1));
  const secrets = vars.filter((v) => v.secret);
  const rows: DiagnosticRow[] = [
    { id: 'env.generated_at', value: text(env.generated_at) },
    { id: 'env.restart_pending', value: bool(env.restart_pending) },
    { id: 'env.overrides_path', value: text(env.overrides_path) },
    { id: 'env.var_count', value: count(vars.length) },
    { id: 'env.secret_count', value: count(secrets.length) },
    { id: 'env.secret_configured_count', value: count(secrets.filter((v) => v.configured).length) },
    {
      id: 'env.override_count',
      value: count(vars.filter((v) => v.override_value !== null).length),
    },
    {
      id: 'env.restart_pending_count',
      value: count(vars.filter((v) => v.restart_pending).length),
    },
  ];
  for (const v of vars) rows.push(...envVarRows(v));
  return { id: 'env', titleKey: 'settings.diagnostics.section.env', source: source.state, rows };
}

const STORAGE_FIELDS = [
  'storage.generated_at',
  'storage.persistence.mode',
  'storage.persistence.backend_family',
  'storage.persistence.durable_store_open',
  'storage.persistence.ledger_length',
] as const;

function storageSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.storage;
  if (!answered(source)) {
    return {
      id: 'storage',
      titleKey: 'settings.diagnostics.section.storage',
      source: source.state,
      rows: [...unknownRows(STORAGE_FIELDS), ...zkRows(input)],
    };
  }
  const status = source.data;
  const persistence = status.persistence;
  const encryption = persistence.database_encryption;
  const permissions = status.permissions;
  const rows: DiagnosticRow[] = [
    { id: 'storage.generated_at', value: text(status.generated_at) },
    { id: 'storage.persistence.mode', value: text(persistence.mode) },
    {
      id: 'storage.persistence.backend_family',
      value: optionalText(persistence.active_backend_family),
    },
    { id: 'storage.persistence.data_dir_configured', value: bool(persistence.data_dir_configured) },
    { id: 'storage.persistence.durable_store_open', value: bool(persistence.durable_store_open) },
    {
      id: 'storage.persistence.sidecar_storage_mode',
      value: text(persistence.sidecar_storage_mode),
    },
    {
      id: 'storage.persistence.store_schema_version',
      value: optionalCount(persistence.store_schema_version),
    },
    { id: 'storage.persistence.ledger_length', value: count(persistence.ledger_length) },
    { id: 'storage.persistence.ledger_verified', value: optionalBool(persistence.ledger_verified) },
    { id: 'storage.persistence.degraded', value: bool(persistence.degraded) },
    // The data directory is reported as PRESENCE, never as a path: a data dir under a home
    // directory carries the operator's account name, and this file leaves the building.
    { id: 'storage.data_dir.exists', value: optionalBool(status.data_dir.exists) },
    { id: 'storage.data_dir.is_directory', value: optionalBool(status.data_dir.is_directory) },
    { id: 'storage.encryption.configured', value: bool(encryption.configured) },
    { id: 'storage.encryption.sqlcipher_available', value: bool(encryption.sqlcipher_available) },
    { id: 'storage.encryption.sqlcipher_backed', value: bool(encryption.sqlcipher_backed) },
    { id: 'storage.encryption.key_source', value: text(encryption.key_source) },
    { id: 'storage.encryption.database_format', value: optionalText(encryption.database_format) },
    {
      id: 'storage.encryption.plaintext_migration_pending',
      value: bool(encryption.plaintext_migration_pending),
    },
    {
      id: 'storage.encryption.plaintext_migration_blocked',
      value: bool(encryption.plaintext_migration_blocked),
    },
    { id: 'storage.encryption.key_ops_error', value: prosePresence(encryption.key_ops_error) },
  ];
  // Each probe is a pass/fail the server actually performed, plus whether it performed it at all —
  // `checked: false` is exactly the "not verified" this report must never render as a pass. The
  // probe's `message` names the path it tried, so only the two booleans travel.
  for (const [name, check] of Object.entries(permissions)) {
    rows.push({
      id: `storage.permissions.${name}`,
      value: check.checked ? bool(check.ok) : unknown,
    });
  }
  rows.push(
    { id: 'storage.usage.total_bytes', value: count(status.usage.total_bytes) },
    { id: 'storage.usage.scan_error_count', value: count(status.usage.scan_errors.length) },
    { id: 'storage.key_rotation.history_count', value: count(status.key_rotation.history_count) },
    {
      id: 'storage.key_rotation.latest_status',
      value: status.key_rotation.latest_receipt
        ? text(status.key_rotation.latest_receipt.status)
        : unset,
    },
    {
      id: 'storage.key_rotation.latest_rotated_at',
      value: status.key_rotation.latest_receipt
        ? text(status.key_rotation.latest_receipt.rotated_at)
        : unset,
    },
    { id: 'storage.key_rotation.read_error', value: prosePresence(status.key_rotation.read_error) },
  );
  rows.push(...zkRows(input));
  return {
    id: 'storage',
    titleKey: 'settings.diagnostics.section.storage',
    source: source.state,
    rows,
  };
}

/** The zero-knowledge object-root interlock, folded into storage — it is a storage fact. */
function zkRows(input: DiagnosticsInput): DiagnosticRow[] {
  const source = input.zk;
  if (!answered(source)) {
    return unknownRows([
      'storage.zk.ready',
      'storage.zk.requires_shared_root',
      'storage.zk.source',
    ]);
  }
  const zk = source.data;
  return [
    { id: 'storage.zk.ready', value: bool(zk.ready) },
    { id: 'storage.zk.requires_shared_root', value: bool(zk.requires_shared_root) },
    { id: 'storage.zk.source', value: text(zk.source) },
    // The declared root is a filesystem path or URL — reported as declared/not declared, exactly
    // like the data directory above.
    { id: 'storage.zk.root_declared', value: configured(zk.declared_root !== null) },
    { id: 'storage.zk.reason', value: prosePresence(zk.reason) },
  ];
}

const LEDGER_FIELDS = [
  'ledger.healthy',
  'ledger.degraded',
  'ledger.global.length',
  'ledger.global.verified',
] as const;

function ledgerSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.ledger;
  if (!answered(source)) {
    return {
      id: 'ledger',
      titleKey: 'settings.diagnostics.section.ledger',
      source: source.state,
      rows: unknownRows(LEDGER_FIELDS),
    };
  }
  const report = source.data;
  const broken = report.chains.filter((chain) => !chain.verified);
  const firstBreak = report.global.first_break ?? broken[0]?.first_break ?? null;
  return {
    id: 'ledger',
    titleKey: 'settings.diagnostics.section.ledger',
    source: source.state,
    rows: [
      { id: 'ledger.healthy', value: bool(report.healthy) },
      { id: 'ledger.degraded', value: bool(report.degraded) },
      { id: 'ledger.global.genesis_kind', value: optionalText(report.global.genesis_kind) },
      { id: 'ledger.global.length', value: count(report.global.length) },
      { id: 'ledger.global.verified', value: bool(report.global.verified) },
      { id: 'ledger.chain_count', value: count(report.chains.length) },
      { id: 'ledger.unverified_chain_count', value: count(broken.length) },
      // The break's location, not its narration: `chain` is a canonical id
      // (`book:{uuid}` / `company:{uuid}`) and `kind` a `BreakKind` variant. The composed
      // `message` is left on the Integridade panel.
      { id: 'ledger.first_break.chain', value: firstBreak ? text(firstBreak.chain) : unset },
      { id: 'ledger.first_break.kind', value: firstBreak ? text(firstBreak.kind) : unset },
      {
        id: 'ledger.first_break.global_seq',
        value: firstBreak ? optionalCount(firstBreak.global_seq) : unset,
      },
      {
        id: 'ledger.reanchored_segment_count',
        value: count(report.reanchored_segments.length),
      },
    ],
  };
}

const SEARCH_FIELDS = [
  'search.enabled',
  'search.execution_mode',
  'search.phase',
  'search.stale',
] as const;

function searchSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.search;
  if (!answered(source)) {
    return {
      id: 'search',
      titleKey: 'settings.diagnostics.section.search',
      source: source.state,
      rows: unknownRows(SEARCH_FIELDS),
    };
  }
  const status = source.data;
  return {
    id: 'search',
    titleKey: 'settings.diagnostics.section.search',
    source: source.state,
    rows: [
      { id: 'search.enabled', value: bool(status.enabled) },
      { id: 'search.execution_mode', value: text(status.execution_mode) },
      { id: 'search.phase', value: text(status.phase) },
      { id: 'search.partial', value: bool(status.partial) },
      { id: 'search.stale', value: bool(status.stale) },
      // The management-only diagnostics below are omitted by the server for a `search.read`
      // principal. `details_redacted` is what tells an operator that the blanks are a permission
      // boundary rather than a broken worker.
      { id: 'search.details_redacted', value: bool(status.details_redacted) },
      { id: 'search.generation', value: optionalCount(status.generation) },
      { id: 'search.document_count', value: optionalCount(status.document_count) },
      {
        id: 'search.truncated_document_count',
        value: optionalCount(status.truncated_document_count),
      },
      { id: 'search.content_truncated', value: optionalBool(status.content_truncated) },
      {
        id: 'search.content_budget_exhausted',
        value: optionalBool(status.content_budget_exhausted),
      },
      { id: 'search.queue_depth', value: optionalCount(status.queue_depth) },
      { id: 'search.queue_capacity', value: optionalCount(status.queue_capacity) },
      { id: 'search.dropped_commands', value: optionalCount(status.dropped_commands) },
      { id: 'search.last_event_seq', value: optionalCount(status.last_event_seq) },
      { id: 'search.last_started_at', value: optionalText(status.last_started_at) },
      { id: 'search.last_completed_at', value: optionalText(status.last_completed_at) },
      { id: 'search.projection_writer', value: optionalBool(status.projection_writer) },
      { id: 'search.projector_phase', value: optionalText(status.projector_phase) },
      { id: 'search.projector_heartbeat_at', value: optionalText(status.projector_heartbeat_at) },
      {
        id: 'search.projector_heartbeat_fresh',
        value: optionalBool(status.projector_heartbeat_fresh),
      },
      // The worker's error text is composed prose; the panel that owns it shows it in full.
      { id: 'search.last_error', value: prosePresence(status.last_error) },
      { id: 'search.error_at', value: optionalText(status.error_at) },
    ],
  };
}

const TRUST_FIELDS = ['trust.scheme_territory', 'trust.stale', 'trust.services'] as const;

function trustSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.trust;
  if (!answered(source)) {
    return {
      id: 'trust',
      titleKey: 'settings.diagnostics.section.trust',
      source: source.state,
      rows: unknownRows(TRUST_FIELDS),
    };
  }
  const summary = source.data;
  const refresh = summary.last_refresh;
  return {
    id: 'trust',
    titleKey: 'settings.diagnostics.section.trust',
    source: source.state,
    rows: [
      { id: 'trust.scheme_territory', value: optionalText(summary.scheme_territory) },
      { id: 'trust.sequence_number', value: optionalCount(summary.sequence_number) },
      { id: 'trust.issue_date_time', value: optionalText(summary.issue_date_time) },
      { id: 'trust.next_update', value: optionalText(summary.next_update) },
      { id: 'trust.stale', value: bool(summary.stale) },
      { id: 'trust.validation.signature', value: text(summary.validation.signature) },
      { id: 'trust.validation.checked_at', value: text(summary.validation.checked_at) },
      { id: 'trust.validation.error', value: prosePresence(summary.validation.error) },
      { id: 'trust.providers', value: count(summary.providers) },
      { id: 'trust.services', value: count(summary.services) },
      { id: 'trust.ca_qc_services', value: count(summary.ca_qc_services) },
      {
        id: 'trust.qualified_esignature_services',
        value: count(summary.qualified_esignature_services),
      },
      {
        id: 'trust.trusted_esignature_services',
        value: count(summary.trusted_esignature_services),
      },
      {
        id: 'trust.last_refresh.attempted_at',
        value: refresh ? text(refresh.attempted_at) : unset,
      },
      { id: 'trust.last_refresh.outcome', value: refresh ? text(refresh.outcome) : unset },
      { id: 'trust.last_refresh.source_kind', value: refresh ? text(refresh.source_kind) : unset },
      { id: 'trust.last_refresh.error', value: refresh ? prosePresence(refresh.error) : unset },
    ],
  };
}

const EMAIL_FIELDS = ['email.password_configured', 'email.deliverable', 'email.encrypted'] as const;

/**
 * Outbound mail: relay posture plus delivery OUTCOMES, never recipients.
 *
 * `EmailDeliveryView` carries `recipient` (a full address) and `user_id`. Neither is read here —
 * not masked, not truncated, not hashed. The delivery log is aggregated into counts by status and
 * by the failure stage / kind an SMTP session failed at, which is what actually points at a fix
 * (`auth` vs `tls` vs `rcpt_to` are three different problems).
 */
function emailSection(input: DiagnosticsInput): DiagnosticSection {
  const statusSource = input.email;
  const rows: DiagnosticRow[] = [];

  if (answered(statusSource)) {
    const status = statusSource.data;
    rows.push(
      { id: 'email.password_configured', value: configured(status.password_configured) },
      { id: 'email.deliverable', value: bool(status.deliverable) },
      { id: 'email.encrypted', value: bool(status.encrypted) },
      { id: 'email.warning_count', value: count(status.warnings.length) },
    );
  } else {
    rows.push(...unknownRows(EMAIL_FIELDS));
  }

  const deliveriesSource = input.deliveries;
  if (answered(deliveriesSource)) {
    const deliveries = deliveriesSource.data;
    rows.push(
      { id: 'email.deliveries.count', value: count(deliveries.length) },
      {
        id: 'email.deliveries.sent',
        value: count(deliveries.filter((d) => d.status === 'sent').length),
      },
      {
        id: 'email.deliveries.failed',
        value: count(deliveries.filter((d) => d.status === 'failed').length),
      },
      {
        id: 'email.deliveries.retried',
        value: count(deliveries.filter((d) => d.attempt > 1).length),
      },
    );
    for (const [stage, total] of tally(deliveries.map((d) => d.failure_stage))) {
      rows.push({ id: `email.deliveries.failure_stage.${stage}`, value: count(total) });
    }
    for (const [kind, total] of tally(deliveries.map((d) => d.failure_kind))) {
      rows.push({ id: `email.deliveries.failure_kind.${kind}`, value: count(total) });
    }
  } else {
    rows.push(
      { id: 'email.deliveries.count', value: unknown },
      { id: 'email.deliveries.failed', value: unknown },
    );
  }

  return {
    id: 'email',
    titleKey: 'settings.diagnostics.section.email',
    source: statusSource.state,
    rows,
  };
}

/** Count occurrences of each defined token, in a stable (sorted) order for a diffable export. */
function tally(values: readonly (string | undefined)[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const value of values) {
    if (value === undefined || value === '') continue;
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()].sort(([left], [right]) => (left < right ? -1 : 1));
}

const CREDENTIAL_FIELDS = ['credentials.strict', 'credentials.record_count'] as const;

/**
 * Signature-provider credential POSTURE. The management list is metadata-only server-side (secrets
 * are write-only), and this narrows it further: an entry's operator-typed `label` is free text that
 * routinely names a person ("cartão da Amélia"), so entries become counts and the per-field
 * `configured` flags become a configured-field count.
 */
function credentialsSection(input: DiagnosticsInput): DiagnosticSection {
  const source = input.credentials;
  if (!answered(source)) {
    return {
      id: 'credentials',
      titleKey: 'settings.diagnostics.section.credentials',
      source: source.state,
      rows: unknownRows(CREDENTIAL_FIELDS),
    };
  }
  const list = source.data;
  const rows: DiagnosticRow[] = [
    { id: 'credentials.strict', value: bool(list.strict) },
    { id: 'credentials.protection_level', value: optionalText(list.protection_level) },
    { id: 'credentials.can_store', value: optionalBool(list.can_store) },
    { id: 'credentials.storage_failure', value: optionalText(list.storage_failure) },
    { id: 'credentials.record_count', value: count(list.providers.length) },
  ];
  for (const group of list.providers) {
    const prefix = `credentials.${group.mode}.${group.provider_id}`;
    rows.push(
      { id: `${prefix}.entry_count`, value: count(group.entries.length) },
      {
        id: `${prefix}.enabled_count`,
        value: count(group.entries.filter((entry) => entry.enabled).length),
      },
      {
        id: `${prefix}.configured_field_count`,
        value: count(
          group.entries.reduce(
            (total, entry) => total + entry.fields.filter((field) => field.configured).length,
            0,
          ),
        ),
      },
    );
  }
  return {
    id: 'credentials',
    titleKey: 'settings.diagnostics.section.credentials',
    source: source.state,
    rows,
  };
}

/**
 * What this report deliberately does NOT carry, as rows rather than as a silence.
 *
 * A missing section reads as "nothing to report"; an `unknown` row with a machine reason reads as
 * "not collected, and here is why". The second is the only honest one, and it is the difference
 * between an operator concluding the cluster is fine and knowing nobody asked.
 */
const NOT_COVERED: readonly { id: string; reason: string }[] = [
  // `chancela-api/src/cluster.rs` + `cluster_route.rs` expose node role, leases and the changefeed
  // to the CLUSTER, not to a browser: there is no client-facing status route. The cluster ENV
  // (CHANCELA_NODE_ROLE and the poll intervals) does appear, under `env.var.*`.
  { id: 'not_covered.cluster_runtime', reason: 'no_client_endpoint' },
  // `GET /v1/users` is the roster: display names and usernames. A count would need it too.
  { id: 'not_covered.accounts', reason: 'personal_data' },
  // Log lines quote act titles, entity names and actor ids.
  { id: 'not_covered.platform_logs', reason: 'personal_data' },
  // The settings document holds the organisation name and the mail sender address. Only its
  // `schema_version` is quoted, in `report.settings.schema_version`.
  { id: 'not_covered.settings_document', reason: 'personal_data' },
  // Ledger events carry their payloads.
  { id: 'not_covered.ledger_events', reason: 'personal_data' },
  // Every secret-bearing variable, by construction — see `envVarRows`.
  { id: 'not_covered.secret_values', reason: 'never_exported' },
];

function notCoveredSection(): DiagnosticSection {
  return {
    id: 'not_covered',
    titleKey: 'settings.diagnostics.section.notCovered',
    source: { kind: 'ok' },
    rows: NOT_COVERED.map(({ id, reason }) => ({ id, value: text(reason) })),
  };
}

// --- The report -----------------------------------------------------------------

/** Build the whole report. Pure: same input, same bytes. */
export function buildDiagnosticsReport(input: DiagnosticsInput): DiagnosticsReport {
  return {
    generatedAt: isoWithOffset(input.generatedAt),
    sections: [
      reportSection(input),
      healthSection(input),
      servicesSection(input),
      envSection(input),
      storageSection(input),
      ledgerSection(input),
      searchSection(input),
      trustSection(input),
      emailSection(input),
      credentialsSection(input),
      notCoveredSection(),
    ],
  };
}

// --- Plain-text rendering -------------------------------------------------------

/**
 * The key column width. A CONSTANT, not the longest key in this particular report: deriving it
 * from the content would make adding one long row reflow every line of a diff between two dumps.
 * Keys longer than this simply push their value one space to the right.
 */
const KEY_COLUMN = 46;

const TITLE = 'CHANCELA DIAGNOSTICS REPORT';

/** The machine token for a value, identical in every locale. */
export function diagnosticValueToken(value: DiagnosticValue): string {
  switch (value.kind) {
    case 'text':
      return value.text;
    case 'bool':
      return value.value ? 'true' : 'false';
    case 'count':
      return String(value.value);
    case 'configured':
      return value.value ? 'configured' : 'not-configured';
    case 'unset':
      return '<unset>';
    case 'unknown':
      return '<unknown>';
    case 'error':
      return `<error:${value.code}>`;
  }
}

/** The machine token for a whole source's state. */
export function diagnosticSourceToken(state: DiagnosticSourceState): string {
  switch (state.kind) {
    case 'ok':
      return 'ok';
    case 'loading':
      return 'loading';
    case 'not_checked':
      return `not-checked:${state.reason}`;
    case 'forbidden':
      return 'forbidden';
    case 'error':
      return `error:${state.code}`;
  }
}

function line(id: string, token: string): string {
  return `${id.padEnd(KEY_COLUMN)} = ${token}`;
}

/**
 * Serialise the report. Byte-identical to what Copy puts on the clipboard and what the `.txt`
 * download contains, because both call exactly this.
 */
export function renderDiagnosticsText(report: DiagnosticsReport): string {
  const out: string[] = [TITLE, '='.repeat(TITLE.length), ''];
  for (const section of report.sections) {
    out.push(`[${section.id}] source=${diagnosticSourceToken(section.source)}`);
    for (const row of section.rows) out.push(line(row.id, diagnosticValueToken(row.value)));
    out.push('');
  }
  return out.join('\n');
}

// --- Timestamps + filename ------------------------------------------------------

const pad2 = (value: number): string => String(value).padStart(2, '0');

/**
 * ISO 8601 in LOCAL time with an explicit offset — the same shape `git log --format=%cI` emits and
 * the same one `buildProvenance` insists on. Local rather than UTC because the operator reading it
 * is comparing it against their own clock; the UTC instant is a separate row, so nothing is lost.
 */
export function isoWithOffset(at: Date): string {
  const offsetMinutes = -at.getTimezoneOffset();
  const sign = offsetMinutes < 0 ? '-' : '+';
  const abs = Math.abs(offsetMinutes);
  const date = `${at.getFullYear()}-${pad2(at.getMonth() + 1)}-${pad2(at.getDate())}`;
  const time = `${pad2(at.getHours())}:${pad2(at.getMinutes())}:${pad2(at.getSeconds())}`;
  return `${date}T${time}${sign}${pad2(Math.floor(abs / 60))}:${pad2(abs % 60)}`;
}

/** A compact UTC stamp for a filename: `20260729T140311Z`. */
function fileStamp(at: Date): string {
  return `${at
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, '')}Z`;
}

/**
 * Reduce a host to something every filesystem accepts. A colon (a port) and a path separator are
 * the two that actually break, but the allowlist is deliberately narrow rather than a blocklist —
 * a filename is not the place to discover a new hostile character.
 */
export function safeFilenamePart(value: string): string {
  const cleaned = value
    .normalize('NFKD')
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/^[-.]+|[-.]+$/g, '')
    .slice(0, 48);
  return cleaned === '' ? 'instance' : cleaned;
}

/** `chancela-diagnostics-<host>-<utc-stamp>.txt`. */
export function diagnosticsFilename(host: string, at: Date): string {
  return `chancela-diagnostics-${safeFilenamePart(host)}-${fileStamp(at)}.txt`;
}
