import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { SettingsPage } from './SettingsPage';
import { DEFAULT_SETTINGS } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  method: string;
  body: string | null;
}

const PERMISSION_CATALOG = {
  permissions: [
    { permission: 'ledger.read', meta: false },
    { permission: 'entity.read', meta: false },
    { permission: 'role.manage', meta: true },
  ],
};

const API_KEY_ONE = {
  id: 'key-1',
  name: 'ERP bridge',
  prefix: 'chk_ab12cd34ef56',
  grant: {
    kind: 'permissions',
    permissions: ['ledger.read'],
    scope: { kind: 'global' },
  },
  created_by: 'user-1',
  created_at: '2026-07-09T10:00:00Z',
  revoked: false,
  active: true,
  rate_limit: { rpm: 60, burst: 20 },
};

type ApiKeyMetadata = typeof API_KEY_ONE;

const API_KEY_REVOKED: ApiKeyMetadata = {
  ...API_KEY_ONE,
  id: 'key-revoked',
  name: 'Retired bridge',
  prefix: 'chk_revoked',
  revoked: true,
  active: false,
};

const REGISTRY_AUTO_UPDATE_PLAN = {
  generated_at: '2026-07-09T10:00:00Z',
  dry_run_only: true,
  config: DEFAULT_SETTINGS.registry_auto_update,
  due: [
    {
      entity_id: 'ent-1',
      entity_name: 'Acme, S.A.',
      entity_profile: 'SociedadeAnonima',
      retrieved_at: '2026-05-01T10:00:00Z',
      age_hours: 1656,
      stale_threshold_hours: 720,
      code_masked: '1234********9012',
      status: 'due',
      reason: 'stale',
      next_allowed_at: null,
    },
  ],
  skipped: {
    disabled: 1,
    fresh: 2,
    backoff: 0,
    running: 0,
    orphaned: 0,
    capped: 0,
  },
  notes: [],
};

const PROCESSOR_ONE = {
  id: 'processor-1',
  name: 'Cloud Processor',
  purpose: 'Alojamento da aplicação',
  legal_basis: 'Contrato',
  data_categories: ['Identificação', 'Contactos'],
  subprocessors: ['EU Backup SARL'],
  risk_level: 'medium',
  status: 'draft',
  created_at: '2026-07-09T10:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T10:00:00Z',
  updated_by: 'amelia.marques',
};

const DPIA_ONE = {
  id: 'dpia-1',
  title: 'Marketing profiling',
  purpose: 'Segmentação de comunicações',
  legal_basis: 'Interesse legítimo',
  data_categories: ['Comportamento'],
  subprocessors: ['Analytics Processor SA'],
  risk_level: 'high',
  status: 'under_review',
  created_at: '2026-07-09T11:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T11:00:00Z',
  updated_by: 'amelia.marques',
};

const BREACH_PLAYBOOK_ONE = {
  id: 'breach-1',
  title: 'Suspected account compromise',
  scope: 'account-access',
  detection_channels: ['SIEM alert'],
  containment_steps: ['Disable sessions'],
  notification_roles: ['DPO'],
  authority_notification_window: '72 hours when required',
  subject_notification_guidance: 'Notify high-risk subjects.',
  risk_level: 'high',
  status: 'active',
  review_notes: 'Annual review.',
  evidence_receipts: [
    {
      id: 'breach-receipt-1',
      evidence_type: 'drill',
      recorded_at: '2026-07-09T12:10:00Z',
      recorded_by: 'amelia.marques',
      notes: 'Tabletop drill only.',
      authority_notified: false,
      subjects_notified: false,
    },
  ],
  created_at: '2026-07-09T12:00:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T12:00:00Z',
  updated_by: 'amelia.marques',
};

const TRANSFER_CONTROL_ONE = {
  id: 'transfer-1',
  name: 'EU to UK support access',
  purpose: 'Support ticket investigation',
  legal_basis: 'Contract',
  data_categories: ['Support messages'],
  recipient: 'UK Support Ltd',
  destination_country: 'United Kingdom',
  transfer_mechanism: 'UK adequacy regulation',
  safeguards: ['Ticket-scoped access'],
  risk_level: 'medium',
  status: 'draft',
  review_notes: 'Quarterly review.',
  evidence_receipts: [
    {
      id: 'transfer-receipt-1',
      recorded_at: '2026-07-09T12:40:00Z',
      recorded_by: 'amelia.marques',
      notes: 'Control review only.',
      transfer_approved: false,
      data_transfer_executed: false,
    },
  ],
  created_at: '2026-07-09T12:30:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T12:30:00Z',
  updated_by: 'amelia.marques',
};

const RETENTION_POLICY_ONE = {
  id: 'retention-1',
  name: 'Mensagens de suporte',
  scope: 'support',
  category: 'messages',
  schedule_id: 'support-messages-v1',
  retention_period: 'P2Y',
  legal_basis: 'Obrigação contratual',
  disposal_action: 'delete',
  status: 'active',
  active: true,
  notes: 'Revisão antes de qualquer descarte.',
  created_at: '2026-07-09T12:50:00Z',
  created_by: 'amelia.marques',
  updated_at: '2026-07-09T12:50:00Z',
  updated_by: 'amelia.marques',
};

type ProcessorRecordMetadata = typeof PROCESSOR_ONE;
type DpiaRecordMetadata = typeof DPIA_ONE;
type BreachPlaybookMetadata = typeof BREACH_PLAYBOOK_ONE;
type TransferControlMetadata = typeof TRANSFER_CONTROL_ONE;
type RetentionPolicyMetadata = typeof RETENTION_POLICY_ONE;

function apiKeyIdFromUrl(url: string): string | undefined {
  return url.match(/\/v1\/api-keys\/([^/]+)/)?.[1];
}

function privacyRecordIdFromUrl(
  url: string,
  root: 'processors' | 'dpias' | 'breach-playbooks' | 'transfer-controls' | 'retention-policies',
): string | undefined {
  return url.match(new RegExp(`/v1/privacy/${root}/([^/]+)`))?.[1];
}

type TestSettings = typeof DEFAULT_SETTINGS;

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function materializeSettings(value: unknown): TestSettings {
  const partial = cloneJson(value) as Partial<TestSettings>;
  const platform = partial.platform ?? DEFAULT_SETTINGS.platform;
  const logging = platform.logging ?? DEFAULT_SETTINGS.platform.logging;
  return {
    ...DEFAULT_SETTINGS,
    ...partial,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      ...(partial.signing ?? {}),
      cmd: { ...DEFAULT_SETTINGS.signing.cmd, ...(partial.signing?.cmd ?? {}) },
      providers: partial.signing?.providers ?? DEFAULT_SETTINGS.signing.providers,
    },
    ai: { ...DEFAULT_SETTINGS.ai, ...(partial.ai ?? {}) },
    ui: {
      ...DEFAULT_SETTINGS.ui,
      ...(partial.ui ?? {}),
      registered_entity_columns:
        partial.ui?.registered_entity_columns ?? DEFAULT_SETTINGS.ui.registered_entity_columns,
    },
    registry_auto_update: {
      ...DEFAULT_SETTINGS.registry_auto_update,
      ...(partial.registry_auto_update ?? {}),
      cadence:
        partial.registry_auto_update?.cadence ?? DEFAULT_SETTINGS.registry_auto_update.cadence,
      entity_defaults: {
        ...DEFAULT_SETTINGS.registry_auto_update.entity_defaults,
        ...(partial.registry_auto_update?.entity_defaults ?? {}),
        enabled_profiles:
          partial.registry_auto_update?.entity_defaults?.enabled_profiles ??
          DEFAULT_SETTINGS.registry_auto_update.entity_defaults.enabled_profiles,
      },
    },
    platform: {
      ...DEFAULT_SETTINGS.platform,
      ...platform,
      logging: {
        ...DEFAULT_SETTINGS.platform.logging,
        ...logging,
        service_overrides:
          logging.service_overrides ?? DEFAULT_SETTINGS.platform.logging.service_overrides,
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
  };
}

function platformActionCapabilities(serviceId: 'api' | 'mcp_stdio') {
  if (serviceId === 'api') {
    return [
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
    ];
  }
  return ['start', 'stop', 'restart'].map((action) => ({
    action,
    supported: false,
    outcome: 'supervisor_required',
    limitation:
      'The stdio MCP server is launched externally; the API can only record desired state.',
  }));
}

function platformServiceStatus(settings: TestSettings, serviceId: 'api' | 'mcp_stdio') {
  if (serviceId === 'api') {
    return {
      id: 'api',
      kind: 'api',
      label: 'Chancela API server',
      configured: true,
      enabled: settings.platform.api_server.enabled,
      desired_state: settings.platform.api_server.desired_state,
      actual_runtime_status: 'running',
      controllable_actions: platformActionCapabilities('api'),
      logging_level:
        settings.platform.logging.service_overrides.api ?? settings.platform.logging.api,
      last_action: settings.platform.api_server.last_action,
      limitations: [
        'The API can observe this process as running only because it is serving this request.',
        'Start, stop, and restart require an external supervisor or process relaunch.',
      ],
    };
  }
  return {
    id: 'mcp_stdio',
    kind: 'mcp',
    label: 'Chancela MCP stdio server',
    configured: false,
    enabled: settings.platform.mcp_stdio_server.enabled,
    desired_state: settings.platform.mcp_stdio_server.desired_state,
    actual_runtime_status: 'unknown',
    controllable_actions: platformActionCapabilities('mcp_stdio'),
    logging_level:
      settings.platform.logging.service_overrides.mcp_stdio ?? settings.platform.logging.mcp,
    last_action: settings.platform.mcp_stdio_server.last_action,
    limitations: [
      'The stdio MCP server is launched by an external client or supervisor; the API cannot observe or spawn that process.',
      'No MCP API key or other secret is exposed through this status surface.',
    ],
  };
}

function platformServicesResponse(settings: TestSettings) {
  return {
    services: [
      platformServiceStatus(settings, 'api'),
      platformServiceStatus(settings, 'mcp_stdio'),
    ],
  };
}

const PLATFORM_LOG_LIMITATIONS = [
  'This is an in-memory API-owned structured log ring; entries reset when the API process restarts.',
  'It is not historical stdout/stderr tailing and does not include MCP process logs unless a future supervisor forwards structured events into the API.',
];

const PLATFORM_LOG_FIXTURE = [
  {
    id: 'platform-log-1',
    seq: 1,
    timestamp: '2026-07-09T12:00:00Z',
    service_id: 'api',
    level: 'info',
    target: 'platform.services',
    message: 'Platform service status read',
    context: { service_count: 2 },
  },
  {
    id: 'platform-log-2',
    seq: 2,
    timestamp: '2026-07-09T12:01:00Z',
    service_id: 'mcp_stdio',
    level: 'warn',
    target: 'platform.service.control',
    message: 'MCP supervisor handoff recorded',
  },
] as const;

function platformOutcome(serviceId: 'api' | 'mcp_stdio', action: string) {
  if (serviceId === 'api' && action === 'restart') return 'restart_required';
  if (serviceId === 'api') return 'unsupported';
  return 'supervisor_required';
}

function platformMessage(serviceId: 'api' | 'mcp_stdio', action: string) {
  if (serviceId === 'api' && action === 'restart') {
    return 'API restart desired state was recorded; an external supervisor must restart the process.';
  }
  if (serviceId === 'api' && action === 'start') {
    return 'API start desired state was recorded, but this already-running process cannot start itself.';
  }
  if (serviceId === 'api') {
    return 'API stop desired state was recorded, but this process cannot terminate itself safely through the API.';
  }
  if (action === 'start') {
    return 'MCP start desired state was recorded; relaunch the external MCP client or supervisor.';
  }
  if (action === 'stop') {
    return 'MCP stop desired state was recorded; stop or relaunch the external MCP client or supervisor.';
  }
  return 'MCP restart desired state was recorded; relaunch the external MCP client or supervisor.';
}

/**
 * A fetch stub for the settings page's endpoints. Captures every call so a test
 * can assert what the PUT sent. The PUT echoes the posted document (schema stamped),
 * mirroring the real server.
 */
function settingsFetch(
  initialSettings: unknown = DEFAULT_SETTINGS,
  options: {
    platformLogs?: readonly unknown[];
    platformLogLimitations?: string[];
  } = {},
): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let storedSettings: unknown = cloneJson(initialSettings);
  let platformLogs = cloneJson(options.platformLogs ?? PLATFORM_LOG_FIXTURE) as Array<
    Record<string, unknown>
  >;
  const platformLogLimitations = options.platformLogLimitations ?? PLATFORM_LOG_LIMITATIONS;
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/platform/logs')) {
      const parsed = new URL(url, 'http://test.local');
      const serviceId = parsed.searchParams.get('service_id');
      const level = parsed.searchParams.get('level');
      const tail = Number(parsed.searchParams.get('tail') ?? '100');
      const logs = platformLogs
        .filter((entry) => !serviceId || entry.service_id === serviceId)
        .filter((entry) => !level || entry.level === level)
        .slice(-tail);
      return Promise.resolve(
        jsonResponse({
          logs,
          tail,
          order: 'chronological',
          limitations: platformLogLimitations,
        }),
      );
    }

    if (url.includes('/v1/platform/services')) {
      if (method === 'POST') {
        const match = url.match(/\/v1\/platform\/services\/([^/]+)\/actions\/([^/?]+)/);
        const serviceId = decodeURIComponent(match?.[1] ?? '') as 'api' | 'mcp_stdio';
        const action = decodeURIComponent(match?.[2] ?? '') as 'start' | 'stop' | 'restart';
        const desired_state = (action === 'stop' ? 'stopped' : 'running') as 'running' | 'stopped';
        const outcome = platformOutcome(serviceId, action) as
          'unsupported' | 'restart_required' | 'supervisor_required';
        const message = platformMessage(serviceId, action);
        const current = materializeSettings(storedSettings);
        const last_action = {
          action,
          requested_at: '2026-07-09T12:00:00Z',
          requested_by: 'amelia.marques',
          outcome,
          message,
        };
        const controlKey = serviceId === 'api' ? 'api_server' : 'mcp_stdio_server';
        current.platform[controlKey] = {
          ...current.platform[controlKey],
          enabled: desired_state === 'running',
          desired_state,
          last_action,
        };
        current.platform.audit = [
          ...current.platform.audit,
          {
            service_id: serviceId,
            action,
            requested_at: last_action.requested_at,
            requested_by: last_action.requested_by,
            outcome,
            desired_state,
            message,
          },
        ].slice(-100);
        storedSettings = { ...(cloneJson(storedSettings) as object), platform: current.platform };
        const service = platformServiceStatus(current, serviceId);
        platformLogs = [
          ...platformLogs,
          {
            id: `platform-log-${platformLogs.length + 1}`,
            seq: platformLogs.length + 1,
            timestamp: '2026-07-09T12:02:00Z',
            service_id: serviceId,
            level: 'info',
            target: 'platform.service.control',
            message: 'Platform service control desired state recorded',
            context: { action, outcome, applied_to_settings: true },
          },
        ];
        return Promise.resolve(
          jsonResponse({
            service,
            action,
            result: {
              kind: outcome,
              supported: false,
              applied_to_settings: true,
              desired_state,
              actual_runtime_status: service.actual_runtime_status,
              message,
              limitations: service.limitations,
            },
          }),
        );
      }
      return Promise.resolve(
        jsonResponse(platformServicesResponse(materializeSettings(storedSettings))),
      );
    }
    if (url.includes('/v1/settings')) {
      if (method === 'PUT') {
        const parsed = JSON.parse(init?.body as string) as Record<string, unknown>;
        storedSettings = { ...parsed, schema_version: 1 };
        return Promise.resolve(jsonResponse(storedSettings));
      }
      return Promise.resolve(jsonResponse(storedSettings));
    }
    if (url.includes('/v1/registry/lookup')) {
      return Promise.resolve(jsonResponse(REGISTRY_AUTO_UPDATE_PLAN));
    }
    if (/\/v1\/entities\/[^/]+\/registry/.test(url) && method === 'POST') {
      return Promise.resolve(
        jsonResponse({
          accepted: true,
          entity_id: 'ent-1',
          status: 'manual_required',
          generated_at: '2026-07-09T10:01:00Z',
          dry_run_only: true,
          reason: 'manual dry run',
          last_attempt_at: '2026-07-09T10:01:00Z',
          next_allowed_at: null,
          failure_count: 0,
          audit_event_seq: 42,
        }),
      );
    }
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
    }
    if (url.includes('/health')) {
      return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function settingsWithoutAi(): Omit<typeof DEFAULT_SETTINGS, 'ai'> {
  const copy: Partial<typeof DEFAULT_SETTINGS> = { ...DEFAULT_SETTINGS };
  delete copy.ai;
  return copy as Omit<typeof DEFAULT_SETTINGS, 'ai'>;
}

function settingsWithoutProviderMetadata(): unknown {
  return {
    ...DEFAULT_SETTINGS,
    signing: {
      ...DEFAULT_SETTINGS.signing,
      providers: undefined,
    },
  };
}

function apiKeysFetch(initialKeys: ApiKeyMetadata[] = [API_KEY_ONE]): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let keys = initialKeys.map((key) => ({
    ...key,
    grant: {
      ...key.grant,
      permissions: [...key.grant.permissions],
      scope: { ...key.grant.scope },
    },
    rate_limit: key.rate_limit ? { ...key.rate_limit } : undefined,
  }));
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/api-keys/') && method === 'POST' && url.endsWith('/rotate')) {
      const id = apiKeyIdFromUrl(url);
      const existing = keys.find((k) => k.id === id);
      if (!existing) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const rotated = {
        ...existing,
        secret: 'chk_rotated_plaintext_secret',
        prefix: 'chk_rotated',
        revoked: false,
        active: true,
      };
      keys = keys.map((k) =>
        k.id === id
          ? {
              ...k,
              prefix: rotated.prefix,
              revoked: rotated.revoked,
              active: rotated.active,
            }
          : k,
      );
      return Promise.resolve(jsonResponse(rotated));
    }
    if (url.includes('/v1/api-keys/') && method === 'DELETE') {
      const id = apiKeyIdFromUrl(url);
      const updated = { ...keys.find((k) => k.id === id)!, revoked: true, active: false };
      keys = keys.map((k) => (k.id === id ? updated : k));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/api-keys')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Record<string, unknown>;
        const name = body.name as string;
        const grant = body.grant as typeof API_KEY_ONE.grant;
        const rate_limit = body.rate_limit as typeof API_KEY_ONE.rate_limit;
        const created = {
          id: 'key-2',
          secret: 'chk_new_plaintext_secret',
          prefix: 'chk_new',
          created_by: 'user-1',
          created_at: '2026-07-09T11:00:00Z',
          revoked: false,
          active: true,
          name,
          grant,
          rate_limit,
        };
        keys = [
          ...keys,
          {
            id: created.id,
            name: created.name,
            prefix: created.prefix,
            grant: created.grant,
            created_by: created.created_by,
            created_at: created.created_at,
            revoked: created.revoked,
            active: created.active,
            rate_limit: created.rate_limit,
          },
        ];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(keys));
    }
    if (url.includes('/v1/permissions')) return Promise.resolve(jsonResponse(PERMISSION_CATALOG));
    if (url.includes('/v1/entities')) return Promise.resolve(jsonResponse([]));
    if (url.includes('/v1/books')) return Promise.resolve(jsonResponse([]));
    if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
    }
    if (url.includes('/health')) {
      return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

function privacyFetch(
  initialProcessors: ProcessorRecordMetadata[] = [PROCESSOR_ONE],
  initialDpias: DpiaRecordMetadata[] = [DPIA_ONE],
  initialBreachPlaybooks: BreachPlaybookMetadata[] = [BREACH_PLAYBOOK_ONE],
  initialTransferControls: TransferControlMetadata[] = [TRANSFER_CONTROL_ONE],
  initialRetentionPolicies: RetentionPolicyMetadata[] = [RETENTION_POLICY_ONE],
): {
  fn: typeof fetch;
  calls: Recorded[];
} {
  const calls: Recorded[] = [];
  let processors = initialProcessors.map((record) => ({
    ...record,
    data_categories: [...record.data_categories],
    subprocessors: [...record.subprocessors],
  }));
  let dpias = initialDpias.map((record) => ({
    ...record,
    data_categories: [...record.data_categories],
    subprocessors: [...record.subprocessors],
  }));
  let breachPlaybooks = initialBreachPlaybooks.map((record) => ({
    ...record,
    detection_channels: [...record.detection_channels],
    containment_steps: [...record.containment_steps],
    notification_roles: [...record.notification_roles],
    evidence_receipts: [...record.evidence_receipts],
  }));
  let transferControls = initialTransferControls.map((record) => ({
    ...record,
    data_categories: [...record.data_categories],
    safeguards: [...record.safeguards],
    evidence_receipts: [...record.evidence_receipts],
  }));
  let retentionPolicies = initialRetentionPolicies.map((record) => ({ ...record }));

  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/privacy/processors/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'processors');
      const patch = JSON.parse(init?.body as string) as Partial<ProcessorRecordMetadata>;
      const current = processors.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const updated = {
        ...current,
        ...patch,
        updated_at: '2026-07-09T12:00:00Z',
        updated_by: 'amelia.marques',
      };
      processors = processors.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/dpias/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'dpias');
      const patch = JSON.parse(init?.body as string) as Partial<DpiaRecordMetadata>;
      const current = dpias.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const updated = {
        ...current,
        ...patch,
        updated_at: '2026-07-09T12:00:00Z',
        updated_by: 'amelia.marques',
      };
      dpias = dpias.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/breach-playbooks/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'breach-playbooks');
      const patch = JSON.parse(init?.body as string) as Partial<BreachPlaybookMetadata> & {
        evidence_receipt?: { evidence_type?: 'review' | 'drill'; notes?: string };
      };
      const current = breachPlaybooks.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const { evidence_receipt: receiptInput, ...recordPatch } = patch;
      const updated = {
        ...current,
        ...recordPatch,
        evidence_receipts: receiptInput
          ? [
              ...current.evidence_receipts,
              {
                id: 'breach-receipt-patch',
                evidence_type: receiptInput.evidence_type ?? 'review',
                recorded_at: '2026-07-09T13:00:00Z',
                recorded_by: 'amelia.marques',
                notes: receiptInput.notes ?? '',
                authority_notified: false,
                subjects_notified: false,
              },
            ]
          : current.evidence_receipts,
        updated_at: '2026-07-09T13:00:00Z',
        updated_by: 'amelia.marques',
      };
      breachPlaybooks = breachPlaybooks.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/transfer-controls/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'transfer-controls');
      const patch = JSON.parse(init?.body as string) as Partial<TransferControlMetadata> & {
        evidence_receipt?: { notes?: string };
      };
      const current = transferControls.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const { evidence_receipt: receiptInput, ...recordPatch } = patch;
      const updated = {
        ...current,
        ...recordPatch,
        evidence_receipts: receiptInput
          ? [
              ...current.evidence_receipts,
              {
                id: 'transfer-receipt-patch',
                recorded_at: '2026-07-09T13:00:00Z',
                recorded_by: 'amelia.marques',
                notes: receiptInput.notes ?? '',
                transfer_approved: false,
                data_transfer_executed: false,
              },
            ]
          : current.evidence_receipts,
        updated_at: '2026-07-09T13:00:00Z',
        updated_by: 'amelia.marques',
      };
      transferControls = transferControls.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/retention-policies/') && method === 'PATCH') {
      const id = privacyRecordIdFromUrl(url, 'retention-policies');
      const patch = JSON.parse(init?.body as string) as Partial<RetentionPolicyMetadata>;
      const current = retentionPolicies.find((record) => record.id === id);
      if (!current) return Promise.resolve(jsonResponse({ error: 'not found' }, 404));
      const updated = {
        ...current,
        ...patch,
        updated_at: '2026-07-09T13:20:00Z',
        updated_by: 'amelia.marques',
      };
      retentionPolicies = retentionPolicies.map((record) => (record.id === id ? updated : record));
      return Promise.resolve(jsonResponse(updated));
    }
    if (url.includes('/v1/privacy/retention-policies/dry-run') && method === 'POST') {
      const body = JSON.parse(init?.body as string) as {
        scope: string;
        category: string;
        record_id?: string;
      };
      const matches = retentionPolicies
        .filter(
          (policy) =>
            policy.scope === body.scope &&
            policy.category === body.category &&
            policy.status === 'active' &&
            policy.active,
        )
        .map((policy) => ({
          policy_id: policy.id,
          name: policy.name,
          scope: policy.scope,
          category: policy.category,
          schedule_id: policy.schedule_id,
          retention_period: policy.retention_period,
          disposal_action: policy.disposal_action,
          status: policy.status,
          active: policy.active,
          destructive_action: ['delete', 'anonymize'].includes(policy.disposal_action),
          would_execute: false,
          reason: 'Dry-run only; no disposal executed.',
        }));
      return Promise.resolve(
        jsonResponse({
          mode: 'dry_run',
          execution_supported: false,
          destructive_execution_supported: false,
          candidate: {
            scope: body.scope,
            category: body.category,
            record_id: body.record_id,
          },
          matched_count: matches.length,
          matches,
        }),
      );
    }
    if (url.includes('/v1/privacy/processors')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<ProcessorRecordMetadata, 'id'>;
        const created = {
          ...body,
          id: 'processor-2',
          created_at: '2026-07-09T12:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T12:00:00Z',
          updated_by: 'amelia.marques',
        };
        processors = [...processors, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(processors));
    }
    if (url.includes('/v1/privacy/dpias')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<DpiaRecordMetadata, 'id'>;
        const created = {
          ...body,
          id: 'dpia-2',
          created_at: '2026-07-09T12:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T12:00:00Z',
          updated_by: 'amelia.marques',
        };
        dpias = [...dpias, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(dpias));
    }
    if (url.includes('/v1/privacy/breach-playbooks')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<BreachPlaybookMetadata, 'id'> & {
          evidence_receipt?: { evidence_type?: 'review' | 'drill'; notes?: string };
        };
        const { evidence_receipt: receiptInput, ...recordBody } = body;
        const created = {
          ...recordBody,
          id: 'breach-2',
          evidence_receipts: receiptInput
            ? [
                {
                  id: 'breach-receipt-2',
                  evidence_type: receiptInput.evidence_type ?? 'review',
                  recorded_at: '2026-07-09T13:00:00Z',
                  recorded_by: 'amelia.marques',
                  notes: receiptInput.notes ?? '',
                  authority_notified: false,
                  subjects_notified: false,
                },
              ]
            : [],
          created_at: '2026-07-09T13:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T13:00:00Z',
          updated_by: 'amelia.marques',
        };
        breachPlaybooks = [...breachPlaybooks, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(breachPlaybooks));
    }
    if (url.includes('/v1/privacy/transfer-controls')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<TransferControlMetadata, 'id'> & {
          evidence_receipt?: { notes?: string };
        };
        const { evidence_receipt: receiptInput, ...recordBody } = body;
        const created = {
          ...recordBody,
          id: 'transfer-2',
          evidence_receipts: receiptInput
            ? [
                {
                  id: 'transfer-receipt-2',
                  recorded_at: '2026-07-09T13:00:00Z',
                  recorded_by: 'amelia.marques',
                  notes: receiptInput.notes ?? '',
                  transfer_approved: false,
                  data_transfer_executed: false,
                },
              ]
            : [],
          created_at: '2026-07-09T13:00:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T13:00:00Z',
          updated_by: 'amelia.marques',
        };
        transferControls = [...transferControls, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(transferControls));
    }
    if (url.includes('/v1/privacy/retention-policies')) {
      if (method === 'POST') {
        const body = JSON.parse(init?.body as string) as Omit<RetentionPolicyMetadata, 'id'>;
        const created = {
          ...body,
          id: 'retention-2',
          created_at: '2026-07-09T13:10:00Z',
          created_by: 'amelia.marques',
          updated_at: '2026-07-09T13:10:00Z',
          updated_by: 'amelia.marques',
        };
        retentionPolicies = [...retentionPolicies, created];
        return Promise.resolve(jsonResponse(created, 201));
      }
      return Promise.resolve(jsonResponse(retentionPolicies));
    }
    if (url.includes('/v1/settings')) return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
    if (url.includes('/v1/ledger/verify')) {
      return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
    }
    if (url.includes('/health')) {
      return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;

  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  document.documentElement.removeAttribute('data-theme');
  document.documentElement.style.removeProperty('--leather-grain-opacity');
});

describe('SettingsPage', () => {
  it('offers a sub-tab per section and shows Aparência by default', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // A segmented sub-tab per section (Gestão included).
    for (const name of [
      'Aparência',
      'Identidade',
      'Documentos',
      'Assinaturas',
      'Gestão',
      'Operações',
      'Sobre',
    ]) {
      expect(await screen.findByRole('button', { name })).toBeTruthy();
    }
    // Aparência is the default section: its theme control is present…
    expect(await screen.findByLabelText('Tema')).toBeTruthy();
    // …while a Documentos-only field is not rendered until that sub-tab is active.
    expect(screen.queryByLabelText('URL de atualização do catálogo CAE')).toBeNull();
  });

  it('deep-links to a section via ?sec= and navigates between sub-tabs', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=documentos']);

    // The deep-linked section renders its field; the default section's does not.
    expect(await screen.findByLabelText('URL de atualização do catálogo CAE')).toBeTruthy();
    expect(screen.queryByLabelText('Tema')).toBeNull();

    // Switching to Sobre surfaces the /health version there.
    fireEvent.click(screen.getByRole('button', { name: 'Sobre' }));
    expect(await screen.findByText('9.9.9')).toBeTruthy();
  });

  it('defaults the AI/MCP tenant gate off when the settings document omits it', async () => {
    const { fn } = settingsFetch(settingsWithoutAi());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar IA/MCP',
    })) as HTMLInputElement;
    expect(toggle.checked).toBe(false);
  });

  it('round-trips an enabled AI/MCP tenant gate through the settings autosave', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar IA/MCP',
    })) as HTMLInputElement;
    fireEvent.click(toggle);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.ai).toEqual({ enabled: true });
  });

  it('hides the AI/MCP tenant gate from users without settings.manage', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission !== 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=gestao'],
    );

    expect(await screen.findByRole('heading', { name: 'Gestão' })).toBeTruthy();
    expect(screen.queryByRole('switch', { name: 'Ativar IA/MCP' })).toBeNull();
  });

  it('shows platform API and MCP status with honest control limitations', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByRole('button', { name: 'Operações' })).toBeTruthy();
    expect(await screen.findByText('Chancela API server')).toBeTruthy();
    expect(await screen.findByText('Chancela MCP stdio server')).toBeTruthy();
    expect(screen.getAllByText('Reinício necessário').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Supervisor necessário').length).toBeGreaterThan(0);
    expect(screen.getByText(/cannot observe or spawn/)).toBeTruthy();
    expect(screen.getAllByRole('button', { name: /Registar reinício/ }).length).toBeGreaterThan(0);
  });

  it('shows AI/MCP provenance assurance to settings managers without secret material', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=operacoes'],
    );

    const title = await screen.findByText('Garantia IA/MCP');
    const panel = title.closest('[role="note"]') as HTMLElement | null;
    expect(panel).toBeTruthy();
    expect(within(panel!).getByText(/O MCP fica inativo/)).toBeTruthy();
    expect(within(panel!).getByText(/RBAC por chave API no servidor/)).toBeTruthy();
    expect(within(panel!).getByText(/draft_minutes e draft_act/)).toBeTruthy();
    expect(within(panel!).getByText(/validate_signature_bundle/)).toBeTruthy();
    expect(panel!.textContent ?? '').not.toMatch(/chk_[A-Za-z0-9_]+|Bearer\s+\S+|plaintext/i);
  });

  it('renders the platform log tail with limitations and expandable context', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByText('Cauda estruturada de logs da API')).toBeTruthy();
    expect(await screen.findByText('Platform service status read')).toBeTruthy();
    expect(screen.getByText(/in-memory API-owned structured log ring/)).toBeTruthy();
    expect(screen.getByText('2 entradas · limite 100 · cronológico')).toBeTruthy();
    expect(screen.getAllByText('Servidor API').length).toBeGreaterThan(0);
    expect(screen.getByText('platform.services')).toBeTruthy();

    const row = screen.getByText('Platform service status read').closest('tr');
    expect(row).toBeTruthy();
    fireEvent.click(within(row!).getByText('Contexto'));
    expect(within(row!).getByText(/service_count/)).toBeTruthy();

    const minimalRow = screen.getByText('MCP supervisor handoff recorded').closest('tr');
    expect(minimalRow).toBeTruthy();
    expect(within(minimalRow!).getByText('Sem contexto')).toBeTruthy();
  });

  it('refetches platform logs with selected filters and manual refresh', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByText('Platform service status read')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Serviço'), { target: { value: 'api' } });
    fireEvent.change(screen.getByLabelText('Nível'), { target: { value: 'info' } });
    fireEvent.change(screen.getByLabelText('Entradas'), { target: { value: '25' } });

    await waitFor(() => {
      expect(
        calls.some((call) => {
          if (!call.url.includes('/v1/platform/logs')) return false;
          const parsed = new URL(call.url, 'http://test.local');
          return (
            parsed.searchParams.get('service_id') === 'api' &&
            parsed.searchParams.get('level') === 'info' &&
            parsed.searchParams.get('tail') === '25'
          );
        }),
      ).toBe(true);
    });

    const refreshButton = await waitFor(() =>
      screen.getByRole('button', { name: 'Atualizar logs' }),
    );
    const beforeRefresh = calls.filter((call) => call.url.includes('/v1/platform/logs')).length;
    fireEvent.click(refreshButton);
    await waitFor(() =>
      expect(calls.filter((call) => call.url.includes('/v1/platform/logs')).length).toBeGreaterThan(
        beforeRefresh,
      ),
    );
  });

  it('shows platform log empty state together with backend limitations', async () => {
    const { fn } = settingsFetch(DEFAULT_SETTINGS, {
      platformLogs: [],
      platformLogLimitations: ['Ring only; no historical process logs are retained.'],
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByText('Sem logs da plataforma')).toBeTruthy();
    expect(screen.getByText('Ring only; no historical process logs are retained.')).toBeTruthy();
    expect(screen.getByText('0 entradas · limite 100 · cronológico')).toBeTruthy();
  });

  it('renders a minimal platform log entry without context', async () => {
    const { fn } = settingsFetch(DEFAULT_SETTINGS, {
      platformLogs: [
        {
          id: 'platform-log-1',
          seq: 1,
          timestamp: '2026-07-09T12:05:00Z',
          service_id: 'app',
          level: 'debug',
          target: 'platform.app',
          message: 'App shell observed platform state',
        },
      ],
    });
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByText('App shell observed platform state')).toBeTruthy();
    expect(screen.getAllByText('Aplicação').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Debug').length).toBeGreaterThan(0);
    expect(screen.getByText('Sem contexto')).toBeTruthy();
  });

  it('records a platform MCP start desired state without implying live process control', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    const mcpRow = (await screen.findByText('Chancela MCP stdio server')).closest('section');
    expect(mcpRow).toBeTruthy();
    fireEvent.click(within(mcpRow!).getByRole('button', { name: /Registar arranque/ }));

    await waitFor(() =>
      expect(
        calls.some(
          (call) =>
            call.method === 'POST' &&
            call.url.includes('/v1/platform/services/mcp_stdio/actions/start'),
        ),
      ).toBe(true),
    );
    expect(
      (await screen.findAllByText(/MCP start desired state was recorded/)).length,
    ).toBeGreaterThan(0);
    expect(screen.getAllByText('Supervisor necessário').length).toBeGreaterThan(0);
    expect((await screen.findAllByText('Operações')).length).toBeGreaterThan(0);
  });

  it('autosaves platform logging levels through the whole settings document', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    const globalLog = (await screen.findByLabelText('Global')) as HTMLSelectElement;
    fireEvent.change(globalLog, { target: { value: 'debug' } });
    const mcpOverride = screen.getByLabelText('MCP stdio') as HTMLSelectElement;
    fireEvent.change(mcpOverride, { target: { value: 'trace' } });

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.platform.logging.global).toBe('debug');
    expect(sent.platform.logging.service_overrides.mcp_stdio).toBe('trace');
    expect(sent.platform.api_server.desired_state).toBe('running');
  });

  it('shows the backend-owned registry auto-update plan and records a dry-run attempt', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    expect(await screen.findByText('Atualização automática da certidão permanente')).toBeTruthy();
    expect(await screen.findByText('Acme, S.A.')).toBeTruthy();
    expect(screen.getByText('Simulação')).toBeTruthy();
    expect(screen.getByText('Por atualizar')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Pedir tentativa' }));

    const resultTitle = await screen.findByText('Resultado da tentativa');
    const resultPanel = resultTitle.closest('[role="note"]');
    expect(resultPanel).toBeTruthy();
    expect(within(resultPanel as HTMLElement).getByText('Revisão manual')).toBeTruthy();

    const attempt = await waitFor(() =>
      calls.find(
        (call) => call.method === 'POST' && call.url.includes('/v1/entities/ent-1/registry'),
      ),
    );
    expect(attempt).toBeTruthy();
    expect(JSON.parse(attempt!.body as string)).toEqual({ dry_run: true });
  });

  it('round-trips registry auto-update settings through the whole-document autosave', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const toggle = (await screen.findByRole('switch', {
      name: 'Ativar trabalhador de atualização',
    })) as HTMLInputElement;
    expect(toggle.checked).toBe(false);
    fireEvent.click(toggle);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.registry_auto_update.enabled).toBe(true);
    expect(sent.registry_auto_update.stale_threshold_hours).toBe(720);
    expect(sent.registry_auto_update.entity_defaults).toEqual({
      enabled: false,
      enabled_profiles: [],
    });
  });

  it('round-trips registered entity table columns through settings autosave', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=gestao']);

    const seat = (await screen.findByRole('switch', { name: 'Sede' })) as HTMLInputElement;
    expect(seat.checked).toBe(false);
    fireEvent.click(seat);

    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.ui.registered_entity_columns).toEqual([
      'Name',
      'Nipc',
      'Seat',
      'Type',
      'LastActivity',
      'Actions',
    ]);
  });

  it('applies the theme override to the document root live', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);
    const themeSelect = (await screen.findByLabelText('Tema')) as HTMLSelectElement;

    fireEvent.change(themeSelect, { target: { value: 'dark' } });
    await waitFor(() => expect(document.documentElement.getAttribute('data-theme')).toBe('dark'));

    fireEvent.change(themeSelect, { target: { value: 'system' } });
    await waitFor(() => expect(document.documentElement.hasAttribute('data-theme')).toBe(false));
  });

  it('scales the grain opacity var from the intensity slider live', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);
    const slider = (await screen.findByRole('slider')) as HTMLInputElement;

    fireEvent.change(slider, { target: { value: '30' } });
    await waitFor(() =>
      expect(document.documentElement.style.getPropertyValue('--leather-grain-opacity')).toBe(
        '0.3',
      ),
    );
  });

  it('PUTs the full settings document via autosave, with edits spanning sub-tabs', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // Edit the org name under Identidade…
    fireEvent.click(await screen.findByRole('button', { name: 'Identidade' }));
    const nameInput = (await screen.findByLabelText('Nome da organização')) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Encosto Estratégico, Lda.' } });

    // …then the CAE URL under Documentos (the working copy spans sub-tabs).
    fireEvent.click(screen.getByRole('button', { name: 'Documentos' }));
    const caeUrl = (await screen.findByLabelText(
      'URL de atualização do catálogo CAE',
    )) as HTMLInputElement;
    fireEvent.change(caeUrl, { target: { value: 'https://catalog.example.pt/cae_dataset.json' } });

    // Autosave is always-on (no manual "Guardar agora" button while enabled): the debounced
    // autosave PUTs the whole document on its own, spanning every edited sub-tab.
    expect(screen.queryByRole('button', { name: 'Guardar agora' })).toBeNull();
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });

    const put = calls.find((c) => c.method === 'PUT');
    expect(put).toBeTruthy();
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    // The whole document is sent, not a partial patch.
    expect(sent.organization.name).toBe('Encosto Estratégico, Lda.');
    expect(sent.appearance).toBeTruthy();
    expect(sent.documents).toBeTruthy();
    expect(sent.signing).toBeTruthy();
    // The audit actor is passed through (attributed from the session, not edited here).
    expect(sent.organization.default_actor).toBe('api');
    // The catalog section (F1b) is part of the whole-document PUT.
    expect(sent.catalog.cae_update_url).toBe('https://catalog.example.pt/cae_dataset.json');
  });

  it('autosaves an edit after the debounce (no explicit save) and confirms with a success toast', async () => {
    const { fn, calls } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);

    const nameInput = (await screen.findByLabelText('Nome da organização')) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Encosto Estratégico, Lda.' } });

    // No button was clicked: the debounced autosave PUTs on its own.
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true), {
      timeout: 3000,
    });
    const put = calls.find((c) => c.method === 'PUT');
    const sent = JSON.parse(put!.body as string) as typeof DEFAULT_SETTINGS;
    expect(sent.organization.name).toBe('Encosto Estratégico, Lda.');

    // Success is a normal toast (not an inline block message).
    expect(await screen.findByText('Configurações guardadas.')).toBeTruthy();
    // The old inline "Guardado" affordance is gone and the save bar collapses on a clean
    // form (nothing left to save → no block, no leftover status text).
    await waitFor(() => expect(screen.queryByText('Guardado')).toBeNull());
    expect(screen.queryByText('Alterações por guardar…')).toBeNull();
  });

  it('raises a toast and keeps an inline error when an autosave fails', async () => {
    const calls: Recorded[] = [];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      calls.push({ url, method, body: (init?.body as string) ?? null });
      if (url.includes('/v1/settings')) {
        if (method === 'PUT') {
          return Promise.resolve(jsonResponse({ error: 'Falha ao guardar' }, 500));
        }
        return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      }
      if (url.includes('/v1/ledger/verify'))
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      if (url.includes('/health'))
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);

    const nameInput = (await screen.findByLabelText('Nome da organização')) as HTMLInputElement;
    fireEvent.change(nameInput, { target: { value: 'Encosto Estratégico, Lda.' } });

    // The failed autosave surfaces an assertive toast…
    const alert = await screen.findByRole('alert', undefined, { timeout: 3000 });
    expect(alert.textContent).toContain('Falha ao guardar');
    // …and the field stays editable (retryable). Autosave is on, so there is no persistent
    // "Guardar agora"; the error state instead exposes a retry affordance so the save is
    // still recoverable.
    expect(nameInput.disabled).toBe(false);
    expect(screen.queryByRole('button', { name: 'Guardar agora' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Tentar novamente' })).toBeTruthy();
  });

  it('hides "Guardar agora" while autosave is enabled (no persistent flush button)', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    const { container } = renderWithProviders(<SettingsPage />, ['/configuracoes?sec=identidade']);

    // The section loaded (its field is present) but the manual flush button is not shown —
    // autosave is always-on today.
    await screen.findByLabelText('Nome da organização');
    expect(screen.queryByRole('button', { name: 'Guardar agora' })).toBeNull();
    // On a clean (untouched) form there is no save bar block at all — it appears only to
    // report a failed save while autosave is enabled.
    expect(container.querySelector('.settings-savebar')).toBeNull();
  });

  it('shows a FieldHelp affordance on config fields (Aparência by default)', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes']);

    // The theme control is present…
    expect(await screen.findByLabelText('Tema')).toBeTruthy();
    // …and at least one help trigger (accessible name "Ajuda") sits beside a field.
    expect(screen.getAllByRole('button', { name: 'Ajuda' }).length).toBeGreaterThan(0);
  });

  it('hosts a Utilizadores sub-tab that lists users inline', async () => {
    const users = [
      {
        id: 'u1',
        username: 'amelia.marques',
        display_name: 'Amélia Marques',
        active: true,
        has_secret: true,
        has_attestation_key: false,
        has_recovery_phrase: false,
      },
    ];
    const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (url.includes('/v1/users')) return Promise.resolve(jsonResponse(users));
      if (url.includes('/v1/settings')) {
        if (method === 'PUT') return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
        return Promise.resolve(jsonResponse(DEFAULT_SETTINGS));
      }
      if (url.includes('/v1/ledger/verify'))
        return Promise.resolve(jsonResponse({ valid: true, length: 3 }));
      if (url.includes('/health'))
        return Promise.resolve(jsonResponse({ status: 'ok', version: '9.9.9' }));
      return Promise.reject(new Error(`no stub for ${url}`));
    }) as typeof fetch;
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=utilizadores']);

    // The sub-tab button exists and the roster renders inline (the fictional example user).
    expect(await screen.findByRole('button', { name: 'Utilizadores' })).toBeTruthy();
    expect(await screen.findByText('amelia.marques')).toBeTruthy();
    // The inline "novo utilizador" action stays inside the settings users section.
    const novo = screen.getByRole('link', { name: /novo utilizador/i });
    expect(novo.getAttribute('href')).toBe('/configuracoes?sec=utilizadores&user=novo');
  });

  it('hosts privacy/compliance processor and DPIA registers with search and filters', async () => {
    const { fn } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    expect(await screen.findByRole('button', { name: 'Privacidade' })).toBeTruthy();
    expect(await screen.findByText('Cloud Processor')).toBeTruthy();
    expect(await screen.findByText('Marketing profiling')).toBeTruthy();

    const dpiaPanel = screen.getByText('DPIAs').closest('section');
    expect(dpiaPanel).toBeTruthy();
    fireEvent.change(within(dpiaPanel!).getByLabelText('Pesquisar'), {
      target: { value: 'marketing' },
    });
    expect(within(dpiaPanel!).getByText('Marketing profiling')).toBeTruthy();

    fireEvent.change(within(dpiaPanel!).getByLabelText('Risco'), {
      target: { value: 'critical' },
    });
    expect(await within(dpiaPanel!).findByText('Sem resultados')).toBeTruthy();
  });

  it('creates and patches GDPR processor records from the privacy settings tab', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    const processorPanel = (await screen.findByText('Processadores GDPR')).closest('section');
    expect(processorPanel).toBeTruthy();
    fireEvent.click(within(processorPanel!).getByRole('button', { name: 'Novo registo' }));

    const formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    const form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Nome do processador'), {
      target: { value: 'Payroll Processor' },
    });
    fireEvent.change(within(form!).getByLabelText('Finalidade'), {
      target: { value: 'Processamento salarial' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Contrato de trabalho' },
    });
    fireEvent.change(within(form!).getByLabelText('Categorias de dados'), {
      target: { value: 'Identificação\nRemuneração' },
    });
    fireEvent.change(within(form!).getByLabelText('Subprocessadores'), {
      target: { value: 'Payroll Backup SA' },
    });
    fireEvent.change(within(form!).getByLabelText('Risco'), { target: { value: 'high' } });
    fireEvent.change(within(form!).getByLabelText('Estado'), { target: { value: 'active' } });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const post = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/processors'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(post!.body as string)).toMatchObject({
      name: 'Payroll Processor',
      purpose: 'Processamento salarial',
      legal_basis: 'Contrato de trabalho',
      data_categories: ['Identificação', 'Remuneração'],
      subprocessors: ['Payroll Backup SA'],
      risk_level: 'high',
      status: 'active',
    });
    expect(await screen.findByText('Payroll Processor')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Estado de Payroll Processor'), {
      target: { value: 'under_review' },
    });

    const patch = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'PATCH' &&
          c.url.endsWith('/v1/privacy/processors/processor-2') &&
          c.body?.includes('under_review'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(patch!.body as string)).toEqual({ status: 'under_review' });
  });

  it('creates breach playbook and transfer-control records from the privacy settings tab', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    const breachPanel = (await screen.findByText('Playbooks de resposta a violações')).closest(
      'section',
    );
    expect(breachPanel).toBeTruthy();
    expect(await within(breachPanel!).findByText('Suspected account compromise')).toBeTruthy();
    expect(await within(breachPanel!).findByText(/Sem notificação à autoridade/)).toBeTruthy();
    fireEvent.click(within(breachPanel!).getByRole('button', { name: 'Novo registo' }));

    let formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    let form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Título do playbook'), {
      target: { value: 'Suspected exfiltration' },
    });
    fireEvent.change(within(form!).getByLabelText('Âmbito'), {
      target: { value: 'document exports' },
    });
    fireEvent.change(within(form!).getByLabelText('Canais de deteção'), {
      target: { value: 'DLP alert\nSupport report' },
    });
    fireEvent.change(within(form!).getByLabelText('Passos de contenção'), {
      target: { value: 'Disable export\nPreserve evidence' },
    });
    fireEvent.change(within(form!).getByLabelText('Funções notificadas'), {
      target: { value: 'DPO' },
    });
    fireEvent.change(within(form!).getByLabelText('Notas de evidência'), {
      target: { value: 'Operator tabletop evidence only.' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const breachPost = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/breach-playbooks'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(breachPost.body as string)).toMatchObject({
      title: 'Suspected exfiltration',
      scope: 'document exports',
      detection_channels: ['DLP alert', 'Support report'],
      containment_steps: ['Disable export', 'Preserve evidence'],
      notification_roles: ['DPO'],
      risk_level: 'high',
      status: 'draft',
      evidence_receipt: {
        evidence_type: 'review',
        notes: 'Operator tabletop evidence only.',
        authority_notified: false,
        subjects_notified: false,
      },
    });
    expect(await screen.findByText('Suspected exfiltration')).toBeTruthy();

    const transferPanel = (await screen.findByText('Controlos de transferência')).closest(
      'section',
    );
    expect(transferPanel).toBeTruthy();
    expect(await within(transferPanel!).findByText('EU to UK support access')).toBeTruthy();
    expect(await within(transferPanel!).findByText(/Sem aprovação/)).toBeTruthy();
    fireEvent.click(within(transferPanel!).getByRole('button', { name: 'Novo registo' }));

    formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Nome do controlo'), {
      target: { value: 'EU to US analytics export' },
    });
    fireEvent.change(within(form!).getByLabelText('Finalidade'), {
      target: { value: 'Product analytics' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Legitimate interest' },
    });
    fireEvent.change(within(form!).getByLabelText('Categorias de dados'), {
      target: { value: 'Usage metrics\nAccount metadata' },
    });
    fireEvent.change(within(form!).getByLabelText('Destinatário'), {
      target: { value: 'Analytics Inc' },
    });
    fireEvent.change(within(form!).getByLabelText('País de destino'), {
      target: { value: 'United States' },
    });
    fireEvent.change(within(form!).getByLabelText('Mecanismo de transferência'), {
      target: { value: 'SCCs' },
    });
    fireEvent.change(within(form!).getByLabelText('Salvaguardas'), {
      target: { value: 'Pseudonymisation\nAccess review' },
    });
    fireEvent.change(within(form!).getByLabelText('Notas de evidência'), {
      target: { value: 'Operator transfer-control review only.' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const transferPost = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/transfer-controls'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(transferPost.body as string)).toMatchObject({
      name: 'EU to US analytics export',
      purpose: 'Product analytics',
      legal_basis: 'Legitimate interest',
      data_categories: ['Usage metrics', 'Account metadata'],
      recipient: 'Analytics Inc',
      destination_country: 'United States',
      transfer_mechanism: 'SCCs',
      safeguards: ['Pseudonymisation', 'Access review'],
      risk_level: 'medium',
      status: 'draft',
      evidence_receipt: {
        notes: 'Operator transfer-control review only.',
        transfer_approved: false,
        data_transfer_executed: false,
      },
    });
    expect(await screen.findByText('EU to US analytics export')).toBeTruthy();
  });

  it('lists, creates, patches, and dry-runs retention policies without destructive execution', async () => {
    const { fn, calls } = privacyFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=privacidade']);

    const retentionPanel = (await screen.findByText('Políticas de retenção')).closest('section');
    expect(retentionPanel).toBeTruthy();
    expect(await within(retentionPanel!).findByText('Mensagens de suporte')).toBeTruthy();
    expect(
      within(retentionPanel!).getByText('destructive_execution_supported: false'),
    ).toBeTruthy();
    fireEvent.click(within(retentionPanel!).getByRole('button', { name: 'Novo registo' }));

    let formCard = await screen.findByRole('heading', { name: 'Novo registo' });
    let form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Nome da política'), {
      target: { value: 'Registos de auditoria' },
    });
    fireEvent.change(within(form!).getByLabelText('Âmbito'), {
      target: { value: 'audit' },
    });
    fireEvent.change(within(form!).getByLabelText('Categoria'), {
      target: { value: 'events' },
    });
    fireEvent.change(within(form!).getByLabelText('Identificador do calendário'), {
      target: { value: 'audit-events-v1' },
    });
    fireEvent.change(within(form!).getByLabelText('Período de retenção'), {
      target: { value: 'P10Y' },
    });
    fireEvent.change(within(form!).getByLabelText('Base legal'), {
      target: { value: 'Obrigação legal' },
    });
    fireEvent.change(within(form!).getByLabelText('Ação prevista'), {
      target: { value: 'archive' },
    });
    fireEvent.change(within(form!).getByLabelText('Estado'), {
      target: { value: 'active' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Criar registo' }));

    const retentionPost = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/retention-policies'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(retentionPost.body as string)).toMatchObject({
      name: 'Registos de auditoria',
      scope: 'audit',
      category: 'events',
      schedule_id: 'audit-events-v1',
      retention_period: 'P10Y',
      legal_basis: 'Obrigação legal',
      disposal_action: 'archive',
      status: 'active',
      active: true,
    });
    expect(await screen.findByText('Registos de auditoria')).toBeTruthy();

    const updatedPanel = screen.getByText('Políticas de retenção').closest('section');
    expect(updatedPanel).toBeTruthy();
    fireEvent.click(within(updatedPanel!).getAllByRole('button', { name: 'Editar' }).at(-1)!);

    formCard = await screen.findByRole('heading', { name: 'Editar registo' });
    form = formCard.closest('section');
    expect(form).toBeTruthy();
    fireEvent.change(within(form!).getByLabelText('Estado'), {
      target: { value: 'suspended' },
    });
    fireEvent.click(within(form!).getByRole('button', { name: 'Guardar alterações' }));

    const retentionPatch = await waitFor(() => {
      const call = calls.find(
        (c) =>
          c.method === 'PATCH' &&
          c.url.endsWith('/v1/privacy/retention-policies/retention-2') &&
          c.body?.includes('suspended'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(retentionPatch.body as string)).toMatchObject({
      status: 'suspended',
      disposal_action: 'archive',
    });

    const dryRunPanel = (await screen.findByText('Simulação de retenção')).closest('section');
    expect(dryRunPanel).toBeTruthy();
    fireEvent.change(within(dryRunPanel!).getByLabelText('Âmbito'), {
      target: { value: 'support' },
    });
    fireEvent.change(within(dryRunPanel!).getByLabelText('Categoria'), {
      target: { value: 'messages' },
    });
    fireEvent.change(within(dryRunPanel!).getByLabelText('ID do registo'), {
      target: { value: 'ticket-123' },
    });
    fireEvent.click(within(dryRunPanel!).getByRole('button', { name: 'Simular retenção' }));

    const dryRun = await waitFor(() => {
      const call = calls.find(
        (c) => c.method === 'POST' && c.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      );
      expect(call).toBeTruthy();
      return call!;
    });
    expect(JSON.parse(dryRun.body as string)).toEqual({
      scope: 'support',
      category: 'messages',
      record_id: 'ticket-123',
    });
    expect(await within(dryRunPanel!).findByText(/destructive_execution_supported:/)).toBeTruthy();
    expect(await within(dryRunPanel!).findByText(/would_execute: false/)).toBeTruthy();
    const retentionCalls = calls.filter((call) =>
      call.url.includes('/v1/privacy/retention-policies'),
    );
    expect(
      retentionCalls.every(
        (call) =>
          call.url.endsWith('/v1/privacy/retention-policies') ||
          call.url.endsWith('/v1/privacy/retention-policies/retention-2') ||
          call.url.endsWith('/v1/privacy/retention-policies/dry-run'),
      ),
    ).toBe(true);
    expect(
      calls.some(
        (call) => /execute|delete|anonymize/.test(call.url) && !call.url.includes('dry-run'),
      ),
    ).toBe(false);
    expect(
      calls.every(
        (call) =>
          !call.body?.includes('execution_request') &&
          !call.body?.includes('execute_supported') &&
          !call.body?.includes('"execute"') &&
          !call.body?.includes('"delete"') &&
          !call.body?.includes('"anonymize"'),
      ),
    ).toBe(true);
  });

  it('matches privacy register permission gating to user.manage or settings.manage', async () => {
    const allowed = privacyFetch();
    vi.stubGlobal('fetch', allowed.fn);

    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'settings.manage')}
      >
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=privacidade'],
    );

    expect(await screen.findByText('Cloud Processor')).toBeTruthy();
    expect(allowed.calls.some((c) => c.url.includes('/v1/privacy/processors'))).toBe(true);

    cleanup();
    const denied = privacyFetch();
    vi.stubGlobal('fetch', denied.fn);

    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <SettingsPage />
      </StaticPermissionsProvider>,
      ['/configuracoes?sec=privacidade'],
    );

    expect(await screen.findByText('Sem permissão')).toBeTruthy();
    expect(denied.calls.some((c) => c.url.includes('/v1/privacy/'))).toBe(false);
  });

  it('resets a signing URL to its default via the icon-only reset button', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    const tsa = (await screen.findByLabelText(
      'URL da autoridade de selo temporal (TSA)',
    )) as HTMLInputElement;
    // The reset control is now an icon-only button; its accessible name comes from the
    // Tooltip `label` (aria-label), so `getByRole(..., { name })` still resolves it (the TSA
    // field's reset is the first of the two).
    const reset = () =>
      screen.getAllByRole('button', { name: 'Repor predefinição' })[0] as HTMLButtonElement;

    // At the default value the reset is inert…
    expect(reset().disabled).toBe(true);

    // …editing away from the default enables it…
    fireEvent.change(tsa, { target: { value: 'https://exemplo.pt/tsa' } });
    expect(reset().disabled).toBe(false);

    // …and clicking it restores the committed default.
    fireEvent.click(reset());
    expect(tsa.value).toBe(DEFAULT_SETTINGS.signing.tsa_url ?? '');
  });

  it('surfaces signing provider modes without secret inputs', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    expect(await screen.findByText('Modos de prestador configurados')).toBeTruthy();
    expect(screen.getByText(/Chave Móvel Digital \(CMD\/SCMD\)/)).toBeTruthy();
    expect(screen.getAllByText(/Cartão de Cidadão/).length).toBeGreaterThan(0);
    expect(screen.getByText(/CSC\/QTSP remote provider/)).toBeTruthy();
    expect(screen.getByText(/Local soft certificate \(PKCS#12\/PFX\)/)).toBeTruthy();
    expect(screen.getAllByText('Bloqueado em produção').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Apenas local').length).toBeGreaterThan(0);
    expect(screen.queryByLabelText(/passphrase|chave privada|private key|pin/i)).toBeNull();
  });

  it('defaults provider metadata when an older settings payload omits it', async () => {
    const { fn } = settingsFetch(settingsWithoutProviderMetadata());
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=assinaturas']);

    expect(await screen.findByText(/Local soft certificate \(PKCS#12\/PFX\)/)).toBeTruthy();
  });

  it('lists API keys as persisted metadata including returned rate limits', async () => {
    const { fn } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    expect(await screen.findByRole('button', { name: 'Chaves API' })).toBeTruthy();
    expect(await screen.findByText('ERP bridge')).toBeTruthy();
    expect(screen.getByText('chk_ab12cd34ef56')).toBeTruthy();
    expect(screen.getByText('60 req/min · rajada 20')).toBeTruthy();
    expect(screen.queryByText('chk_new_plaintext_secret')).toBeNull();
  });

  it('creates an API key with a scoped permission grant and shows the plaintext once', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Nova chave API' }));
    fireEvent.change(await screen.findByLabelText('Nome da chave'), {
      target: { value: 'Ledger export' },
    });
    fireEvent.click(await screen.findByLabelText('ledger.read'));
    fireEvent.change(screen.getByLabelText('Pedidos por minuto'), { target: { value: '120' } });
    fireEvent.change(screen.getByLabelText('Rajada'), { target: { value: '10' } });
    fireEvent.click(screen.getByRole('button', { name: 'Criar chave' }));

    expect(await screen.findByText('Guarde este segredo agora')).toBeTruthy();
    expect(screen.getByText('chk_new_plaintext_secret')).toBeTruthy();
    expect(screen.queryByLabelText('role.manage')).toBeNull();

    const post = await waitFor(() =>
      calls.find((c) => c.method === 'POST' && c.url.includes('/v1/api-keys')),
    );
    expect(JSON.parse(post!.body as string)).toMatchObject({
      name: 'Ledger export',
      grant: {
        kind: 'permissions',
        permissions: ['ledger.read'],
        scope: { kind: 'global' },
      },
      rate_limit: { rpm: 120, burst: 10 },
    });

    fireEvent.click(screen.getByRole('button', { name: 'Concluído' }));
    await waitFor(() => expect(screen.queryByText('chk_new_plaintext_secret')).toBeNull());
    expect(await screen.findByText('chk_new')).toBeTruthy();
  });

  it('rotates an active API key and shows the replacement secret once', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Rodar chave' }));

    expect(await screen.findByText('Guarde este segredo agora')).toBeTruthy();
    expect(screen.getByText('chk_rotated_plaintext_secret')).toBeTruthy();
    await waitFor(() =>
      expect(
        calls.some((c) => c.method === 'POST' && c.url.includes('/v1/api-keys/key-1/rotate')),
      ).toBe(true),
    );

    fireEvent.click(screen.getByRole('button', { name: 'Concluído' }));
    await waitFor(() => expect(screen.queryByText('chk_rotated_plaintext_secret')).toBeNull());
    expect(await screen.findByText('chk_rotated')).toBeTruthy();
  });

  it('does not offer API-key actions for revoked keys', async () => {
    const { fn } = apiKeysFetch([API_KEY_ONE, API_KEY_REVOKED]);
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    const activeRow = (await screen.findByText('ERP bridge')).closest('tr');
    const revokedRow = (await screen.findByText('Retired bridge')).closest('tr');
    expect(activeRow).toBeTruthy();
    expect(revokedRow).toBeTruthy();

    expect(within(activeRow!).getByRole('button', { name: 'Rodar chave' })).toBeTruthy();
    expect(within(revokedRow!).queryByRole('button', { name: 'Rodar chave' })).toBeNull();
    expect(within(revokedRow!).queryByRole('button', { name: 'Revogar' })).toBeNull();
    expect(within(revokedRow!).getByText('—')).toBeTruthy();
  });

  it('revokes API keys from the settings tab', async () => {
    const { fn, calls } = apiKeysFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=chaves-api']);

    fireEvent.click(await screen.findByRole('button', { name: 'Revogar' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirmar revogação' }));

    await waitFor(() =>
      expect(calls.some((c) => c.method === 'DELETE' && c.url.includes('/v1/api-keys/key-1'))).toBe(
        true,
      ),
    );
    expect(await screen.findByText('Revogada')).toBeTruthy();
  });
});
