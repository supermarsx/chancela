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

type ProcessorRecordMetadata = typeof PROCESSOR_ONE;
type DpiaRecordMetadata = typeof DPIA_ONE;

function apiKeyIdFromUrl(url: string): string | undefined {
  return url.match(/\/v1\/api-keys\/([^/]+)/)?.[1];
}

function privacyRecordIdFromUrl(url: string, root: 'processors' | 'dpias'): string | undefined {
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
  'This is an in-memory API log ring; entries reset when the API process restarts.',
  'It is not historical stdout/stderr tailing and does not include MCP process logs unless a future supervisor forwards them.',
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

  it('renders the platform log tail with limitations and expandable context', async () => {
    const { fn } = settingsFetch();
    vi.stubGlobal('fetch', fn);

    renderWithProviders(<SettingsPage />, ['/configuracoes?sec=operacoes']);

    expect(await screen.findByText('Cauda de logs da plataforma')).toBeTruthy();
    expect(await screen.findByText('Platform service status read')).toBeTruthy();
    expect(screen.getByText(/in-memory API log ring/)).toBeTruthy();
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
