import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { RegistryAutoUpdateSection } from './RegistryAutoUpdateSection';
import {
  DEFAULT_SETTINGS,
  type RegistryAutoUpdateCadence,
  type RegistryAutoUpdateSettings,
  type RegistryAutoUpdateStatus,
} from '../../api/types';
import { renderWithProviders } from '../../test/utils';

/**
 * Tests for the registry-auto-update settings section. It is a controlled component
 * (`value` + `onChange`) that also drives two API surfaces via react-query: the dry-run
 * plan (`GET /v1/registry/lookup`) and the per-entity attempt mutation
 * (`POST /v1/entities/{id}/registry`). We stub `fetch` per the sibling settings tests and
 * assert real handler/branch behaviour rather than smoke-rendering.
 */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const BASE_SETTINGS: RegistryAutoUpdateSettings = DEFAULT_SETTINGS.registry_auto_update;

function withCadence(cadence: RegistryAutoUpdateCadence): RegistryAutoUpdateSettings {
  return { ...BASE_SETTINGS, cadence };
}

function planWithDue(overrides: Record<string, unknown> = {}) {
  return {
    generated_at: '2026-07-09T10:00:00Z',
    dry_run_only: true,
    config: BASE_SETTINGS,
    due: [
      {
        entity_id: 'ent-1',
        entity_name: 'Encosto Estratégico Lda',
        entity_profile: 'SociedadePorQuotas',
        retrieved_at: '2026-05-01T10:00:00Z',
        age_hours: 1656,
        stale_threshold_hours: 720,
        code_masked: '1234****9012',
        status: 'due' as RegistryAutoUpdateStatus,
        reason: 'stale',
        next_allowed_at: null,
      },
    ],
    skipped: { disabled: 1, fresh: 2, backoff: 0, running: 0, orphaned: 0, capped: 0 },
    notes: [],
    ...overrides,
  };
}

function attemptView(overrides: Record<string, unknown> = {}) {
  return {
    accepted: true,
    entity_id: 'ent-1',
    status: 'manual_required' as RegistryAutoUpdateStatus,
    generated_at: '2026-07-09T10:01:00Z',
    dry_run_only: true,
    reason: 'manual dry run',
    last_attempt_at: '2026-07-09T10:01:00Z',
    next_allowed_at: null,
    failure_count: 0,
    audit_event_seq: 42,
    ...overrides,
  };
}

interface RegistryFetchOptions {
  plan?: unknown;
  planStatus?: number;
  attempt?: unknown;
  attemptStatus?: number;
  hangAttempt?: boolean;
}

function registryFetch(opts: RegistryFetchOptions = {}): {
  fn: typeof fetch;
  calls: { url: string; method: string; body: string | null }[];
} {
  const {
    plan = planWithDue(),
    planStatus = 200,
    attempt = attemptView(),
    attemptStatus = 200,
    hangAttempt = false,
  } = opts;
  const calls: { url: string; method: string; body: string | null }[] = [];
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });

    if (url.includes('/v1/registry/lookup')) {
      return Promise.resolve(jsonResponse(plan, planStatus));
    }
    if (/\/v1\/entities\/[^/]+\/registry/.test(url) && method === 'POST') {
      if (hangAttempt) return new Promise<Response>(() => {});
      return Promise.resolve(jsonResponse(attempt, attemptStatus));
    }
    return Promise.reject(new Error(`no stub for ${url}`));
  }) as typeof fetch;
  return { fn, calls };
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('RegistryAutoUpdateSection', () => {
  it('renders the card, schedule controls, and the loaded due plan', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    expect(
      screen.getByText('Atualização automática da certidão permanente'),
    ).toBeTruthy();
    // Interval cadence (the default) → the "hours between runs" input branch is shown.
    const cadenceSelect = screen.getByLabelText('Periodicidade') as HTMLSelectElement;
    expect(cadenceSelect.value).toBe('interval_hours');
    expect(screen.getByLabelText('Horas entre execuções')).toBeTruthy();
    expect(
      screen.getByRole('switch', { name: 'Ativar trabalhador de atualização' }),
    ).toBeTruthy();

    // The plan resolves and the due entity row (plus the attempt button) appears.
    expect(await screen.findByText('Encosto Estratégico Lda')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Pedir tentativa' })).toBeTruthy();
  });

  it('toggles the enabled flag through onChange', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    fireEvent.click(screen.getByRole('switch', { name: 'Ativar trabalhador de atualização' }));
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ enabled: true }));
  });

  it('changes the schedule interval field through onChange', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    fireEvent.change(screen.getByLabelText('Horas entre execuções'), {
      target: { value: '48' },
    });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ cadence: { kind: 'interval_hours', hours: 48 } }),
    );
  });

  it('switches the cadence kind to daily with sensible defaults', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    fireEvent.change(screen.getByLabelText('Periodicidade'), { target: { value: 'daily' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ cadence: { kind: 'daily', hour_utc: 2 } }),
    );
  });

  it('renders the daily cadence field and edits its hour', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection
        value={withCadence({ kind: 'daily', hour_utc: 2 })}
        onChange={onChange}
      />,
    );

    const hourInput = screen.getByLabelText('Hora UTC') as HTMLInputElement;
    expect(hourInput).toBeTruthy();
    fireEvent.change(hourInput, { target: { value: '5' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ cadence: { kind: 'daily', hour_utc: 5 } }),
    );
  });

  it('renders the weekly cadence fields and edits the weekday', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection
        value={withCadence({ kind: 'weekly', weekday: 'monday', hour_utc: 2 })}
        onChange={onChange}
      />,
    );

    expect(screen.getByLabelText('Hora UTC')).toBeTruthy();
    const weekdaySelect = screen.getByLabelText('Dia da semana') as HTMLSelectElement;
    expect(weekdaySelect.value).toBe('monday');
    fireEvent.change(weekdaySelect, { target: { value: 'friday' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        cadence: { kind: 'weekly', weekday: 'friday', hour_utc: 2 },
      }),
    );
  });

  it('toggles an entity profile through onChange', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    // With no explicit profiles selected, "all profiles" is checked; unchecking a specific
    // profile narrows the selection away from "all".
    const checkboxes = screen.getAllByRole('checkbox');
    // checkboxes[0] is the "all profiles" master; the rest are per-profile.
    fireEvent.click(checkboxes[1]);
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        entity_defaults: expect.objectContaining({
          enabled_profiles: expect.any(Array),
        }),
      }),
    );
    const lastCall = onChange.mock.calls.at(-1)?.[0] as RegistryAutoUpdateSettings;
    expect(lastCall.entity_defaults.enabled_profiles.length).toBeGreaterThan(0);
  });

  it('disables the attempt button and shows the pending label while the mutation is in flight', async () => {
    vi.stubGlobal('fetch', registryFetch({ hangAttempt: true }).fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Pedir tentativa' }));

    await waitFor(() => {
      const pending = screen.getByRole('button', { name: 'A pedir…' }) as HTMLButtonElement;
      expect(pending.disabled).toBe(true);
    });
  });

  it('records a successful attempt with a success toast and result panel', async () => {
    vi.stubGlobal('fetch', registryFetch({ attempt: attemptView({ accepted: true }) }).fn);
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Pedir tentativa' }));

    expect(await screen.findByText('Tentativa registada.')).toBeTruthy();
    expect(await screen.findByText('Resultado da tentativa')).toBeTruthy();
  });

  it('surfaces an attempt failure as an error toast', async () => {
    vi.stubGlobal(
      'fetch',
      registryFetch({
        attempt: { error: 'Tentativa recusada pelo servidor.' },
        attemptStatus: 422,
      }).fn,
    );
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Pedir tentativa' }));

    const alert = await screen.findByRole('alert');
    expect(alert.textContent).toContain('Tentativa recusada pelo servidor.');
  });

  it('renders an inline error note when the due plan fails to load', async () => {
    vi.stubGlobal(
      'fetch',
      registryFetch({ plan: { error: 'Falha ao carregar o plano.' }, planStatus: 500 }).fn,
    );
    const onChange = vi.fn();
    renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    expect(await screen.findByText('Falha ao carregar o plano.')).toBeTruthy();
  });
});
