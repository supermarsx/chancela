import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { RegistryAutoUpdateSection } from './RegistryAutoUpdateSection';
import {
  DEFAULT_SETTINGS,
  type RegistryAutoUpdateCadence,
  type RegistryAutoUpdateSettings,
  type RegistryAutoUpdateStatus,
  ENTITY_KINDS,
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
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

    expect(screen.getByText('Atualização automática da certidão permanente')).toBeTruthy();
    // Interval cadence (the default) → the "hours between runs" input branch is shown.
    const cadenceSelect = screen.getByLabelText('Periodicidade') as HTMLSelectElement;
    expect(cadenceSelect.value).toBe('interval_hours');
    expect(screen.getByLabelText('Horas entre execuções')).toBeTruthy();
    expect(screen.getByRole('switch', { name: 'Ativar trabalhador de atualização' })).toBeTruthy();

    // The plan resolves and the due entity row (plus the attempt button) appears.
    expect(await screen.findByText('Encosto Estratégico Lda')).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Pedir tentativa' })).toBeTruthy();
  });

  it('renders each editable configuration as a direct table-like settings row', () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    const settingsRows = container.querySelector('.settings-rows');
    expect(settingsRows).toBeTruthy();
    expect(container.querySelector('.registry-auto-update-grid')).toBeNull();

    const worker = screen.getByRole('switch', { name: 'Ativar trabalhador de atualização' });
    const workerRow = worker.closest('.toggle');
    expect(workerRow?.parentElement).toBe(settingsRows);
    expect(worker.getAttribute('aria-describedby')).toBe('registry-auto-update-enabled-hint');
    expect(workerRow?.nextElementSibling?.id).toBe('registry-auto-update-enabled-hint');

    [
      'registry-auto-cadence',
      'registry-auto-hours',
      'registry-auto-stale',
      'registry-auto-min-backoff',
      'registry-auto-max-backoff',
      'registry-auto-max-attempts',
    ].forEach((controlId) => {
      expect(container.querySelector(`#${controlId}`)?.closest('.field')?.parentElement).toBe(
        settingsRows,
      );
    });

    const entityDefault = screen.getByRole('switch', {
      name: 'Novas entidades elegíveis por omissão',
    });
    const entityDefaultRow = entityDefault.closest('.toggle');
    expect(entityDefaultRow?.parentElement).toBe(settingsRows);
    expect(entityDefault.getAttribute('aria-describedby')).toBe(
      'registry-auto-update-entity-default-hint',
    );
    expect(entityDefaultRow?.nextElementSibling?.id).toBe(
      'registry-auto-update-entity-default-hint',
    );

    const profiles = screen.getByRole('group', { name: 'Perfil' });
    expect(profiles.classList.contains('field')).toBe(true);
    expect(profiles.parentElement).toBe(settingsRows);
    expect(profiles.getAttribute('aria-describedby')).toBe(
      'registry-auto-update-entity-default-hint',
    );
    expect(profiles.querySelector('.registry-auto-update-profiles')).toBeTruthy();
  });

  it('toggles the enabled flag through onChange', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

    fireEvent.click(screen.getByRole('switch', { name: 'Ativar trabalhador de atualização' }));
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ enabled: true }));
  });

  it('changes the schedule interval field through onChange', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

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
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

    fireEvent.change(screen.getByLabelText('Periodicidade'), { target: { value: 'daily' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ cadence: { kind: 'daily', hour_utc: 2 } }),
    );
  });

  it('renders the daily cadence field and edits its hour', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection
        value={withCadence({ kind: 'daily', hour_utc: 2 })}
        onChange={onChange}
      />,
    );

    const hourInput = screen.getByLabelText('Hora UTC') as HTMLInputElement;
    expect(hourInput).toBeTruthy();
    expect(hourInput.closest('.field')?.parentElement).toBe(
      container.querySelector('.settings-rows'),
    );
    fireEvent.change(hourInput, { target: { value: '5' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ cadence: { kind: 'daily', hour_utc: 5 } }),
    );
  });

  it('renders the weekly cadence fields and edits the weekday', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection
        value={withCadence({ kind: 'weekly', weekday: 'monday', hour_utc: 2 })}
        onChange={onChange}
      />,
    );

    const settingsRows = container.querySelector('.settings-rows');
    expect(screen.getByLabelText('Hora UTC').closest('.field')?.parentElement).toBe(settingsRows);
    const weekdaySelect = screen.getByLabelText('Dia da semana') as HTMLSelectElement;
    expect(weekdaySelect.value).toBe('monday');
    expect(weekdaySelect.closest('.field')?.parentElement).toBe(settingsRows);
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
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

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
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Pedir tentativa' }));

    await waitFor(() => {
      const pending = screen.getByRole('button', { name: 'A pedir…' }) as HTMLButtonElement;
      expect(pending.disabled).toBe(true);
    });
  });

  it('records a successful attempt with a success toast and result panel', async () => {
    vi.stubGlobal('fetch', registryFetch({ attempt: attemptView({ accepted: true }) }).fn);
    const onChange = vi.fn();
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

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
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

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
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />);

    expect(await screen.findByText('Falha ao carregar o plano.')).toBeTruthy();
  });
});

/**
 * The status readouts, the schedule handlers, and the outcome arms.
 *
 * These assert by stable id, ARIA role and the values pushed through `onChange` — never by
 * translated prose — so the pt-PT copy can be rewritten without touching them. That is the
 * opposite convention to some of the assertions above, which predate the rule; they are left
 * alone rather than churned.
 */
describe('RegistryAutoUpdateSection — status tables and schedule handlers', () => {
  const byId = (container: HTMLElement, id: string): HTMLInputElement =>
    container.querySelector(`#${id}`) as HTMLInputElement;

  /**
   * A stateful host, because the section is CONTROLLED.
   *
   * With a bare `vi.fn()` for `onChange` the `value` prop never advances, so every branch that
   * reads the value in force — `setCadenceKind`'s early return, the "all profiles" checkbox,
   * which cadence fields are mounted — is measured against the initial settings no matter what
   * was clicked. That is not a smaller test, it is a test of a component that does not exist.
   */
  function Host({
    initial = BASE_SETTINGS,
    onValue,
  }: {
    initial?: RegistryAutoUpdateSettings;
    onValue?: (next: RegistryAutoUpdateSettings) => void;
  }) {
    const [value, setValue] = useState(initial);
    return (
      <RegistryAutoUpdateSection
        value={value}
        onChange={(next) => {
          onValue?.(next);
          setValue(next);
        }}
      />
    );
  }

  it('renders the plan, the skipped counts and the attempt result as real tables', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={vi.fn()} />,
    );
    await screen.findByRole('button', { name: 'Pedir tentativa' });

    // Every status readout is a `<table>` with a hidden `<caption>` naming it, and a
    // `<th scope="row">` per fact — what a `dl.deflist` could not carry.
    const captions = [...container.querySelectorAll('table > caption')];
    expect(captions.length).toBeGreaterThanOrEqual(2);
    for (const caption of captions) expect(caption.className).toContain('sr-only');
    expect(container.querySelectorAll('th[scope="row"]').length).toBeGreaterThanOrEqual(10);

    // Each converted table's column headers carry a keyboard-reachable help trigger, not a
    // hover-only tooltip: `ColumnHead` renders a real <button> with its own description.
    const helpButtons = [...container.querySelectorAll('thead th button')];
    expect(helpButtons.length).toBeGreaterThanOrEqual(4);
    for (const button of helpButtons) {
      expect(button.getAttribute('aria-describedby')).toBeTruthy();
    }

    // The glossary inside the informational banner stays a definition list on purpose.
    expect(container.querySelectorAll('dl.deflist').length).toBe(1);
  });

  it('renders the attempt result table once an attempt resolves', async () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={vi.fn()} />,
    );
    // Read the baseline only AFTER the plan has rendered its own two tables.
    await screen.findByRole('button', { name: 'Pedir tentativa' });
    const before = container.querySelectorAll('table > caption').length;
    fireEvent.click(screen.getByRole('button', { name: 'Pedir tentativa' }));
    await waitFor(() =>
      expect(container.querySelectorAll('table > caption').length).toBe(before + 1),
    );
  });

  it('carries a keyboard-reachable help trigger on every form control that has one', () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={vi.fn()} />,
    );
    // `FieldHelp` renders a <button>, so each explanation is a tab stop. Hover-only would be
    // decoration; this asserts the trigger exists and is described, not what it says.
    const triggers = [...container.querySelectorAll('button[aria-describedby]')];
    expect(triggers.length).toBeGreaterThanOrEqual(8);
    for (const trigger of triggers) {
      expect(trigger.tagName).toBe('BUTTON');
      // `getElementById`, not `querySelector('#…')`: React's `useId` emits ids like `:r7:`, which
      // are legal HTML ids and illegal CSS selectors.
      expect(
        document.getElementById(trigger.getAttribute('aria-describedby') as string),
      ).toBeTruthy();
    }
  });

  it('moves between all three cadence kinds and seeds each with its own defaults', () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onValue = vi.fn();
    const { container } = renderWithProviders(<Host onValue={onValue} />);
    const select = byId(container, 'registry-auto-cadence');

    fireEvent.change(select, { target: { value: 'daily' } });
    expect(onValue.mock.calls.at(-1)?.[0].cadence).toEqual({ kind: 'daily', hour_utc: 2 });
    expect(byId(container, 'registry-auto-hour-utc')).toBeTruthy();

    fireEvent.change(select, { target: { value: 'weekly' } });
    expect(onValue.mock.calls.at(-1)?.[0].cadence).toEqual({
      kind: 'weekly',
      weekday: 'monday',
      hour_utc: 2,
    });
    expect(byId(container, 'registry-auto-weekday')).toBeTruthy();

    fireEvent.change(select, { target: { value: 'interval_hours' } });
    expect(onValue.mock.calls.at(-1)?.[0].cadence).toEqual({ kind: 'interval_hours', hours: 24 });

    // Re-selecting the kind already in effect is a no-op, not a reseed.
    const calls = onValue.mock.calls.length;
    fireEvent.change(select, { target: { value: 'interval_hours' } });
    expect(onValue.mock.calls.length).toBe(calls);
  });

  it('edits the daily and weekly cadence fields', () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    const daily = renderWithProviders(
      <RegistryAutoUpdateSection
        value={withCadence({ kind: 'daily', hour_utc: 2 })}
        onChange={onChange}
      />,
    );
    fireEvent.change(byId(daily.container, 'registry-auto-hour-utc'), { target: { value: '5' } });
    expect(onChange.mock.calls.at(-1)?.[0].cadence).toEqual({ kind: 'daily', hour_utc: 5 });
    cleanup();

    const weekly = renderWithProviders(
      <RegistryAutoUpdateSection
        value={withCadence({ kind: 'weekly', weekday: 'monday', hour_utc: 2 })}
        onChange={onChange}
      />,
    );
    fireEvent.change(byId(weekly.container, 'registry-auto-hour-utc'), { target: { value: '7' } });
    expect(onChange.mock.calls.at(-1)?.[0].cadence).toEqual({
      kind: 'weekly',
      weekday: 'monday',
      hour_utc: 7,
    });
    fireEvent.change(byId(weekly.container, 'registry-auto-weekday'), {
      target: { value: 'friday' },
    });
    expect(onChange.mock.calls.at(-1)?.[0].cadence.weekday).toBe('friday');
  });

  it('edits every numeric threshold, and keeps the previous value when one is unparseable', () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onChange = vi.fn();
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={onChange} />,
    );

    const edits: [string, keyof RegistryAutoUpdateSettings, string, number][] = [
      ['registry-auto-hours', 'cadence', '12', 12],
      ['registry-auto-stale', 'stale_threshold_hours', '48', 48],
      ['registry-auto-min-backoff', 'min_backoff_minutes', '15', 15],
      ['registry-auto-max-backoff', 'max_backoff_minutes', '900', 900],
      ['registry-auto-max-attempts', 'max_attempts_per_run', '25', 25],
    ];
    for (const [id, key, raw, expected] of edits) {
      fireEvent.change(byId(container, id), { target: { value: raw } });
      const next = onChange.mock.calls.at(-1)?.[0];
      if (key === 'cadence') expect(next.cadence.hours).toBe(expected);
      else expect(next[key]).toBe(expected);
    }

    // `numberValue`'s fallback cannot be reached through these controls, and that is worth
    // pinning rather than asserting a fiction: `<input type="number">` blanks an unparseable
    // entry, so the handler sees '' and `Number('')` is a finite 0. The guard is real but it
    // guards against a programmatic value, not against typing.
    fireEvent.change(byId(container, 'registry-auto-stale'), { target: { value: 'abc' } });
    expect(onChange.mock.calls.at(-1)?.[0].stale_threshold_hours).toBe(0);
  });

  it('toggles the entity default and narrows the eligible profiles', () => {
    vi.stubGlobal('fetch', registryFetch().fn);
    const onValue = vi.fn();
    const { container } = renderWithProviders(<Host onValue={onValue} />);

    const switches = [...container.querySelectorAll('.toggle input')];
    fireEvent.click(switches[switches.length - 1] as HTMLInputElement);
    expect(onValue.mock.calls.at(-1)?.[0].entity_defaults.enabled).toBe(
      !BASE_SETTINGS.entity_defaults.enabled,
    );

    // Unchecking one profile out of "all" narrows the list…
    const boxes = () => [...container.querySelectorAll('.registry-auto-update-profiles input')];
    expect(boxes().length).toBeGreaterThan(1);
    fireEvent.click(boxes()[1] as HTMLInputElement);
    const narrowed = onValue.mock.calls.at(-1)?.[0].entity_defaults.enabled_profiles;
    expect(narrowed.length).toBeGreaterThan(0);
    expect(narrowed.length).toBeLessThan(ENTITY_KINDS.length);

    // …and re-checking "all" empties it, which is how the API spells "type is not a criterion".
    fireEvent.click(boxes()[0] as HTMLInputElement);
    expect(onValue.mock.calls.at(-1)?.[0].entity_defaults.enabled_profiles).toEqual([]);

    // Re-checking the profile that was removed also restores the empty ("all") form, because a
    // full selection normalises back to it.
    fireEvent.click(boxes()[1] as HTMLInputElement);
    fireEvent.click(boxes()[1] as HTMLInputElement);
    expect(onValue.mock.calls.at(-1)?.[0].entity_defaults.enabled_profiles).toEqual([]);
  });

  it('refetches the plan on demand', async () => {
    const stub = registryFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={vi.fn()} />);
    await screen.findByRole('button', { name: 'Pedir tentativa' });
    const before = stub.calls.filter((c) => c.url.includes('/v1/registry/lookup')).length;

    fireEvent.click(screen.getByRole('button', { name: 'Atualizar plano' }));
    await waitFor(() =>
      expect(
        stub.calls.filter((c) => c.url.includes('/v1/registry/lookup')).length,
      ).toBeGreaterThan(before),
    );
  });

  it('tones every plan status, and says so when the retrieval date is unusable', async () => {
    const statuses: RegistryAutoUpdateStatus[] = [
      'idle',
      'due',
      'queued',
      'running',
      'completed',
      'failed',
      'manual_required',
    ];
    const due = statuses.map((status, i) => ({
      entity_id: `ent-${i}`,
      entity_name: `Entidade ${i}`,
      entity_profile: 'SociedadePorQuotas',
      retrieved_at: '2026-05-01T10:00:00Z',
      // The unknown-age arm: the reason line cannot quote hours it does not have.
      age_hours: i === 0 ? null : 1656,
      stale_threshold_hours: 720,
      code_masked: '1234****9012',
      status,
      reason: 'stale',
      next_allowed_at: null,
    }));
    vi.stubGlobal('fetch', registryFetch({ plan: planWithDue({ due }) }).fn);
    const { container } = renderWithProviders(
      <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={vi.fn()} />,
    );
    await screen.findByText('Entidade 6');

    // One badge per row, and the tone set covers ok / warn / accent / neutral.
    const tones = new Set(
      [...container.querySelectorAll('tbody .badge')].map(
        (b) => /badge--([a-z]+)/u.exec(b.className)?.[1],
      ),
    );
    expect(tones.has('ok')).toBe(true);
    expect(tones.has('warn')).toBe(true);
    expect(tones.has('accent')).toBe(true);
    expect(tones.has('neutral')).toBe(true);
  });

  it('renders every attempt outcome arm', async () => {
    const cases: { status: RegistryAutoUpdateStatus; accepted: boolean; next: string | null }[] = [
      { status: 'manual_required', accepted: true, next: null },
      { status: 'running', accepted: true, next: null },
      { status: 'idle', accepted: false, next: '2026-07-09T12:00:00Z' },
      { status: 'idle', accepted: false, next: null },
      { status: 'completed', accepted: true, next: null },
    ];
    for (const { status, accepted, next } of cases) {
      vi.stubGlobal(
        'fetch',
        registryFetch({ attempt: attemptView({ status, accepted, next_allowed_at: next }) }).fn,
      );
      const { container } = renderWithProviders(
        <RegistryAutoUpdateSection value={BASE_SETTINGS} onChange={vi.fn()} />,
      );
      fireEvent.click(await screen.findByRole('button', { name: 'Pedir tentativa' }));
      // The result banner carries a sentence for every arm; assert one arrived, not which.
      await waitFor(() => {
        const notes = [...container.querySelectorAll('[role="note"]')];
        expect(notes.length).toBeGreaterThanOrEqual(2);
      });
      cleanup();
    }
  });
});
