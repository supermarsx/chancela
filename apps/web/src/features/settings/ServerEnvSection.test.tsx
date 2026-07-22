/**
 * Tests for the "Ambiente do servidor" pane (t14). It reads the server-declared env registry from
 * `GET /v1/platform/env` and writes non-secret overrides with `PUT /v1/platform/env`, so `fetch` is
 * stubbed the same way the sibling settings tests do it. The assertions pin the tier contract — a
 * Tier A editor, a Tier B masked/display-only secret, a Tier C boundary behind an acknowledgement
 * gate, a Tier D read-only fact — plus the restart-pending surfacing, the complete-desired-map PUT
 * body, RBAC read-only, and the 422 inline path.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { ServerEnvSection } from './ServerEnvSection';
import type { ServerEnvResponse, ServerEnvVarView } from '../../api/types';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';

function tierA(overrides: Partial<ServerEnvVarView> = {}): ServerEnvVarView {
  return {
    name: 'CHANCELA_LOG',
    group: 'logging',
    tier: 'A',
    editable: true,
    secret: false,
    boundary: false,
    narrow_only: false,
    acknowledgement_required: false,
    excluded_typed_slice: null,
    source: 'override',
    configured: true,
    effective_value: 'info',
    override_value: 'debug',
    default_value: 'info',
    restart_pending: true,
    validator: { kind: 'free_text', allowed: null },
    ...overrides,
  };
}

/** A Tier C boundary bool var, editable only behind acknowledgement. */
function tierC(overrides: Partial<ServerEnvVarView> = {}): ServerEnvVarView {
  return {
    name: 'CHANCELA_RATE_LIMIT_ENABLED',
    group: 'rate_limit',
    tier: 'C',
    editable: true,
    secret: false,
    boundary: true,
    narrow_only: false,
    acknowledgement_required: true,
    excluded_typed_slice: null,
    source: 'env',
    configured: true,
    effective_value: 'true',
    override_value: null,
    default_value: 'true',
    restart_pending: false,
    validator: { kind: 'bool', allowed: null },
    ...overrides,
  };
}

/** A Tier B secret — value never echoed, only `configured`. */
function tierB(overrides: Partial<ServerEnvVarView> = {}): ServerEnvVarView {
  return {
    name: 'CHANCELA_DB_KEY',
    group: 'database',
    tier: 'B',
    editable: false,
    secret: true,
    boundary: false,
    narrow_only: false,
    acknowledgement_required: false,
    excluded_typed_slice: null,
    source: 'env',
    configured: true,
    effective_value: null,
    override_value: null,
    default_value: null,
    restart_pending: false,
    validator: { kind: 'free_text', allowed: null },
    ...overrides,
  };
}

/** The narrow-only, typed-slice-excluded egress ceiling — read-only with a cross-link reason. */
function ceiling(overrides: Partial<ServerEnvVarView> = {}): ServerEnvVarView {
  return {
    name: 'CHANCELA_CONNECTOR_ALLOWED_HOSTS',
    group: 'connectors',
    tier: 'C',
    editable: false,
    secret: false,
    boundary: true,
    narrow_only: true,
    acknowledgement_required: true,
    excluded_typed_slice: 'connectors.allowed_hosts — env is the deployment egress ceiling',
    source: 'env',
    configured: true,
    effective_value: 'registo.example.pt',
    override_value: null,
    default_value: null,
    restart_pending: false,
    validator: { kind: 'host_list', allowed: null },
    ...overrides,
  };
}

function response(overrides: Partial<ServerEnvResponse> = {}): ServerEnvResponse {
  return {
    vars: [tierA(), tierC(), tierB(), ceiling()],
    restart_pending: true,
    overrides_path: '/var/lib/chancela/env-overrides.json',
    generated_at: '2026-07-22T10:15:00Z',
    ...overrides,
  };
}

interface Call {
  url: string;
  method: string;
  body: string | null;
}

function stubFetch(opts: { get?: ServerEnvResponse; putStatus?: number; putBody?: unknown } = {}): {
  fn: typeof fetch;
  calls: Call[];
} {
  const { get = response(), putStatus = 200, putBody } = opts;
  const calls: Call[] = [];
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    calls.push({ url, method, body: (init?.body as string) ?? null });
    if (url.includes('/v1/platform/env') && method === 'GET') return Promise.resolve(json(get));
    // PUT: echo a fresh view (or an error) — the mutation seeds the cache from it.
    return Promise.resolve(json(putBody ?? { ...get, restart_pending: true }, putStatus));
  }) as typeof fetch;
  return { fn, calls };
}

/** The `.field` row that carries `name` as its label. */
function row(name: string): HTMLElement {
  const label = screen.getByText(name, { selector: 'label' });
  return label.closest('.field') as HTMLElement;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('ServerEnvSection', () => {
  it('renders a Tier A editor pre-filled with the override, its source and a restart badge', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<ServerEnvSection />);

    // The restart-pending banner (response-level) is shown.
    expect(await screen.findByText('Guardado, ainda não aplicado')).toBeTruthy();

    // Tier A: a text input labelled by the var name, carrying the current override value.
    const input = screen.getByLabelText('CHANCELA_LOG') as HTMLInputElement;
    expect(input.value).toBe('debug');
    // Its row shows the source badge (override) and its own restart-pending badge.
    const logRow = row('CHANCELA_LOG');
    expect(within(logRow).getByText('Substituição')).toBeTruthy();
    expect(within(logRow).getByText('Reinício pendente')).toBeTruthy();
  });

  it('renders a Tier B secret masked/display-only, never an input', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<ServerEnvSection />);

    await screen.findByLabelText('CHANCELA_LOG');
    // No input for the secret, and the configured state is shown instead of any value.
    expect(screen.queryByLabelText('CHANCELA_DB_KEY')).toBeNull();
    const dbRow = row('CHANCELA_DB_KEY');
    expect(within(dbRow).getByText('Configurada')).toBeTruthy();
  });

  it('renders the narrow-only typed-slice ceiling read-only with its reason', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(<ServerEnvSection />);

    await screen.findByLabelText('CHANCELA_LOG');
    expect(screen.queryByLabelText('CHANCELA_CONNECTOR_ALLOWED_HOSTS')).toBeNull();
    const ceilRow = row('CHANCELA_CONNECTOR_ALLOWED_HOSTS');
    // Read-only + narrow-only badges, and the typed-slice reason is surfaced.
    expect(within(ceilRow).getByText('Apenas leitura')).toBeTruthy();
    expect(within(ceilRow).getByText('Só pode restringir')).toBeTruthy();
    expect(within(ceilRow).getByText(/env is the deployment egress ceiling/)).toBeTruthy();
  });

  it('gates a Tier C boundary change behind acknowledgement, then PUTs the complete map', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ServerEnvSection />);

    // Change the boundary bool via its Select (no override → false).
    const select = (await screen.findByLabelText(
      'CHANCELA_RATE_LIMIT_ENABLED',
    )) as HTMLSelectElement;
    fireEvent.change(select, { target: { value: 'false' } });

    // The acknowledgement toggle and warning appear once the row is dirty; save is blocked.
    const ack = await screen.findByRole('switch', {
      name: 'Confirmo que compreendo o efeito desta alteração',
    });
    const saveButton = screen.getByRole('button', { name: 'Guardar substituições' });
    expect(saveButton.hasAttribute('disabled')).toBe(true);

    // Acknowledge, then save: the PUT carries the complete desired override map plus the ack.
    fireEvent.click(ack);
    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Guardar substituições' }).hasAttribute('disabled'),
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Guardar substituições' }));

    await waitFor(() => {
      const put = stub.calls.find((c) => c.method === 'PUT');
      expect(put, 'a PUT was issued').toBeTruthy();
      const body = JSON.parse(put!.body ?? '{}');
      // Complete desired set: the pre-existing Tier A override is retained, the boundary added.
      expect(body.overrides).toEqual({
        CHANCELA_LOG: 'debug',
        CHANCELA_RATE_LIMIT_ENABLED: 'false',
      });
      expect(body.acknowledge).toEqual(['CHANCELA_RATE_LIMIT_ENABLED']);
    });
  });

  it('clearing a Tier A override drops it from the PUT map', async () => {
    const stub = stubFetch();
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ServerEnvSection />);

    const input = (await screen.findByLabelText('CHANCELA_LOG')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar substituições' }));

    await waitFor(() => {
      const put = stub.calls.find((c) => c.method === 'PUT');
      expect(put).toBeTruthy();
      const body = JSON.parse(put!.body ?? '{}');
      // Empty → no override for CHANCELA_LOG; nothing else changed, so the map is empty.
      expect(body.overrides).toEqual({});
      expect(body.acknowledge).toEqual([]);
    });
  });

  it('surfaces a 422 rejection inline without clearing the working copy', async () => {
    const stub = stubFetch({
      putStatus: 422,
      putBody: { error: 'Confirme cada alteração a uma fronteira de segurança antes de guardar.' },
    });
    vi.stubGlobal('fetch', stub.fn);
    renderWithProviders(<ServerEnvSection />);

    const input = (await screen.findByLabelText('CHANCELA_LOG')) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'trace' } });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar substituições' }));

    // The server message renders inline, and the edited value is still present.
    expect(
      await screen.findByText(
        'Confirme cada alteração a uma fronteira de segurança antes de guardar.',
      ),
    ).toBeTruthy();
    expect((screen.getByLabelText('CHANCELA_LOG') as HTMLInputElement).value).toBe('trace');
  });

  it('is read-only without settings.manage — no editors, no save', async () => {
    vi.stubGlobal('fetch', stubFetch().fn);
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <ServerEnvSection />
      </StaticPermissionsProvider>,
    );

    // The Tier A input renders (facts are still shown) but is disabled, and no save affordance exists.
    const input = (await screen.findByLabelText('CHANCELA_LOG')) as HTMLInputElement;
    expect(input.disabled).toBe(true);
    expect(screen.queryByRole('button', { name: 'Guardar substituições' })).toBeNull();
  });
});
