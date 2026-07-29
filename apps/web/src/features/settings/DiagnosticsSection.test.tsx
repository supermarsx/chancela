/**
 * Tests for the Diagnóstico pane.
 *
 * Three things are worth a test here and the rest is covered by `diagnosticsReport.test.ts`:
 *
 * 1. **Screen and export cannot drift.** Every field id rendered as a table row must appear in the
 *    text the Copy button puts on the clipboard, and vice versa. That is the invariant the whole
 *    "one model, two renderings" arrangement exists to hold, and the only way it stays true when
 *    someone adds a section next month.
 * 2. **The three affordances, including their failure paths.** A clipboard refusal (an insecure
 *    context, a permissions policy) must be VISIBLE — the earlier idiom of swallowing it silently
 *    is wrong for a control whose entire purpose is to hand the operator the report.
 * 3. **The gate.** The pane aggregates every operations pane, so it may not be a weaker door than
 *    the ones it aggregates: without `settings.read` it renders the permission notice, not rows.
 *
 * Assertions are on field ids, roles and `data-*` hooks — never on translated prose, which would
 * couple this file to pt-PT grammar.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { DiagnosticsSection } from './DiagnosticsSection';
import { renderWithProviders } from '../../test/utils';
import { permissionsValue, StaticPermissionsProvider } from '../session/permissions';

/** One stubbed route. Longest paths first — the matcher takes the first substring hit. */
const ROUTES: { match: string; status?: number; body: unknown }[] = [
  {
    match: '/v1/settings/email/deliveries',
    body: [
      {
        id: 'd1',
        template_id: 'user.welcome',
        recipient: 'amelia.marques@encosto-estrategico.example',
        status: 'failed',
        attempt: 1,
        failure_stage: 'auth',
        failure_kind: 'rejected',
        created_at: '2026-07-29T10:00:00Z',
        actor: 'api',
        resendable: true,
      },
    ],
  },
  {
    match: '/v1/settings/email/status',
    body: { password_configured: true, deliverable: true, encrypted: true, warnings: [] },
  },
  {
    match: '/v1/platform/services',
    body: {
      services: [
        {
          id: 'api',
          kind: 'http',
          label: 'API',
          configured: true,
          enabled: true,
          desired_state: 'running',
          actual_runtime_status: 'running',
          controllable_actions: [],
          logging_level: 'info',
          last_action: null,
          limitations: [],
        },
      ],
    },
  },
  {
    match: '/v1/platform/env',
    body: {
      vars: [
        {
          name: 'CHANCELA_DB_KEY',
          group: 'database',
          tier: 'B',
          editable: false,
          secret: true,
          boundary: false,
          narrow_only: false,
          acknowledgement_required: false,
          excluded_typed_slice: null,
          external_reader: null,
          source: 'env',
          configured: true,
          // A server that regressed. The pane must still refuse to render or export it.
          effective_value: 'sqlcipher-passphrase-LEAK',
          override_value: null,
          default_value: null,
          restart_pending: false,
          validator: { kind: 'free_text', allowed: null },
        },
      ],
      restart_pending: false,
      overrides_path: '/var/lib/chancela/env-overrides.json',
      generated_at: '2026-07-29T12:00:00Z',
    },
  },
  { match: '/v1/zk-repositories/storage-status', status: 403, body: { error: 'forbidden' } },
  { match: '/v1/ledger/integrity', status: 403, body: { error: 'forbidden' } },
  { match: '/v1/search/status', status: 403, body: { error: 'forbidden' } },
  { match: '/v1/trust/status', status: 403, body: { error: 'forbidden' } },
  { match: '/v1/signature/provider-credentials', status: 403, body: { error: 'forbidden' } },
  { match: '/v1/data/status', status: 403, body: { error: 'forbidden' } },
  { match: '/v1/settings', body: { schema_version: 7 } },
  { match: '/health', body: { status: 'ok', version: '26.1.0', integrity: 'ok', degraded: false } },
];

function stubFetch(): typeof fetch {
  return ((input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    const hit = ROUTES.find((route) => url.includes(route.match));
    if (!hit) return Promise.reject(new Error(`no stub for ${url}`));
    return Promise.resolve(
      new Response(JSON.stringify(hit.body), {
        status: hit.status ?? 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as typeof fetch;
}

/**
 * The report settles progressively — each query resolves on its own tick — so waiting on one row
 * would compare a half-rendered screen against a fuller export. This waits for a marker row from
 * EVERY source the stub table answers 200 for; the refused ones fail on the same ticks.
 */
const SETTLED_ROWS = [
  'health.status',
  'platform_services.count',
  'env.var.CHANCELA_DB_KEY.configured',
  'email.deliveries.count',
  'report.settings.schema_version',
];

async function waitForReport() {
  await waitFor(() => {
    for (const id of SETTLED_ROWS) {
      expect(document.querySelector(`[data-diagnostic-row="${id}"]`), id).not.toBeNull();
    }
    // `report.settings.schema_version` exists from the first paint as an unknown; the report is
    // only settled once it carries the value the stub returned.
    expect(
      document.querySelector('[data-diagnostic-row="report.settings.schema_version"]')?.textContent,
    ).toContain('7');
  });
}

function renderPane() {
  return renderWithProviders(<DiagnosticsSection />);
}

let writeText: ReturnType<typeof vi.fn>;

beforeEach(() => {
  vi.stubGlobal('fetch', stubFetch());
  writeText = vi.fn(() => Promise.resolve());
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  document.body.classList.remove('printing-diagnostics');
});

describe('Diagnóstico — the report', () => {
  it('renders every declared section, including the ones nothing answered for', async () => {
    renderPane();
    await waitForReport();

    const sections = new Set(
      [...document.querySelectorAll('[data-diagnostic-section]')].map((row) =>
        row.getAttribute('data-diagnostic-section'),
      ),
    );
    expect([...sections].sort()).toEqual([
      'credentials',
      'email',
      'env',
      'health',
      'ledger',
      'not_covered',
      'platform_services',
      'report',
      'search',
      'storage',
      'trust',
    ]);
  });

  it('reports a refused source as refused rather than as a blank or a pass', async () => {
    renderPane();
    await waitForReport();

    // `/v1/ledger/integrity` answered 403 in the stub table above: the declared fields are present
    // and every one of them says it was not read.
    const row = document.querySelector('[data-diagnostic-row="ledger.healthy"]');
    expect(row).not.toBeNull();
    expect(row?.querySelector('.badge')?.className).toContain('badge--warn');
  });

  it('never renders a secret value on screen', async () => {
    renderPane();
    await waitForReport();

    expect(document.body.textContent).not.toContain('sqlcipher-passphrase-LEAK');
    expect(
      document.querySelector('[data-diagnostic-row="env.var.CHANCELA_DB_KEY.value"]'),
    ).toBeNull();
    expect(
      document.querySelector('[data-diagnostic-row="env.var.CHANCELA_DB_KEY.configured"]'),
    ).not.toBeNull();
  });
});

describe('Diagnóstico — screen and export do not drift', () => {
  it('copies exactly the fields the screen shows, and no others', async () => {
    renderPane();
    await waitForReport();

    fireEvent.click(screen.getByRole('button', { name: /copy|copiar/i }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));

    const text = writeText.mock.calls[0][0] as string;
    const onScreen = [...document.querySelectorAll('[data-diagnostic-row]')].map(
      (row) => row.getAttribute('data-diagnostic-row') as string,
    );
    const exported = text
      .split('\n')
      .filter((line) => line.includes(' = '))
      .map((line) => line.split(' = ')[0].trim());

    expect(onScreen.length).toBeGreaterThan(0);
    expect(exported).toEqual(onScreen);
    expect(text).not.toContain('sqlcipher-passphrase-LEAK');
    // The delivery log is on screen as counts, and the export carries the same — no recipient in
    // either.
    expect(document.body.textContent).not.toContain('amelia.marques');
    expect(text).not.toContain('amelia.marques');
  });
});

describe('Diagnóstico — the three affordances', () => {
  it('surfaces a clipboard refusal instead of failing silently', async () => {
    writeText.mockRejectedValueOnce(new Error('denied'));
    renderPane();
    await waitForReport();

    fireEvent.click(screen.getByRole('button', { name: /copy|copiar/i }));
    await waitFor(() => expect(document.querySelector('.inline-warning--error')).not.toBeNull());
  });

  it('surfaces an unavailable clipboard (an insecure context) the same way', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    renderPane();
    await waitForReport();

    fireEvent.click(screen.getByRole('button', { name: /copy|copiar/i }));
    await waitFor(() => expect(document.querySelector('.inline-warning--error')).not.toBeNull());
  });

  it('isolates the report subtree for print and clears the class afterwards', async () => {
    const print = vi.fn(() => window.dispatchEvent(new Event('afterprint')));
    vi.stubGlobal('print', print);
    renderPane();
    await waitForReport();

    fireEvent.click(screen.getByRole('button', { name: /print|imprimir/i }));
    expect(print).toHaveBeenCalledTimes(1);
    // The class is added for the dialog and removed on `afterprint`, which the stub fires
    // synchronously — so the app is never left permanently hidden.
    expect(document.body.classList.contains('printing-diagnostics')).toBe(false);
  });

  it('writes a .txt whose bytes are what Copy produces, with a safe filename', async () => {
    const createObjectURL = vi.fn((_blob: Blob) => 'blob:diagnostics');
    const revokeObjectURL = vi.fn();
    vi.stubGlobal('URL', { ...URL, createObjectURL, revokeObjectURL });
    const clicks: HTMLAnchorElement[] = [];
    const realClick = HTMLAnchorElement.prototype.click;
    HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
      clicks.push(this);
    };

    try {
      renderPane();
      await waitForReport();
      fireEvent.click(screen.getByRole('button', { name: /\.txt/i }));

      await waitFor(() => expect(clicks.length).toBe(1));
      expect(clicks[0].download).toMatch(
        /^chancela-diagnostics-[A-Za-z0-9._-]+-\d{8}T\d{6}Z\.txt$/,
      );
      // The object URL is released as soon as the anchor has been activated.
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:diagnostics');

      const blob = createObjectURL.mock.calls[0][0];
      expect(blob.type).toContain('text/plain');
      const written = await blob.text();

      fireEvent.click(screen.getByRole('button', { name: /copy|copiar/i }));
      await waitFor(() => expect(writeText).toHaveBeenCalled());
      expect(written).toBe(writeText.mock.calls[0][0]);
    } finally {
      HTMLAnchorElement.prototype.click = realClick;
    }
  });
});

describe('Diagnóstico — the gate', () => {
  it('shows the permission notice, and no rows, without settings.read', async () => {
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <DiagnosticsSection />
      </StaticPermissionsProvider>,
    );

    await waitFor(() => expect(document.querySelector('.inline-warning--error')).not.toBeNull());
    expect(document.querySelector('[data-diagnostic-row]')).toBeNull();
    expect(screen.queryByRole('button', { name: /\.txt/i })).toBeNull();
  });

  it('renders the full report for a reader holding only settings.read', async () => {
    renderWithProviders(
      <StaticPermissionsProvider
        value={permissionsValue((permission) => permission === 'settings.read')}
      >
        <DiagnosticsSection />
      </StaticPermissionsProvider>,
    );

    await waitForReport();
    expect(screen.getByRole('button', { name: /\.txt/i }).hasAttribute('disabled')).toBe(false);
  });
});
