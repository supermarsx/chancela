/**
 * Focused browser hardening for the notification popup layer. The app-shell behavior here
 * depends on real fixed/portal DOM placement, outside-click handling, and routed links, so
 * these checks sit in Playwright with mocked API state instead of live providers.
 */
import { expect, test, type Page, type Route } from './fixtures';
import type {
  Dashboard,
  DashboardAlert,
  LedgerEventView,
  NotificationTriageEntry,
  NotificationTriageStatus,
  Settings,
  UserView,
} from '../src/api/types';

const USER_ID = '6f0ca878-6a50-45fa-8a4d-2511ff0f0a01';
const LEDGER_ALERT_ID = 'alert:ledger.integrity.review_required:-:-:-:0';

test('notification popup is portaled above shell chrome and closes on outside click', async ({
  page,
}) => {
  const triageUpdates = await routeNotificationFixtures(page);

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Vista geral' })).toBeVisible();

  const bell = page.getByRole('button', { name: '1 notificações pendentes' });
  await expect(bell).toHaveAttribute('aria-expanded', 'false');

  await bell.click();

  const dialog = page.getByRole('dialog', { name: 'Notificações' });
  await expect(dialog).toBeVisible();
  await expect(bell).toHaveAttribute('aria-expanded', 'true');
  await expect(dialog.getByText('Verificar cadeia do registo')).toBeVisible();

  await expect
    .poll(() => dialog.evaluate((node) => node.parentElement === document.body))
    .toBe(true);
  const popupZ = await zIndex(dialog);
  const topbarZ = await zIndex(page.locator('.topbar'));
  expect(popupZ).toBeGreaterThan(topbarZ);

  await page.mouse.click(12, 220);

  await expect(dialog).toHaveCount(0);
  await expect(bell).toHaveAttribute('aria-expanded', 'false');
  await expect(page).toHaveURL(/\/$/);
  expect(triageUpdates).toEqual([]);
});

test('notification action closes the popup before routing to the archive page', async ({
  page,
}) => {
  await routeNotificationFixtures(page);

  await page.goto('/');
  await page.getByRole('button', { name: '1 notificações pendentes' }).click();

  const dialog = page.getByRole('dialog', { name: 'Notificações' });
  await expect(dialog.getByRole('link', { name: 'Abrir arquivo' })).toBeVisible();

  await Promise.all([
    page.waitForURL(/\/arquivo$/),
    dialog.getByRole('link', { name: 'Abrir arquivo' }).click(),
  ]);

  await expect(dialog).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Arquivo — registo cronológico' })).toBeVisible();
  await expect(page.getByText('Cadeia verificada (3 eventos)')).toBeVisible();
});

test('marking a notification read encodes the id and removes it from the popup count', async ({
  page,
}) => {
  const triageUpdates = await routeNotificationFixtures(page);

  await page.goto('/');
  await page.getByRole('button', { name: '1 notificações pendentes' }).click();

  const dialog = page.getByRole('dialog', { name: 'Notificações' });
  const patchResponse = page.waitForResponse((response) => {
    const request = response.request();
    const url = new URL(response.url());
    return (
      request.method() === 'PATCH' &&
      url.pathname === `/v1/notifications/triage/${encodeURIComponent(LEDGER_ALERT_ID)}`
    );
  });

  await dialog.getByRole('button', { name: 'Marcar como lida' }).click();
  expect((await patchResponse).status()).toBe(200);

  await expect(page.locator('.notification-bell')).toHaveAccessibleName('Notificações');
  await expect(page.getByRole('button', { name: '1 notificações pendentes' })).toHaveCount(0);
  await expect(dialog.getByText('Verificar cadeia do registo')).toHaveCount(0);
  await expect(dialog.getByText('Evento notification.fixture')).toBeVisible();
  expect(triageUpdates).toEqual([{ notificationId: LEDGER_ALERT_ID, status: 'read' }]);
});

async function routeNotificationFixtures(page: Page): Promise<TriageUpdate[]> {
  const triageEntries: NotificationTriageEntry[] = [];
  const triageUpdates: TriageUpdate[] = [];
  const user = userFixture();

  await page.route('**/health', async (route) => {
    await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
  });

  await page.route('**/v1/settings', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, settingsFixture());
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/session**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/session') {
      await fulfillJson(route, sessionFixture(user));
      return;
    }
    if (request.method() === 'GET' && pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: [
          {
            id: user.id,
            username: user.username,
            display_name: user.display_name,
            has_secret: false,
          },
        ],
      });
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/users', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, [user]);
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/dashboard', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, dashboardFixture());
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/notifications/triage**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/notifications/triage') {
      await fulfillJson(route, {
        entries: triageEntries,
        durable: true,
        max_entries_per_owner: 500,
      });
      return;
    }

    const notificationId = pathname.match(/^\/v1\/notifications\/triage\/(.+)$/)?.[1];
    if (request.method() === 'PATCH' && notificationId) {
      const status = (request.postDataJSON() as { status: NotificationTriageStatus }).status;
      const decodedId = decodeURIComponent(notificationId);
      triageUpdates.push({ notificationId: decodedId, status });
      const entry =
        status === 'unread'
          ? null
          : {
              notification_id: decodedId,
              status,
              updated_at: '2026-07-10T10:00:00.000Z',
            };
      triageEntries.splice(0, triageEntries.length, ...(entry ? [entry] : []));
      await fulfillJson(route, { status, entry, durable: true });
      return;
    }

    await route.continue();
  });

  await page.route('**/v1/ledger/verify', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, { valid: true, length: 3 });
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/ledger/integrity', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, {
        healthy: true,
        degraded: false,
        global: null,
        chains: [],
        reanchored_segments: [],
      });
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/ledger/events**', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, [ledgerEventFixture()]);
      return;
    }
    await route.continue();
  });

  return triageUpdates;
}

type TriageUpdate = {
  notificationId: string;
  status: NotificationTriageStatus;
};

async function zIndex(locator: ReturnType<Page['locator']>): Promise<number> {
  return locator.evaluate((node) => {
    const raw = window.getComputedStyle(node).zIndex;
    const parsed = Number(raw);
    return Number.isFinite(parsed) ? parsed : 0;
  });
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function userFixture(): UserView {
  return {
    id: USER_ID,
    username: 'notifications.e2e',
    display_name: 'Notificações E2E',
    created_at: '2026-07-10T00:00:00.000Z',
    active: true,
    has_secret: false,
    has_attestation_key: false,
    has_recovery_phrase: false,
  };
}

function sessionFixture(user: UserView) {
  return {
    user,
    permissions: ['ledger.read'].map((permission) => ({
      permission,
      scope: { kind: 'global' },
      source: 'role',
    })),
  };
}

function dashboardFixture(): Dashboard {
  return {
    entities: 0,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    ledger_length: 3,
    ledger_valid: true,
    current_work: {
      open_books: [],
      act_counts_by_state: {
        Draft: 0,
        Review: 0,
        Convened: 0,
        Deliberated: 0,
        TextApproved: 0,
        Signing: 0,
        Sealed: 0,
        Archived: 0,
      },
    },
    alerts: [ledgerAlertFixture()],
    reminders: [],
    recent_events: [ledgerEventFixture()],
  };
}

function ledgerAlertFixture(): DashboardAlert {
  return {
    code: 'ledger.integrity.review_required',
    label: 'ReviewRequired',
    severity: 'Error',
    category: 'LedgerIntegrity',
    message: 'Ledger review required in the E2E fixture.',
    params: {},
    target: {
      entity_id: null,
      book_id: null,
      act_id: null,
      links: { entity: null, book: null, act: null, ledger: '/v1/ledger/verify' },
    },
    source: 'e2e.notifications',
  };
}

function ledgerEventFixture(): LedgerEventView {
  return {
    id: 'notification-ledger-event',
    seq: 3,
    actor: 'notifications.e2e',
    justification: null,
    timestamp: '2026-07-10T09:00:00.000Z',
    scope: 'global',
    kind: 'notification.fixture',
    payload_digest: 'aa'.repeat(32),
    prev_hash: 'bb'.repeat(32),
    hash: 'cc'.repeat(32),
    chains: ['global'],
    attestation: null,
  };
}

function settingsFixture(): Settings {
  return {
    schema_version: 1,
    organization: { name: null, default_actor: 'api' },
    documents: { locale: 'pt-PT', numbering_scheme_default: 'Sequential' },
    catalog: {
      cae_update_url: null,
      cae_sources: [],
      cae_official_source: false,
      preferred_official_source: 'Ine',
    },
    signing: {
      preferred_family: 'ChaveMovelDigital',
      tsa_url: null,
      tsl_url: null,
      require_qualified_for_seal: false,
      cmd: { env: 'preprod', application_id: null, ama_cert_configured: false },
    },
    appearance: {
      theme: 'system',
      leather_texture: true,
      texture_intensity: 60,
      button_texture: true,
    },
    onboarding: { completed: true, completed_at: '2026-07-10T00:00:00.000Z' },
    ai: { enabled: false },
  };
}
