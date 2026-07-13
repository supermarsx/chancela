import { expect, test, type Page, type Route } from '@playwright/test';
import {
  DEFAULT_SETTINGS,
  type Dashboard,
  type IntegrityReportView,
  type LedgerEventView,
  type LedgerEventsPage,
  type Settings,
  type UserView,
} from '../src/api/types';

const OPERATOR: UserView = {
  id: 'user-archive-bounds',
  username: 'amelia.marques',
  display_name: 'Amelia Marques',
  email: 'amelia@example.test',
  created_at: '2026-07-13T09:00:00.000Z',
  active: true,
  has_secret: false,
  has_attestation_key: false,
  has_recovery_phrase: true,
};

test('arquivo loads only the bounded first page and fetches older events by cursor', async ({
  page,
}) => {
  const firstPageEvents = Array.from({ length: 100 }, (_, index) =>
    ledgerEvent(1100 - index, { kind: `first-page.event.${1100 - index}` }),
  );
  const olderTailEvent = ledgerEvent(900, { kind: 'older-tail.event.900' });
  const ledgerRequests = await routeArchiveFixtures(page, {
    firstPage: ledgerPage(firstPageEvents, { has_more: true, next_cursor: 1000 }),
    olderPage: ledgerPage([ledgerEvent(1000, { kind: 'cursor-page.event.1000' }), olderTailEvent]),
  });

  await page.goto('/arquivo');

  await expect(page.getByText('first-page.event.1100')).toBeVisible();
  await expect(page.getByText('first-page.event.1001')).toBeVisible();
  await expect(page.getByText('cursor-page.event.1000')).toHaveCount(0);
  await expect(page.getByText('older-tail.event.900')).toHaveCount(0);
  await expect(page.getByRole('row')).toHaveCount(101);
  expect(ledgerRequests.page).toEqual(['/v1/ledger/events/page?limit=100&order=desc']);

  await page.getByRole('button', { name: 'Carregar eventos mais antigos' }).click();

  await expect(page.getByText('cursor-page.event.1000')).toBeVisible();
  await expect(page.getByText('older-tail.event.900')).toBeVisible();
  await expect
    .poll(() =>
      ledgerRequests.page.includes('/v1/ledger/events/page?before_seq=1000&limit=100&order=desc'),
    )
    .toBe(true);
});

test('arquivo filters and archive export use the current bounded newest-first query', async ({
  page,
}) => {
  const ledgerRequests = await routeArchiveFixtures(page, {
    firstPage: ledgerPage([ledgerEvent(88, { kind: 'act.sealed', scope: 'act:88' })]),
  });
  const expectedFilterPath =
    '/v1/ledger/events/page?q=approved+digest&chain=book%3Abook-123456789&scope=act%3A88&kind=act.sealed&actor=amelia.marques&from=2026-07-01&to=2026-07-31&limit=50&order=desc';

  await page.goto('/arquivo');
  await expect(page.getByText('act.sealed')).toBeVisible();

  await page.getByRole('searchbox', { name: 'Pesquisar' }).fill('approved digest');
  await page.getByLabel('Filtrar por cadeia').selectOption('book:book-123456789');
  await page.getByLabel('Filtrar por âmbito').fill('act:88');
  await page.getByText('Filtros avançados').click();
  await page.getByLabel('Tipo de evento').fill('act.sealed');
  await page.getByLabel('Autor').fill('amelia.marques');
  await page.getByLabel('Desde').fill('2026-07-01');
  await page.getByLabel('Até').fill('2026-07-31');
  await page.getByLabel('Eventos por página').selectOption('50');

  await expect.poll(() => ledgerRequests.page.includes(expectedFilterPath)).toBe(true);

  await page.getByLabel('Formato de exportação').selectOption('json');
  await page.getByRole('button', { name: 'Exportar arquivo' }).click();

  await expect.poll(() => ledgerRequests.archive.length).toBe(1);
  const archiveUrl = new URL(`http://chancela.test${ledgerRequests.archive[0]}`);
  expect(archiveUrl.pathname).toBe('/v1/ledger/archive/document');
  expect(archiveUrl.searchParams.get('format')).toBe('json');
  expect(archiveUrl.searchParams.get('q')).toBe('approved digest');
  expect(archiveUrl.searchParams.get('chain')).toBe('book:book-123456789');
  expect(archiveUrl.searchParams.get('scope')).toBe('act:88');
  expect(archiveUrl.searchParams.get('kind')).toBe('act.sealed');
  expect(archiveUrl.searchParams.get('actor')).toBe('amelia.marques');
  expect(archiveUrl.searchParams.get('from')).toBe('2026-07-01');
  expect(archiveUrl.searchParams.get('to')).toBe('2026-07-31');
  expect(archiveUrl.searchParams.get('limit')).toBe('50');
  expect(archiveUrl.searchParams.get('order')).toBe('desc');
  expect(archiveUrl.searchParams.has('before_seq')).toBe(false);
});

type ArchiveRouteOptions = {
  firstPage: LedgerEventsPage;
  olderPage?: LedgerEventsPage;
};

type ArchiveRequests = {
  page: string[];
  archive: string[];
};

async function routeArchiveFixtures(
  page: Page,
  options: ArchiveRouteOptions,
): Promise<ArchiveRequests> {
  const requests: ArchiveRequests = { page: [], archive: [] };

  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = `${url.pathname}${url.search}`;

    if (url.pathname === '/health') {
      await fulfillJson(route, { status: 'ok', version: 'e2e', integrity: 'ok', degraded: false });
      return;
    }

    if (!url.pathname.startsWith('/v1/')) {
      await route.continue();
      return;
    }

    if (request.method() !== 'GET') {
      await fulfillJson(route, { error: `Unexpected ${request.method()} ${url.pathname}` }, 500);
      return;
    }

    if (url.pathname === '/v1/session') {
      await fulfillJson(route, {
        user: OPERATOR,
        permissions: [{ permission: 'ledger.read', scope: { kind: 'global' }, source: 'role' }],
      });
      return;
    }

    if (url.pathname === '/v1/session/roster') {
      await fulfillJson(route, {
        onboarding_required: false,
        users: [
          {
            id: OPERATOR.id,
            username: OPERATOR.username,
            display_name: OPERATOR.display_name,
            has_secret: false,
          },
        ],
      });
      return;
    }

    if (url.pathname === '/v1/settings') {
      await fulfillJson(route, settingsFixture());
      return;
    }

    if (url.pathname === '/v1/users') {
      await fulfillJson(route, [OPERATOR]);
      return;
    }

    if (url.pathname === '/v1/dashboard') {
      await fulfillJson(route, dashboardFixture());
      return;
    }

    if (url.pathname === '/v1/notifications/triage') {
      await fulfillJson(route, { entries: [], durable: true, max_entries_per_owner: 500 });
      return;
    }

    if (url.pathname === '/v1/ledger/verify') {
      await fulfillJson(route, { valid: true, length: 1100 });
      return;
    }

    if (url.pathname === '/v1/ledger/integrity') {
      await fulfillJson(route, integrityFixture());
      return;
    }

    if (url.pathname === '/v1/ledger/events/page') {
      requests.page.push(path);
      await fulfillJson(
        route,
        url.searchParams.has('before_seq')
          ? (options.olderPage ?? ledgerPage([]))
          : options.firstPage,
      );
      return;
    }

    if (url.pathname === '/v1/ledger/archive/document') {
      requests.archive.push(path);
      await route.fulfill({
        status: 200,
        contentType: archiveContentType(url.searchParams.get('format')),
        body: archiveBody(url.searchParams.get('format')),
      });
      return;
    }

    await fulfillJson(route, { error: `Unexpected route-stubbed request: ${path}` }, 500);
  });

  return requests;
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}

function ledgerPage(
  events: LedgerEventView[],
  patch: Partial<LedgerEventsPage> = {},
): LedgerEventsPage {
  return {
    events,
    next_cursor: null,
    has_more: false,
    limit: 100,
    order: 'desc',
    ...patch,
  };
}

function ledgerEvent(seq: number, patch: Partial<LedgerEventView> = {}): LedgerEventView {
  return {
    id: `ledger-event-${seq}`,
    seq,
    actor: 'amelia.marques',
    justification: null,
    timestamp: `2026-07-13T10:${String(seq % 60).padStart(2, '0')}:00.000Z`,
    scope: `act:${seq}`,
    kind: `event.${seq}`,
    payload_digest: 'aa'.repeat(32),
    prev_hash: '00'.repeat(32),
    hash: String(seq % 10).repeat(64),
    chains: ['global', 'book:book-123456789'],
    attestation: null,
    ...patch,
  };
}

function settingsFixture(): Settings {
  return {
    ...DEFAULT_SETTINGS,
    organization: { ...DEFAULT_SETTINGS.organization, name: 'Arquivo E2E' },
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
    ledger_length: 1100,
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
    alerts: [],
    reminders: [],
    recent_events: [],
  };
}

function integrityFixture(): IntegrityReportView {
  return {
    healthy: true,
    degraded: false,
    global: {
      chain: 'global',
      genesis_kind: null,
      length: 1100,
      head: 'bb'.repeat(32),
      verified: true,
      first_break: null,
    },
    chains: [
      {
        chain: 'book:book-123456789',
        genesis_kind: 'book.opened',
        length: 1100,
        head: 'bb'.repeat(32),
        verified: true,
        first_break: null,
      },
    ],
    reanchored_segments: [],
  };
}

function archiveContentType(format: string | null): string {
  if (format === 'json') return 'application/json';
  if (format === 'txt') return 'text/plain;charset=utf-8';
  if (format === 'csv') return 'text/csv;charset=utf-8';
  if (format === 'html') return 'text/html;charset=utf-8';
  return 'application/pdf';
}

function archiveBody(format: string | null): string {
  if (format === 'json') return '{"events":[]}';
  if (format === 'txt') return 'AUDIT EXPORT';
  if (format === 'csv') return 'seq,kind\n';
  if (format === 'html') return '<!doctype html><h1>Audit export</h1>';
  return '%PDF-archive';
}
