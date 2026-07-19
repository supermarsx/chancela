/**
 * Route stubs for the endpoints the signed-in app shell polls on **every** page.
 *
 * Specs that fake a signed-in shell with `page.route` (rather than really signing in via
 * {@link ./auth#signInAt}) have no session token, so any request they forget to stub reaches
 * the real server and comes back `401`. Every helper in `src/api/client.ts` clears the session
 * token on a 401, which unmounts the app chrome and drops the test onto the sign-in page — a
 * failure mode that looks like a stale selector and is not, and that a spec provokes simply by
 * omitting a stub for something it never mentions.
 *
 * `NotificationBell` is part of the shell, so `/v1/dashboard` and `/v1/notifications/triage`
 * are polled on every route. They are stubbed here, once, so a fake-shell helper cannot forget
 * them. Register this **first** in the fake-shell helper: Playwright matches handlers in
 * reverse registration order, so any stub a spec installs afterwards still wins.
 */
import type { Page, Route } from './fixtures';
import type { Dashboard, NotificationTriageResponse } from '../src/api/types';

/** A well-formed dashboard with nothing in it: renders the shell, raises no alerts. */
export function emptyDashboardFixture(): Dashboard {
  return {
    entities: 0,
    books_open: 0,
    books_total: 0,
    acts_total: 0,
    acts_draft: 0,
    acts_awaiting_signature: 0,
    acts_sealed: 0,
    unresolved_compliance: 0,
    failed_sync_jobs: 0,
    pending_backup_jobs: 0,
    ledger_length: 0,
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

function emptyTriageFixture(): NotificationTriageResponse {
  return { entries: [], durable: true, max_entries_per_owner: 500 };
}

/**
 * Stub the shell-polled reads (`/v1/dashboard`, `/v1/notifications/triage`) plus the triage
 * PATCH the bell issues when the operator marks an entry read. Call this at the top of a
 * fake-signed-in-shell helper; specs that need a real payload just route the same URL later.
 */
export async function routeShellPolling(page: Page): Promise<void> {
  await page.route('**/v1/dashboard', async (route) => {
    if (route.request().method() === 'GET') {
      await fulfillJson(route, emptyDashboardFixture());
      return;
    }
    await route.continue();
  });

  await page.route('**/v1/notifications/triage**', async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'GET' && pathname === '/v1/notifications/triage') {
      await fulfillJson(route, emptyTriageFixture());
      return;
    }

    const notificationId = pathname.match(/^\/v1\/notifications\/triage\/([^/]+)$/)?.[1];
    if (request.method() === 'PATCH' && notificationId) {
      const status = (request.postDataJSON() as { status?: string } | null)?.status ?? 'read';
      await fulfillJson(route, {
        status,
        entry:
          status === 'unread'
            ? null
            : {
                notification_id: decodeURIComponent(notificationId),
                status,
                updated_at: new Date().toISOString(),
              },
        durable: true,
      });
      return;
    }

    await route.continue();
  });
}

async function fulfillJson(route: Route, body: unknown, status = 200): Promise<void> {
  await route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify(body),
  });
}
