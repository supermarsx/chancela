import { expect, test as base } from '@playwright/test';
import type { APIRequestContext, TestInfo } from '@playwright/test';
import { OPERATOR, OPERATOR_PASSWORD } from './auth';

const RESET_DISABLED_ENV = 'CHANCELA_E2E_RESET_BETWEEN_TESTS';
const RESET_ACTOR = 'e2e:playwright-reset';
const SESSION_RETRY_DELAYS_MS = [0, 250, 750, 1_500, 3_000];
const ROSTER_RETRY_DELAYS_MS = [100, 250, 500, 1_000, 2_000];

/** t33-e2: one boolean. It used to also list every user — unauthenticated enumeration. */
type SessionRoster = {
  onboarding_required: boolean;
};

type SessionResult = {
  token: string;
};

export const test = base.extend<{ e2eBackendReset: void }>({
  e2eBackendReset: [
    async ({ request }, use, testInfo) => {
      if (!isResetDisabled()) {
        await resetBackendForTest(request, testInfo);
      }

      await use();
    },
    { auto: true },
  ],
});

export { expect };
export type { APIRequestContext, Download, Locator, Page, Route } from '@playwright/test';

function isResetDisabled(): boolean {
  const value = process.env[RESET_DISABLED_ENV]?.toLowerCase();
  return value === '0' || value === 'false';
}

async function resetBackendForTest(request: APIRequestContext, testInfo: TestInfo): Promise<void> {
  const roster = await fetchRoster(request, `before ${testInfo.title}`);
  if (roster.onboarding_required) {
    return;
  }

  const session = await createResetSession(request, testInfo);

  const response = await request.post('/v1/data/reset', {
    headers: { 'X-Chancela-Session': session.token },
    data: {
      scope: 'backend_factory',
      confirm_phrase: 'REPOR FÁBRICA',
      export_first: false,
      skip_export_confirm: true,
      reauth: { password: OPERATOR_PASSWORD },
      actor: RESET_ACTOR,
    },
  });

  if (!response.ok()) {
    throw new Error(
      `E2E backend reset failed before "${testInfo.title}": ${await responseDetails(response)}`,
    );
  }

  await waitForFreshInstall(request, testInfo);
}

/**
 * Open the reset session. t33-e2: `GET /v1/session/roster` no longer lists users (it was
 * unauthenticated user enumeration), so there is nothing to look the operator up in — and
 * nothing to: `POST /v1/session` resolves the username itself. A missing operator, an
 * inactive one and a wrong password are now the same opaque 401, which the error below
 * reports honestly rather than pretending to know which it was.
 */
async function createResetSession(
  request: APIRequestContext,
  testInfo: TestInfo,
): Promise<SessionResult> {
  let lastDetails = 'session was not attempted';

  for (const delayMs of SESSION_RETRY_DELAYS_MS) {
    if (delayMs > 0) {
      await delay(delayMs);
    }

    const response = await request.post('/v1/session', {
      data: {
        username: OPERATOR.username,
        password: OPERATOR_PASSWORD,
      },
    });

    if (response.ok()) {
      return (await response.json()) as SessionResult;
    }

    lastDetails = await responseDetails(response);
    if (response.status() !== 429) {
      break;
    }
  }

  throw new Error(
    `E2E backend reset could not create a reset session for ${OPERATOR.username} before "${testInfo.title}": ${lastDetails}`,
  );
}

async function waitForFreshInstall(request: APIRequestContext, testInfo: TestInfo): Promise<void> {
  for (const delayMs of ROSTER_RETRY_DELAYS_MS) {
    await delay(delayMs);
    const roster = await fetchRoster(request, `after reset for ${testInfo.title}`);
    if (roster.onboarding_required) {
      return;
    }
  }

  throw new Error(`E2E backend reset before "${testInfo.title}" did not reach first-launch state.`);
}

async function fetchRoster(request: APIRequestContext, context: string): Promise<SessionRoster> {
  const response = await request.get('/v1/session/roster');
  if (!response.ok()) {
    throw new Error(`E2E session roster failed ${context}: ${await responseDetails(response)}`);
  }

  return (await response.json()) as SessionRoster;
}

async function responseDetails(response: { status(): number; text(): Promise<string> }) {
  const body = await response.text();
  const truncated = body.length > 500 ? `${body.slice(0, 500)}...` : body;
  return `HTTP ${response.status()} ${truncated}`;
}

async function delay(ms: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
