/**
 * Browser coverage for the fresh authentication tranche (t95/t103/t107) — the account
 * security surfaces that only a real browser exercises.
 *
 * ## What this file covers, and the audit that shaped it
 *
 * The task asked for browser coverage of three "fresh auth" flows: the two-step (2FA)
 * sign-in challenge, the forced-password-change wall, and the active-sessions revoke panel.
 * A read of the actual SPA (2026-07-22) found that **two of those three have no client
 * implementation** and therefore cannot be driven in a browser:
 *
 *  - **Two-step sign-in challenge** — the server returns a `two_factor_challenge` (no token)
 *    from `POST /v1/session` when the account has a confirmed factor, but the web contract
 *    (`api/types.ts`: `SessionResult = { token; user }`) models only the token arm, and
 *    `useCreateSession` calls `setSessionToken(result.token)` unconditionally. `SignIn.tsx`
 *    has no code-entry screen. There is nothing in the browser to complete a challenge on.
 *  - **Forced-password-change wall** — the server rides `required_action` on the sign-in
 *    response and on `GET /v1/session`, but the web `SessionView`/`SessionResult` drop the
 *    field entirely and the AuthGate/SignIn state machine never reads it. There is no wall
 *    screen in the SPA.
 *
 * Both flows are exercised end-to-end at the router+AppState level by
 * `crates/chancela-api/tests/two_step_signin.rs` — which is the whole of their behaviour,
 * because the behaviour is entirely server-side. Writing browser tests that "pass" against
 * screens that do not exist would be theatre, so this file does not. The gap (the SPA login
 * state machine has no 2FA/forced-change states) is reported to the lead, not papered over.
 *
 * What DOES have real browser UI, and is the actually-untested-in-a-browser part of this
 * tranche, is on the **Segurança** tab of a user's own edit screen (`EditUserPage.tsx`):
 *
 *  1. **TOTP self-enrolment** — enrol → the QR + one-time base32 secret → confirm with a
 *     live code → the ten single-use backup codes shown once. The code is computed in-spec
 *     from the shown secret (RFC 6238, HMAC-SHA1/6-digit/30s), mirroring
 *     `two_step_signin.rs::current_code`.
 *  2. **Active sessions** — the caller's own sign-ins, the current one flagged and guarded
 *     against self-revoke, and a per-row "Terminar" that genuinely drops the revoked
 *     session's token on its next request.
 *
 * ## Server-poisoning hazard, and why enrolment stays inside one session
 *
 * Because the SPA cannot complete a 2FA challenge, an account that enrols TOTP and then
 * signs out would be unable to sign back in through the browser (the server would answer the
 * next `POST /v1/session` with an un-handleable challenge). The enrolment test therefore
 * never signs out after enrolling — it asserts within the same live session — and the e2e
 * fixture resets the backend to a factory install before every test, so no enrolled factor
 * leaks into a sibling spec.
 */
import { createHmac } from 'node:crypto';
import { test, expect, type APIRequestContext, type Page } from './fixtures';
import { OPERATOR, OPERATOR_PASSWORD, signInAt } from './auth';

const SESSION_HEADER = 'X-Chancela-Session';

/**
 * Pin the browser language to pt-PT for this file.
 *
 * The signed-OUT UI already renders in the instance's document locale (pt-PT), so onboarding
 * works regardless. But once signed in the interface follows the operator's own `language`,
 * which onboarding leaves as `auto` → negotiated against `navigator.languages`. Playwright's
 * default is `en-US`, so the signed-in app would otherwise render in English and every pt-PT
 * assertion below ("Segurança", "Sessões ativas", "Ativar dois fatores"…) would miss. Fixing
 * the browser locale makes `auto` resolve to pt-PT and the whole run deterministic.
 */
test.use({ locale: 'pt-PT' });

// --- In-spec TOTP, mirroring the server's RFC 6238 defaults (totp.rs) ----------------------
//
// HMAC-SHA1, 6 digits, 30-second step, unpadded base32 secret. Implemented here rather than
// pulled as a dependency for the same reason the server implements its own: it is a handful of
// lines and a new dev dependency in a shared tree is a coordination cost out of proportion.

function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  const out: number[] = [];
  let value = 0;
  let bits = 0;
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error(`invalid base32 character: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

/** The current 6-digit TOTP code for a base32 secret, at `atMs` (default now). */
function totpCode(secret: string, atMs: number = Date.now()): string {
  const key = base32Decode(secret);
  const counter = Math.floor(atMs / 1000 / 30);
  const message = Buffer.alloc(8);
  message.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  message.writeUInt32BE(counter >>> 0, 4);
  const hmac = createHmac('sha1', key).update(message).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return (binary % 1_000_000).toString().padStart(6, '0');
}

// --- Helpers -------------------------------------------------------------------------------

/**
 * Open the signed-in operator's own **Segurança** tab (`/users/:id/security`) by navigating
 * the roster the way an operator would.
 *
 * Deliberately **client-side only** — no `page.goto`/reload. The session token is held
 * in-memory + tab-scoped `sessionStorage` (`api/session.ts`), and reaching the panel through
 * SPA route transitions keeps the single onboarding session intact. A full document load would
 * both risk dropping the client token (as `auth.ts` documents happens after onboarding) and
 * mint a fresh server session while orphaning the old one — which would corrupt the
 * active-sessions counts these tests assert on. No id is typed; the panel's self-service
 * affordances only render when the session user IS the edited user, which holds here.
 */
async function openOwnSecurityTab(page: Page): Promise<void> {
  // The current-user picker's "Gerir utilizadores" link → the roster, client-side.
  await page.getByTestId('session-trigger').click();
  await page.getByRole('link', { name: 'Gerir utilizadores' }).click();
  await expect(page).toHaveURL(/\/settings\/users$/);
  await expect(page.getByRole('heading', { name: 'Utilizadores' })).toBeVisible();
  // The roster row's pencil action → `/users/:id`. With one account there is one "Editar".
  await page.getByRole('button', { name: 'Editar', exact: true }).first().click();
  await expect(page).toHaveURL(/\/users\/[0-9a-f-]{36}$/);
  await page.getByRole('button', { name: 'Segurança', exact: true }).click();
  await expect(page).toHaveURL(/\/users\/[0-9a-f-]{36}\/security$/);
  await expect(page.getByRole('heading', { name: 'Segurança da conta' })).toBeVisible();
}

/**
 * Mint a SECOND session for the operator straight against the API — a stand-in for "signed in
 * on another device". Returns its token so the test can prove the token is honoured before a
 * revoke and rejected after. This deliberately creates a real durable session, so the panel
 * lists it alongside the browser's own (current) one.
 */
async function openApiSession(request: APIRequestContext): Promise<string> {
  const response = await request.post('/v1/session', {
    data: { username: OPERATOR.username, password: OPERATOR_PASSWORD },
  });
  expect(response.ok(), `second session: HTTP ${response.status()}`).toBeTruthy();
  const body = (await response.json()) as { token: string };
  expect(body.token).toBeTruthy();
  return body.token;
}

/** Whether a token is still honoured, probed against an auth-gated endpoint (`GET /v1/users`
 *  needs a live session → 401 once the session is revoked). */
async function tokenAccepted(request: APIRequestContext, token: string): Promise<boolean> {
  const response = await request.get('/v1/users', { headers: { [SESSION_HEADER]: token } });
  return response.ok();
}

// --- Active sessions -----------------------------------------------------------------------

test('active sessions: the current device is flagged and cannot be revoked', async ({ page }) => {
  await signInAt(page, '/');
  await openOwnSecurityTab(page);

  const sessions = page.getByRole('table', { name: 'Sessões ativas nesta conta' });
  await expect(sessions).toBeVisible();

  // The one session (the browser's own) is the current one: badged, and its action cell reads
  // "Sessão atual" instead of offering a revoke.
  await expect(page.getByText('esta sessão')).toBeVisible();
  await expect(page.getByText('Sessão atual')).toBeVisible();

  // The current session is never self-revocable here (sign-out is that verb), and with no other
  // session there is no bulk "terminar as outras" action either.
  await expect(page.getByRole('button', { name: 'Terminar', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Terminar as outras sessões' })).toHaveCount(0);
});

test('active sessions: revoking another session drops that session on its next request', async ({
  page,
  request,
}) => {
  await signInAt(page, '/');

  // A second "device": a real API session for the same operator, minted before the panel loads
  // so its first `GET /v1/sessions` already lists two.
  const otherToken = await openApiSession(request);
  expect(await tokenAccepted(request, otherToken)).toBeTruthy();

  await openOwnSecurityTab(page);

  const sessions = page.getByRole('table', { name: 'Sessões ativas nesta conta' });
  await expect(sessions).toBeVisible();
  // Current row is guarded; exactly the OTHER row carries a revoke control.
  await expect(page.getByText('Sessão atual')).toBeVisible();
  const revoke = page.getByRole('button', { name: 'Terminar', exact: true });
  await expect(revoke).toHaveCount(1);

  await revoke.click();
  await expect(page.getByText('Sessão terminada.')).toBeVisible();

  // The list collapses back to just the current session...
  await expect(page.getByRole('button', { name: 'Terminar', exact: true })).toHaveCount(0);
  await expect(page.getByText('Sessão atual')).toBeVisible();

  // ...and the revoked token is genuinely dead: rejected on its next request, not merely
  // delisted from the panel.
  await expect
    .poll(() => tokenAccepted(request, otherToken), {
      message: 'the revoked session token must be rejected on its next request',
    })
    .toBeFalsy();
});

// --- TOTP self-enrolment -------------------------------------------------------------------

test('two-factor: TOTP can be enrolled and confirmed from the Segurança panel', async ({
  page,
}) => {
  await signInAt(page, '/');
  await openOwnSecurityTab(page);

  // Off to begin with.
  const totpCard = page.getByText('Autenticação de dois fatores');
  await expect(totpCard).toBeVisible();

  await page.getByRole('button', { name: 'Ativar dois fatores' }).click();

  // The one-time base32 secret is shown for manual entry; read it and compute a live code, as
  // an authenticator app would from the QR. (`two_step_signin.rs::current_code`, in-browser.)
  const secretLocator = page.locator('.totp-enrol__secret code.mono');
  await expect(secretLocator).toBeVisible();
  const secret = (await secretLocator.textContent())?.trim();
  expect(secret, 'the enrolment secret must be shown once for manual entry').toBeTruthy();

  await page.getByLabel('Código de verificação').fill(totpCode(secret as string));
  await page.getByRole('button', { name: 'Confirmar', exact: true }).click();

  // A confirmed factor reveals the ten single-use backup codes, shown exactly once.
  await expect(page.getByText('Guarde os códigos de recuperação')).toBeVisible();
  await expect(page.locator('.totp-backup-codes li')).toHaveCount(10);

  // Dismiss the once-shown codes; the factor now reads as active.
  await page.getByRole('button', { name: 'Concluído' }).click();
  await expect(page.getByText('Códigos de recuperação restantes')).toBeVisible();

  // Clean up the factor before the test ends. This is REQUIRED, not cosmetic: a confirmed TOTP
  // on the sole operator makes the next `POST /v1/session` return a 2FA challenge instead of a
  // token — including the one the e2e fixture uses to authenticate its factory reset — so a
  // leftover factor would fail the reset of every subsequent test (the SPA cannot complete a
  // challenge; see the file header). Disabling is offered because this account is not
  // `two_factor_required`, and it returns the operator to a resettable state.
  await page.getByRole('button', { name: 'Desativar dois fatores' }).click();
  await expect(page.getByText('Dois fatores desativados.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Ativar dois fatores' })).toBeVisible();
});

test('two-factor: a wrong confirmation code is rejected inline, keeping the enrolment open', async ({
  page,
}) => {
  await signInAt(page, '/');
  await openOwnSecurityTab(page);

  await page.getByRole('button', { name: 'Ativar dois fatores' }).click();

  const secretLocator = page.locator('.totp-enrol__secret code.mono');
  await expect(secretLocator).toBeVisible();
  const secret = ((await secretLocator.textContent()) ?? '').trim();
  // A code guaranteed NOT to be the current one (real + 1, mod 10^6), so the "wrong code"
  // assertion cannot flake on a 1-in-a-million collision with the live code.
  const wrong = ((Number(totpCode(secret)) + 1) % 1_000_000).toString().padStart(6, '0');

  await page.getByLabel('Código de verificação').fill(wrong);
  await page.getByRole('button', { name: 'Confirmar', exact: true }).click();

  // Rejected inline against the field; a wrong code is a credential-proof failure, never a
  // sign-out — the enrolment form stays open (the secret field is still shown) to retry.
  await expect(page.getByText('Código incorreto. Tente novamente.')).toBeVisible();
  await expect(secretLocator).toBeVisible();
  await expect(page.getByTestId('tab-bar')).toBeVisible();
  await expect(page.locator('.totp-backup-codes li')).toHaveCount(0);
});
