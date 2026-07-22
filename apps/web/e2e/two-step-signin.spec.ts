/**
 * Browser coverage for the fresh authentication tranche (t95/t103/t107) — the account
 * security surfaces that only a real browser exercises.
 *
 * ## What this file covers, and the audit that shaped it
 *
 * The task asked for browser coverage of three "fresh auth" flows: the two-step (2FA)
 * sign-in challenge, the forced-password-change wall, and the active-sessions revoke panel.
 * When this file was first written (2026-07-22) **two of those three had no client
 * implementation** — the SPA dropped the server's `two_factor_challenge` and `required_action`
 * responses on the floor, so an operator who enrolled TOTP and then signed out was locked out of
 * the browser entirely (the next `POST /v1/session` came back as a challenge the client could not
 * handle). t21 shipped the two missing screens — the challenge sub-state in `SignIn.tsx`
 * (`TwoFactorChallengeForm`) and the required-action wall in `AuthGate.tsx` (`RequiredActionGate`)
 * — so those flows are now real UI a browser can drive, and the tests at the foot of this file
 * prove the lockout is fixed end-to-end:
 *
 *  - **Two-step sign-in challenge** — enrol TOTP, sign out, sign back in with the password: the
 *    SPA now shows the code-entry card (not a dead end), a live code lands in the app, and a wrong
 *    code is rejected inline without leaving the challenge or the sign-in surface.
 *  - **Forced-password-change wall** — an account seeded through the `send_welcome_email:true`
 *    create path (which sets `force_password_change`, `users.rs`) signs in to the wall, which
 *    blocks the app until the password is changed, then lifts into the chrome.
 *
 * The same behaviour is exercised at the router+AppState level by
 * `crates/chancela-api/tests/two_step_signin.rs`; these browser tests add the one layer only a real
 * browser covers — the SPA state machine actually rendering the challenge and the wall, and the
 * uniform-401 rejects staying inline rather than ejecting the session.
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
 * ## Server-poisoning hazard, and why every enrolment is disabled again
 *
 * The SPA can now complete a challenge, but the e2e fixture's factory reset (`fixtures.ts`) still
 * authenticates over the raw `POST /v1/session` API, which has NO challenge step: a confirmed TOTP
 * factor makes that reset session come back as an un-handleable challenge instead of a token,
 * stranding the reset of every subsequent test. So the panel enrolment test asserts within one
 * live session, and the round-trip test below — which deliberately enrols, signs out, and signs
 * back in through the challenge — ends by disabling the factor again, returning the operator to
 * the resettable state the fixture needs. The e2e fixture also resets the backend to a factory
 * install before every test, so no enrolled factor leaks into a sibling spec.
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

// --- Two-step sign-in challenge + required-action wall (t21) --------------------------------
//
// The screens these drive did not exist when the file was first written (see the header); t21
// shipped them, so the lockout the header describes is now provable in a real browser. Every
// test that leaves a confirmed TOTP factor enrolled MUST disable it again before it ends — the
// fixture's factory reset authenticates over the challenge-less `POST /v1/session` API, so a
// stranded factor would fail the reset of the next test (see the header's poisoning note).

/** One TOTP step in ms — the server's `STEP_SECONDS` (totp.rs). */
const TOTP_STEP_MS = 30_000;

/**
 * Enrol TOTP from the open Segurança panel and return the base32 secret, leaving the factor
 * ACTIVE. Unlike the panel enrolment test above (which disables it in the same session), this
 * keeps the factor on so the caller can sign out and be challenged — the exact state that used to
 * lock the browser out. The confirmation code is computed live from the shown secret.
 */
async function enrolTotpFromSecurityPanel(page: Page): Promise<string> {
  await page.getByRole('button', { name: 'Ativar dois fatores' }).click();
  const secretLocator = page.locator('.totp-enrol__secret code.mono');
  await expect(secretLocator).toBeVisible();
  const secret = ((await secretLocator.textContent()) ?? '').trim();
  expect(secret, 'the enrolment secret must be shown once for manual entry').toBeTruthy();

  await page.getByLabel('Código de verificação').fill(totpCode(secret));
  await page.getByRole('button', { name: 'Confirmar', exact: true }).click();
  await expect(page.getByText('Guarde os códigos de recuperação')).toBeVisible();
  await page.getByRole('button', { name: 'Concluído' }).click();
  await expect(page.getByText('Códigos de recuperação restantes')).toBeVisible();
  return secret;
}

/** Sign out through the current-user picker and land back on the sign-in surface. */
async function signOutToSignInSurface(page: Page): Promise<void> {
  await page.getByTestId('session-trigger').click();
  await page.getByRole('button', { name: 'Terminar sessão', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Iniciar sessão' })).toBeVisible();
}

/**
 * Type an identifier + password on the sign-in surface and submit. Deliberately does NOT wait for
 * the app chrome: the account may answer with a 2FA challenge (Screen A) or a required-action wall
 * (Screen B) instead of the tab bar — the caller asserts which.
 */
async function submitSignIn(page: Page, username: string, password: string): Promise<void> {
  await page.getByLabel('Utilizador', { exact: true }).fill(username);
  await page.getByLabel('Palavra-passe', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Entrar' }).click();
}

/** Disable TOTP from the open Segurança panel — REQUIRED cleanup (see the section note). */
async function disableTotpFromSecurityPanel(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Desativar dois fatores' }).click();
  await expect(page.getByText('Dois fatores desativados.')).toBeVisible();
}

test('two-step sign-in: an enrolled operator is challenged on sign-in and completes it (the lockout, fixed)', async ({
  page,
}) => {
  await signInAt(page, '/');
  await openOwnSecurityTab(page);

  // Enrol a real factor and KEEP it on — this is the state that locked the browser out before t21.
  const secret = await enrolTotpFromSecurityPanel(page);

  // Sign out: the next `POST /v1/session` will answer with a challenge, not a token.
  await signOutToSignInSurface(page);

  // Sign in with the password. Before t21 the SPA dropped the challenge and never signed in; now
  // the code-entry card takes over the sign-in surface instead of the app.
  await submitSignIn(page, OPERATOR.username, OPERATOR_PASSWORD);
  await expect(page.getByRole('heading', { name: 'Verificação em dois passos' })).toBeVisible();
  await expect(page.getByTestId('tab-bar')).toHaveCount(0);

  // A wrong code is rejected inline; the card stays, the app is not shown, nothing navigates. The
  // "+1" wrong code mirrors the panel enrolment test above (collision with a live window code is a
  // ~3-in-a-million non-event); a rejected attempt does not spend the challenge server-side.
  const wrong = ((Number(totpCode(secret)) + 1) % 1_000_000).toString().padStart(6, '0');
  await page.getByLabel('Código de verificação').fill(wrong);
  await page.getByRole('button', { name: 'Confirmar', exact: true }).click();
  await expect(page.getByText('Código incorreto. Tente novamente.')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Verificação em dois passos' })).toBeVisible();
  await expect(page.getByTestId('tab-bar')).toHaveCount(0);

  // A live code completes the challenge and lands in the app. Computed one step AHEAD on purpose:
  // the enrolment confirmation already spent the current step, and the server's replay guard
  // (`last_accepted_step`, totp.rs) refuses any step it has already accepted — a same-window code
  // would be rejected as a replay. One step ahead is inside the server's ±1 window yet strictly
  // later than the enrol step, so it is accepted, not replayed.
  const live = totpCode(secret, Date.now() + TOTP_STEP_MS);
  await page.getByLabel('Código de verificação').fill(live);
  await page.getByRole('button', { name: 'Confirmar', exact: true }).click();
  await expect(page.getByTestId('tab-bar')).toBeVisible();

  // Cleanup (REQUIRED): disable the factor so the fixture's challenge-less reset can authenticate
  // for the next test. This is the recovery the header's poisoning note describes.
  await openOwnSecurityTab(page);
  await disableTotpFromSecurityPanel(page);
});

test('required-action wall: a forced-password-change account must change it before reaching the app', async ({
  page,
  request,
}) => {
  // Onboard the operator: this initialises the instance (so the create below is authorized) and
  // means the seeded account signs in against a real sign-in surface, not the first-run wizard.
  await signInAt(page, '/');

  // Seed the walled account the real way (plan D3): `POST /v1/users` with `send_welcome_email:true`
  // sets `force_password_change` (users.rs), the admin choosing the initial password — so the test
  // knows it. Authorized with a fresh session for the operator (Owner\@Global). The example account
  // is fictional, per the house naming rule.
  const operatorToken = await openApiSession(request);
  const walledUser = 'amelia.marques';
  const seededPassword = 'Adm1n!Seed2026';
  const created = await request.post('/v1/users', {
    headers: { [SESSION_HEADER]: operatorToken },
    data: {
      username: walledUser,
      display_name: 'Amélia Marques',
      email: 'amelia.marques@example.test',
      password: seededPassword,
      send_welcome_email: true,
    },
  });
  expect(created.ok(), `seed forced-change user: HTTP ${created.status()}`).toBeTruthy();

  // Sign the operator out, then sign in as the seeded account. The sign-in returns a real token
  // together with `required_action = change_password`, so AuthGate intercepts before the chrome.
  await signOutToSignInSurface(page);
  await submitSignIn(page, walledUser, seededPassword);

  // The change-password wall is shown, and it blocks the app — the tab bar is NOT rendered.
  await expect(page.getByRole('heading', { name: 'Defina a sua palavra-passe' })).toBeVisible();
  await expect(page.getByTestId('tab-bar')).toHaveCount(0);

  // Complete the change. The server clears `force_password_change` on the self set-secret, the wall
  // re-reads the session, and the app appears — no reload, no sign-out.
  const newPassword = 'Nov0!Chave2026';
  await page.getByLabel('Palavra-passe atual', { exact: true }).fill(seededPassword);
  await page.getByLabel('Nova palavra-passe', { exact: true }).fill(newPassword);
  await page.getByLabel('Confirmar a nova palavra-passe', { exact: true }).fill(newPassword);
  await page.getByRole('button', { name: 'Guardar a palavra-passe' }).click();

  await expect(page.getByTestId('tab-bar')).toBeVisible();
});
