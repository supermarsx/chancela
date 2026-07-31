/**
 * The self-service account area.
 *
 * ## What these tests are actually for
 *
 * The area exists because an ordinary user — one holding no `user.read` and no `user.manage` —
 * had **no route to their own settings**. So the load-bearing assertions here are about the
 * REQUESTS the surface makes and the permissions it needs, not about what it looks like: a screen
 * that renders beautifully and then calls `GET /v1/users` has not fixed anything.
 *
 * Every test therefore runs inside a `permissionsValue` context that denies every administrative
 * verb, and several assert that no administrative endpoint was touched at all. Nothing matches on
 * translated prose — controls are found by role, by `data-testid` or by a reused catalog value read
 * from the pt-PT source, so a translator improving a sentence cannot turn a gate red.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { Route, Routes, matchRoutes } from 'react-router-dom';
import { router } from '../../app/router';
import { CurrentUserPicker } from '../session/CurrentUserPicker';
import { clearSessionToken, setSessionToken } from '../../api/session';
import { renderWithProviders } from '../../test/utils';
import { StaticPermissionsProvider, permissionsValue } from '../session/permissions';
import { AccountPage } from './AccountPage';
import { ALL_NOTICE_KEYS } from './AccountPreferencesSection';
import { ACCOUNT_PATH, ACCOUNT_SECURITY_PATH, accountSectionPath } from './paths';
import { ptPT } from '../../i18n/locales/pt-PT';
import { DEFAULT_SETTINGS } from '../../api/types';
import type { NoticeKey, UserPreferences, UserView } from '../../api/types';

const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
};

interface Recorded {
  url: string;
  method: string;
  body: Record<string, unknown> | null;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * A server that answers only what a signed-in user with NO administrative permission may reach,
 * and `403`s everything else.
 *
 * The 403 arm is the point: it is what makes "this surface needs no administrative permission" a
 * real assertion rather than a claim. A regression that reintroduces `GET /v1/users` shows up as a
 * refusal in the rendered screen and in `calls`, instead of silently passing against a stub that
 * would have answered anything.
 */
function accountServer(
  options: {
    user?: UserView;
    preferences?: UserPreferences;
    onPatch?: (body: unknown) => void;
  } = {},
): { fn: typeof fetch; calls: Recorded[] } {
  const user = options.user ?? AMELIA;
  const preferences = options.preferences ?? { table_columns: {} };
  const calls: Recorded[] = [];
  let current = user;

  const fn = ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    const method = init?.method ?? 'GET';
    const body = init?.body ? (JSON.parse(init.body as string) as Record<string, unknown>) : null;
    calls.push({ url, method, body });

    if (url.includes('/v1/me/profile')) {
      options.onPatch?.(body);
      current = { ...current, ...(body as Partial<UserView>) };
      return Promise.resolve(json(current));
    }
    if (url.includes('/v1/me/suspend')) {
      current = { ...current, active: false };
      return Promise.resolve(json({ user: current, sessions_revoked: 2 }));
    }
    if (url.includes('/v1/me/preferences')) return Promise.resolve(json(preferences));
    if (url.includes('/v1/sessions')) return Promise.resolve(json({ sessions: [] }));
    // Self-service too: the list is self-or-`user.manage`, and everything that changes a
    // credential is self-only in the handler.
    if (url.includes('/passkeys')) {
      return Promise.resolve(json({ passkeys: [], rp_id: 'localhost' }));
    }
    if (url.includes('/two-factor')) {
      return Promise.resolve(
        json({ enrolled: false, confirmed: false, required: false, backup_codes_remaining: null }),
      );
    }
    if (url.includes('/v1/session')) {
      return Promise.resolve(json({ user: current, permissions: [] }));
    }
    // The real settings shape: the notice-dismissal capability reads `ui` off it, and a partial
    // stub crashes the row rather than failing an assertion.
    if (url.includes('/v1/settings')) return Promise.resolve(json(DEFAULT_SETTINGS));
    // Anything else is an administrative endpoint this surface must never call.
    return Promise.resolve(json({ error: 'sem permissão para esta operação neste âmbito' }, 403));
  }) as typeof fetch;

  return { fn, calls };
}

/** The area at a real address, under a context that grants NOTHING. */
function renderAccount(section?: 'security' | 'preferences') {
  return renderWithProviders(
    <StaticPermissionsProvider value={permissionsValue(() => false)}>
      <Routes>
        <Route path="/account/:sec?" element={<AccountPage />} />
      </Routes>
    </StaticPermissionsProvider>,
    [section ? accountSectionPath(section) : ACCOUNT_PATH],
  );
}

/** Let anything a click started reach the transport. */
async function settle(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

/**
 * The user endpoints that genuinely require an administrative verb — the roster reads
 * (`user.read`) and the administrative profile write (`user.manage`).
 *
 * Precise on purpose. The SELF-SERVICE credential routes also live under `/v1/users/{id}/…`
 * (`/secret`, `/recovery`, `/attestation-key`, `/two-factor/*`, `/passkeys*`) and are gated
 * `Session` + self inside their handlers, so matching the whole `/v1/users` prefix would flag
 * exactly the calls this surface is *supposed* to make. What must never appear is a call to the
 * collection or to a bare `/v1/users/{id}` — the two that 403 an ordinary user.
 */
function administrativeCalls(calls: Recorded[]): Recorded[] {
  return calls.filter((c) => /\/v1\/users(?:\/page)?(?:\/[^/?]+)?(?:\?|$)/u.test(c.url));
}

afterEach(() => {
  cleanup();
  clearSessionToken();
  vi.restoreAllMocks();
});

describe('the account area addresses', () => {
  it('names one path per section, so no second spelling can drift', () => {
    expect(ACCOUNT_PATH).toBe('/account');
    expect(accountSectionPath('security')).toBe(ACCOUNT_SECURITY_PATH);
    // English slugs: an address is an identifier, never copy.
    expect(ACCOUNT_SECURITY_PATH).toBe('/account/security');
    expect(accountSectionPath('preferences')).toBe('/account/preferences');
  });
});

describe('AccountPage — Perfil', () => {
  it('renders and edits the profile with no administrative permission and no admin request', async () => {
    const patched: unknown[] = [];
    const { fn, calls } = accountServer({ onPatch: (b) => patched.push(b) });
    vi.stubGlobal('fetch', fn);

    renderAccount();

    // The identity form is bound to the SESSION's user — no `GET /v1/users/{id}` anywhere.
    const display = (await screen.findByLabelText(
      ptPT['users.edit.displayNameLabel'],
    )) as HTMLInputElement;
    expect(display.value).toBe('Amélia Marques');
    const username = screen.getByLabelText(ptPT['users.table.username']) as HTMLInputElement;
    expect(username.value).toBe('amelia.marques');
    expect(username.readOnly).toBe(true);

    fireEvent.change(display, { target: { value: 'Amélia M. Marques' } });
    fireEvent.click(screen.getByRole('button', { name: ptPT['account.identity.save'] }));

    await waitFor(() => expect(patched.length).toBe(1));
    // Only what changed, through the SELF endpoint.
    expect(patched[0]).toEqual({ display_name: 'Amélia M. Marques' });
    expect(calls.some((c) => c.method === 'PATCH' && c.url.includes('/v1/me/profile'))).toBe(true);
    expect(administrativeCalls(calls)).toEqual([]);
  });

  it('sends no request at all when nothing changed', async () => {
    const { fn, calls } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount();

    const save = (await screen.findByRole('button', {
      name: ptPT['account.identity.save'],
    })) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(save);
    await settle();
    expect(calls.filter((c) => c.method === 'PATCH')).toEqual([]);
  });

  it('clears the e-mail with an explicit null rather than an empty string', async () => {
    // `''` and "no address" are different facts, and the server distinguishes them
    // (`double_option`). Sending `''` would store an empty address instead of removing one.
    const patched: unknown[] = [];
    const { fn } = accountServer({
      user: { ...AMELIA, email: 'amelia.marques@example.test' },
      onPatch: (b) => patched.push(b),
    });
    vi.stubGlobal('fetch', fn);
    renderAccount();

    const email = (await screen.findByLabelText(ptPT['registry.email.label'])) as HTMLInputElement;
    expect(email.value).toBe('amelia.marques@example.test');
    fireEvent.change(email, { target: { value: '  ' } });
    fireEvent.click(screen.getByRole('button', { name: ptPT['account.identity.save'] }));

    await waitFor(() => expect(patched.length).toBe(1));
    expect(patched[0]).toEqual({ email: null });
  });

  it('says the data export is unavailable rather than offering a control that would 403', async () => {
    const { fn, calls } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount();

    expect(await screen.findByText(ptPT['account.export.unavailable'])).toBeTruthy();
    expect(screen.queryByRole('button', { name: ptPT['account.export.download'] })).toBeNull();
    await settle();
    expect(calls.some((c) => c.url.includes('/privacy/'))).toBe(false);
  });

  it('offers the export to a holder of privacy.manage, because for them it really works', async () => {
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue((p) => p === 'privacy.manage')}>
        <Routes>
          <Route path="/account/:sec?" element={<AccountPage />} />
        </Routes>
      </StaticPermissionsProvider>,
      [ACCOUNT_PATH],
    );

    expect(
      await screen.findByRole('button', { name: ptPT['account.export.download'] }),
    ).toBeTruthy();
    expect(screen.queryByText(ptPT['account.export.unavailable'])).toBeNull();
  });
});

describe('AccountPage — Segurança', () => {
  it('mounts the shared credential blocks without any administrative request', async () => {
    const { fn, calls } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount('security');

    // The shared `UserAccessManager` (password), the shared TOTP and passkey blocks, and the
    // session list — all four are the administrative screen's own modules, not copies of them.
    expect(await screen.findByText(ptPT['users.totp.title'])).toBeTruthy();
    expect(screen.getByText(ptPT['users.passkeys.title'])).toBeTruthy();
    expect(screen.getByText(ptPT['users.sessions.title'])).toBeTruthy();
    // Self, not cross-user: the cross-user proof banner belongs to the administrative surface.
    expect(screen.queryByText(ptPT['users.access.crossUserNote'])).toBeNull();
    // Self, so the enrol call-to-action rather than the admin-only "require 2FA" toggle.
    expect(screen.getByRole('button', { name: ptPT['users.totp.enrol'] })).toBeTruthy();
    expect(screen.queryByRole('button', { name: ptPT['users.totp.required.add'] })).toBeNull();

    await settle();
    expect(administrativeCalls(calls)).toEqual([]);
  });

  it('does not point a user who cannot open it at the administrative screen', async () => {
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount('security');

    await screen.findByText(ptPT['users.totp.title']);
    expect(screen.queryByText(ptPT['account.security.adminView'])).toBeNull();
  });

  it('points a user.manage holder at the administrative view of the same account', async () => {
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue((p) => p === 'user.manage')}>
        <Routes>
          <Route path="/account/:sec?" element={<AccountPage />} />
        </Routes>
      </StaticPermissionsProvider>,
      [ACCOUNT_SECURITY_PATH],
    );

    const link = (await screen.findByText(ptPT['account.security.adminView'])) as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/users/u1/access');
  });
});

describe('AccountPage — self-suspension', () => {
  it('states the three consequences before the control, not inside the dialog', async () => {
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount('security');

    await screen.findByTestId('account-suspend');
    // A confirmation dialog re-states a decision; it is the wrong place to introduce one.
    expect(screen.getByText(ptPT['account.suspend.effect.sessions'])).toBeTruthy();
    expect(screen.getByText(ptPT['account.suspend.effect.signin'])).toBeTruthy();
    expect(screen.getByText(ptPT['account.suspend.effect.lift'])).toBeTruthy();
  });

  it('cannot suspend on the session alone — the step-up proof is carried on the request', async () => {
    const { fn, calls } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount('security');

    fireEvent.click(await screen.findByTestId('account-suspend'));
    const dialog = await screen.findByRole('dialog');

    // Nothing has been sent by opening the dialog.
    expect(calls.some((c) => c.url.includes('/v1/me/suspend'))).toBe(false);

    // The confirm is inert until the step-up proof is supplied — this is the gate, and it is the
    // shared `ConfirmActionModal`'s, so it cannot drift from the other step-up surfaces.
    const submit = dialog.querySelector<HTMLButtonElement>('button[type=submit]');
    expect(submit).toBeTruthy();
    expect(submit!.disabled).toBe(true);

    const proof = dialog.querySelector<HTMLInputElement>('input[type=password]');
    expect(proof).toBeTruthy();
    fireEvent.change(proof!, { target: { value: 'Teste-Forte7!X' } });
    await waitFor(() => expect(submit!.disabled).toBe(false));

    fireEvent.click(submit!);
    await waitFor(() => {
      const sent = calls.find((c) => c.url.includes('/v1/me/suspend'));
      expect(sent, 'the suspension was sent').toBeTruthy();
      // The proof rides the request; the endpoint takes no id, because the subject is the caller.
      expect(sent!.method).toBe('POST');
      expect(sent!.body).toEqual({ reauth: { password: 'Teste-Forte7!X' } });
    });
  });

  it('offers no way to lift a suspension, because there is no endpoint for one', async () => {
    // The whole point of a self-suspension is that it is one-way: whoever is holding the stolen
    // session would otherwise hold exactly the access needed to undo it. A control here would be
    // that hole, so its absence is asserted rather than assumed.
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount('security');

    await screen.findByTestId('account-suspend');
    const restore = screen.queryAllByRole('button').map((b) => b.getAttribute('data-testid'));
    expect(restore).not.toContain('account-unsuspend');
    // And no request the client could make would reactivate the account.
    expect(Object.keys(await import('../../api/client')).includes('unsuspendMyAccount')).toBe(
      false,
    );
  });
});

describe('AccountPage — Preferências', () => {
  it('enumerates every notice key the preferences API accepts', () => {
    // Exhaustiveness is enforced by the TYPE (`Record<NoticeKey, true>` is total, so a new union
    // member does not compile until it is listed). This pins the set as it stands, so a key
    // REMOVED from the index — which the type cannot catch, since a smaller record still satisfies
    // a smaller union — fails here instead of quietly dropping a notice out of the one place a
    // hidden one can be found.
    const declared: NoticeKey[] = [
      'external_signing',
      'platform_log_scope',
      'leg_citations',
      'termo_signing_legend',
      'book_open_guidance',
    ];
    expect([...ALL_NOTICE_KEYS].sort()).toEqual([...declared].sort());
  });

  it('says nothing is hidden when nothing is', async () => {
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    renderAccount('preferences');

    expect(await screen.findByText(ptPT['account.notices.empty'])).toBeTruthy();
  });

  it('lists a hidden restorable notice and restores it through the preferences document', async () => {
    const { fn, calls } = accountServer({
      preferences: {
        table_columns: {},
        notice_dismissals: { leg_citations: { mode: 'permanent' } },
      },
    });
    vi.stubGlobal('fetch', fn);
    renderAccount('preferences');

    // Found by the notice key, never by its (translated, inflected) restore sentence.
    const restore = await waitFor(() => {
      const el = document.querySelector<HTMLButtonElement>('button[data-notice="leg_citations"]');
      expect(el).toBeTruthy();
      return el!;
    });
    expect(screen.queryByText(ptPT['account.notices.empty'])).toBeNull();

    fireEvent.click(restore);
    await waitFor(() => {
      const put = calls.find((c) => c.method === 'PUT' && c.url.includes('/v1/me/preferences'));
      expect(put, 'the dismissal was cleared').toBeTruthy();
      const body = put!.body as unknown as UserPreferences;
      expect(body.notice_dismissals?.leg_citations).toBeUndefined();
    });
  });

  it('does not list a hidden notice that its copy never made restorable', async () => {
    // `external_signing` has deliberately never offered a way back, and there is no sentence that
    // names it — so listing it would mean inventing one, and offering an action that does not exist.
    const { fn } = accountServer({
      preferences: {
        table_columns: {},
        notice_dismissals: { external_signing: { mode: 'permanent' } },
      },
    });
    vi.stubGlobal('fetch', fn);
    renderAccount('preferences');

    expect(await screen.findByText(ptPT['account.notices.empty'])).toBeTruthy();
    expect(document.querySelector('button[data-notice="external_signing"]')).toBeNull();
    // …and the footnote says so, so the omission is stated rather than discovered.
    expect(screen.getByText(ptPT['account.notices.footnote'])).toBeTruthy();
  });
});

describe('the door into the account area', () => {
  it('registers /account and its sections on the real route table, one page deep', () => {
    // `navDepth: 1` is what keys the shell on `/account`, so switching tab is not a page change
    // and does not remount the screen — discarding the profile form's working copy.
    const root = matchRoutes(router.routes, ACCOUNT_PATH);
    const security = matchRoutes(router.routes, ACCOUNT_SECURITY_PATH);
    expect(root?.at(-1)?.route.path).toBe('account/:sec?');
    expect(security?.at(-1)?.route.path).toBe('account/:sec?');
    expect((security?.at(-1)?.route.handle as { navDepth?: number }).navDepth).toBe(1);
  });

  it('offers every signed-in user the account link, and the roster only to a user.manage holder', async () => {
    // The defect: the picker's only link went to the administrative roster, which is
    // `user.read`@Global — so an ordinary user followed the one link their own menu offered and
    // was refused. Both halves are asserted together because it is the contrast that is the fix.
    const { fn } = accountServer();
    vi.stubGlobal('fetch', fn);
    setSessionToken('tok-0');

    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue(() => false)}>
        <CurrentUserPicker />
      </StaticPermissionsProvider>,
    );
    fireEvent.click(await screen.findByTestId('session-trigger'));

    const account = (await screen.findByText(ptPT['account.picker.link'])) as HTMLAnchorElement;
    expect(account.getAttribute('href')).toBe(ACCOUNT_PATH);
    expect(screen.queryByText(ptPT['session.manage'])).toBeNull();

    cleanup();
    renderWithProviders(
      <StaticPermissionsProvider value={permissionsValue((p) => p === 'user.manage')}>
        <CurrentUserPicker />
      </StaticPermissionsProvider>,
    );
    fireEvent.click(await screen.findByTestId('session-trigger'));
    expect(await screen.findByText(ptPT['account.picker.link'])).toBeTruthy();
    const roster = screen.getByText(ptPT['session.manage']) as HTMLAnchorElement;
    expect(roster.getAttribute('href')).toBe('/settings/users');
  });
});
