/**
 * The passkey block on the Segurança tab (t10).
 *
 * Asserts roles, ids and stable codes — never translated prose. Where copy is unavoidable (a
 * badge whose only content is words), the assertion reads the catalog value by key, so the test
 * survives a rewording and fails only when the *meaning* moves.
 *
 * The three properties under test are the ones whose regression would be invisible: cross-user
 * controls (an authorization split the server enforces and the UI must not contradict), the
 * desktop-shell suppression (a control that could only throw), and the honest surfacing of the
 * server's account-lifecycle refusal (which must never be pre-empted by a disabled button).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';

const tauriMock = vi.hoisted(() => ({ isTauri: vi.fn(() => false) }));
vi.mock('../../desktop/tauri', () => tauriMock);

import { renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import { PasskeySection } from './PasskeySection';
import type { PasskeyListView, PasskeyView, UserView } from '../../api/types';

const USER: UserView = {
  id: 'b2c3d4e5-0000-4000-8000-00000000a001',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  active: true,
} as UserView;

function passkey(overrides: Partial<PasskeyView> = {}): PasskeyView {
  const base: PasskeyView = {
    credential_id: 'Y3JlZGVudGlhbA',
    name: 'Telemóvel',
    created_at: '2026-07-01T09:00:00Z',
    // Always present, nullable — never omitted. The e2e contract harness does strict key-set
    // equality per object, so a key that appears only on used credentials would make a list's
    // verdict depend on whether its first row happened to have been used.
    last_used_at: null,
    rp_id: 'example.pt',
    usable: true,
    backup: 'exists',
    attachment: 'platform',
    transports: ['internal'],
    prf_capable: true,
    unlocks_without_password: false,
    sign_count: 0,
  };
  // `Object.assign` rather than a second spread: spreading `Partial<PasskeyView>` over a *required*
  // field re-widens it to include `undefined`, which `PasskeyView` no longer admits now that
  // `last_used_at` is always present on the wire. A cast would hide the next such mismatch too.
  return Object.assign(base, overrides);
}

function mockList(list: Partial<PasskeyListView>): void {
  const body: PasskeyListView = {
    passkeys: [],
    rp_id: 'example.pt',
    enrolment_available: true,
    ...list,
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(
      async () =>
        new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
    ),
  );
}

/**
 * Make this jsdom look like a browser that implements WebAuthn.
 *
 * jsdom implements none of it, so without this every test would exercise the
 * "browser cannot do passkeys" arm — and the enrolment tests would pass by rendering nothing,
 * which is the worst kind of green.
 */
function enableWebAuthn(): void {
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { create: vi.fn(), get: vi.fn() },
  });
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, 'credentials');
  tauriMock.isTauri.mockReturnValue(false);
});

describe('PasskeySection', () => {
  it('offers no mutation control on another user’s account, but still lists the credentials', async () => {
    // The server's split, mirrored: the LIST is self-or-`user.manage`, every mutation is self-only
    // and refused in the handler. Rendering the buttons anyway would offer an administrator three
    // controls that can only 403 — and one of them would silently lock a colleague out if it
    // worked.
    mockList({ passkeys: [passkey()] });
    renderWithProviders(<PasskeySection user={USER} isSelf={false} />);

    await screen.findByText('Telemóvel');
    expect(screen.queryByRole('button', { name: ptPT['users.passkeys.rename'] })).toBeNull();
    expect(screen.queryByRole('button', { name: ptPT['users.passkeys.revoke'] })).toBeNull();
    expect(screen.queryByRole('button', { name: ptPT['users.passkeys.add'] })).toBeNull();
    // No orphan header over an absent column.
    expect(
      screen.queryByRole('columnheader', { name: ptPT['users.passkeys.col.action'] }),
    ).toBeNull();
    expect(screen.getByText(ptPT['users.passkeys.crossUser.note'])).toBeTruthy();
  });

  it('offers rename and revoke on one’s own account', async () => {
    enableWebAuthn();
    mockList({ passkeys: [passkey()] });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    await screen.findByText('Telemóvel');
    expect(screen.getByRole('button', { name: ptPT['users.passkeys.rename'] })).toBeTruthy();
    expect(screen.getByRole('button', { name: ptPT['users.passkeys.revoke'] })).toBeTruthy();
    expect(screen.getByRole('button', { name: ptPT['users.passkeys.add'] })).toBeTruthy();
  });

  it('hides the enrolment control in the desktop shell and says why once', async () => {
    // Passkeys cannot work in Tauri on any platform: the custom protocol admits only
    // `tauri.localhost` as an RP ID, and WebKitGTK implements no WebAuthn at all. A button here
    // could only throw, so there is none — and one sentence explains it rather than leaving a
    // silently missing feature.
    tauriMock.isTauri.mockReturnValue(true);
    mockList({ passkeys: [] });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    await screen.findByText(ptPT['users.passkeys.unavailable.desktop']);
    expect(screen.queryByRole('button', { name: ptPT['users.passkeys.add'] })).toBeNull();
  });

  it('explains an unconfigured instance instead of offering a control that would 422', async () => {
    // `enrolment_available: false` is an instance-configuration fact — no operator has made the
    // one-way RP ID choice — not something the user did wrong.
    enableWebAuthn();
    mockList({ passkeys: [], enrolment_available: false, rp_id: undefined });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    await screen.findByText(ptPT['users.passkeys.unconfigured.title']);
    expect(screen.queryByRole('button', { name: ptPT['users.passkeys.add'] })).toBeNull();
  });

  it('marks a credential from a previous domain and names both domains', async () => {
    // "My passkey is broken" and "the administrator moved this instance" send a person to two
    // different places, and only the second is true.
    enableWebAuthn();
    mockList({
      passkeys: [passkey({ usable: false, rp_id: 'antigo.example.pt' })],
      rp_id: 'example.pt',
    });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    await screen.findByText('Telemóvel');
    expect(screen.getByText(ptPT['users.passkeys.unusable.badge'])).toBeTruthy();
    const hint = screen.getByText(/antigo\.example\.pt/u);
    expect(hint.textContent).toContain('example.pt');
    // Still removable: it is still enrolled, and only its holder can take it off the account.
    expect(screen.getByRole('button', { name: ptPT['users.passkeys.revoke'] })).toBeTruthy();
  });

  it('marks the passwordless row and only it, keying on the wrap not the capability', async () => {
    // The per-row badge follows `unlocks_without_password` — the wrap that exists — never
    // `prf_capable`, the capability that might have. The first row below is capable AND wrapped
    // (badge); the second is capable but not wrapped, e.g. its wrap ceremony never completed (no
    // badge). Keying on `prf_capable` would promise a passwordless path the second row lacks.
    enableWebAuthn();
    mockList({
      passkeys: [
        passkey({
          credential_id: 'cHJm',
          name: 'Telemóvel',
          prf_capable: true,
          unlocks_without_password: true,
        }),
        passkey({
          credential_id: 'bm9wcmY',
          name: 'Chave de segurança',
          prf_capable: true,
          unlocks_without_password: false,
        }),
      ],
    });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    const wrapped = (await screen.findByText('Telemóvel')).closest('tr');
    const fallback = screen.getByText('Chave de segurança').closest('tr');
    const badge = ptPT['users.passkeys.passwordless.badge'];
    expect(wrapped?.textContent).toContain(badge);
    expect(fallback?.textContent).not.toContain(badge);
  });

  it('states once, for every credential, that the password still opens the audit key', async () => {
    // The standing fact, said on the card rather than per row. It must survive a reload, which is
    // why it is not the post-enrolment notice.
    enableWebAuthn();
    mockList({ passkeys: [passkey({ prf_capable: true })] });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    await screen.findByText('Telemóvel');
    expect(screen.getByText(ptPT['users.passkeys.passwordNote'])).toBeTruthy();
  });

  it('distinguishes a synced credential from a device-bound one', async () => {
    // The column an operator deciding what to revoke actually needs: "remove the one on the laptop
    // I dropped" has opposite answers depending on which it was.
    enableWebAuthn();
    mockList({
      passkeys: [
        passkey({ credential_id: 'c3luY2Vk', name: 'Telemóvel', backup: 'exists' }),
        passkey({ credential_id: 'Ym91bmQ', name: 'Chave de segurança', backup: 'not_eligible' }),
      ],
    });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    await screen.findByText('Telemóvel');
    expect(screen.getByText(ptPT['users.passkeys.backup.exists'])).toBeTruthy();
    expect(screen.getByText(ptPT['users.passkeys.backup.notEligible'])).toBeTruthy();
  });

  it('pushes a second credential while exactly one is enrolled', async () => {
    // One passkey is one lost phone away from a lockout.
    enableWebAuthn();
    mockList({ passkeys: [passkey()] });
    const { unmount } = renderWithProviders(<PasskeySection user={USER} isSelf />);
    await screen.findByText(ptPT['users.passkeys.addSecond']);
    unmount();
    cleanup();

    mockList({ passkeys: [passkey(), passkey({ credential_id: 'c2Vjb25k', name: 'Portátil' })] });
    renderWithProviders(<PasskeySection user={USER} isSelf />);
    await screen.findByText('Portátil');
    expect(screen.queryByText(ptPT['users.passkeys.addSecond'])).toBeNull();
  });

  it('never suggests the password can be removed', async () => {
    // The overclaim guard. The attestation key always retains its password wrap — the server
    // refuses to remove it while a key exists — so "passwordless" here means no password at
    // sign-in and nothing more.
    enableWebAuthn();
    mockList({ passkeys: [passkey()] });
    renderWithProviders(<PasskeySection user={USER} isSelf />);
    await waitFor(() => expect(screen.getByText(ptPT['users.passkeys.passwordNote'])).toBeTruthy());
  });

  it('opens the revoke dialog with the step-up field the server demands', async () => {
    // Revoking a credential is a credential operation and must not ride a session alone. The
    // account-lifecycle refusal is deliberately NOT pre-empted here: the button is live, and a
    // `409` from the handler is what explains the refusal.
    enableWebAuthn();
    mockList({ passkeys: [passkey()] });
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    const revoke = await screen.findByRole('button', { name: ptPT['users.passkeys.revoke'] });
    expect(revoke.hasAttribute('disabled')).toBe(false);
    revoke.click();

    const dialog = await screen.findByRole('dialog');
    expect(dialog.textContent).toContain('Telemóvel');
    // The step-up proof field, named by its label rather than by its markup.
    expect(screen.getByLabelText(ptPT['confirm.reauth.password'])).toBeTruthy();
  });
});

/**
 * The enrolment and rename flows, driven end to end against a stubbed authenticator.
 *
 * These cover the two moments the operator experiences as "did that work?": the ceremony that
 * produces a credential, and the sentence that has to follow a credential whose authenticator
 * cannot hold the PRF secret.
 */
describe('PasskeySection — enrolment and rename', () => {
  /** A `navigator.credentials` whose `create` resolves a registration credential. */
  function stubAuthenticator(): void {
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: {
        create: vi.fn(async () => ({
          id: 'bmV3',
          rawId: new Uint8Array([7, 7]).buffer,
          type: 'public-key',
          authenticatorAttachment: 'platform',
          getClientExtensionResults: () => ({ prf: { enabled: true } }),
          response: {
            clientDataJSON: new Uint8Array([1]).buffer,
            attestationObject: new Uint8Array([2]).buffer,
            getTransports: () => ['internal'],
          },
        })),
        get: vi.fn(),
      },
    });
  }

  /**
   * An authenticator whose `create` enrols and whose `get` answers the PRF-wrap ceremony with a
   * user-verified assertion carrying a PRF output — so the enrol → wrap flow completes end to end.
   */
  function stubPrfCapableAuthenticator(): void {
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    const authData = new Uint8Array(37);
    authData[32] = 0x05; // UP | UV
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: {
        create: vi.fn(async () => ({
          id: 'bmV3',
          rawId: new Uint8Array([7, 7]).buffer,
          type: 'public-key',
          authenticatorAttachment: 'platform',
          getClientExtensionResults: () => ({ prf: { enabled: true } }),
          response: {
            clientDataJSON: new Uint8Array([1]).buffer,
            attestationObject: new Uint8Array([2]).buffer,
            getTransports: () => ['internal'],
          },
        })),
        get: vi.fn(async () => ({
          id: 'bmV3',
          rawId: new Uint8Array([7, 7]).buffer,
          type: 'public-key',
          authenticatorAttachment: 'platform',
          getClientExtensionResults: () => ({
            prf: { results: { first: new Uint8Array(32).fill(9).buffer } },
          }),
          response: {
            clientDataJSON: new Uint8Array([1]).buffer,
            authenticatorData: authData.buffer,
            signature: new Uint8Array([4]).buffer,
            userHandle: new Uint8Array([5]).buffer,
          },
        })),
      },
    });
  }

  /** Like {@link stubServer}, plus the two PRF-wrap endpoints, so the wrap actually seals. */
  function stubServerWithPrfWrap(enrolled: PasskeyView, wrapped: PasskeyView) {
    const json = (body: unknown) =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (url.endsWith('/prf/options')) {
        return Promise.resolve(json({ public_key: { challenge: 'AAAA' }, purpose: 'prf_wrap' }));
      }
      if (method === 'POST' && url.endsWith('/prf')) return Promise.resolve(json(wrapped));
      if (url.endsWith('/passkeys/options')) {
        return Promise.resolve(
          json({
            public_key: { challenge: 'AAAA', user: { id: 'BBBB' } },
            purpose: 'registration',
          }),
        );
      }
      if (method === 'POST' && url.endsWith('/passkeys')) return Promise.resolve(json(enrolled));
      return Promise.resolve(
        json({ passkeys: [wrapped], rp_id: 'example.pt', enrolment_available: true }),
      );
    });
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  }

  /** An authenticator whose `create` rejects with a named DOM exception. */
  function stubFailingAuthenticator(name: string): void {
    const error = new Error(name);
    error.name = name;
    vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: {
        create: vi.fn(() => Promise.reject(error)),
        get: vi.fn(),
      },
    });
  }

  /**
   * Route by method and path, so the ceremony's three requests can answer differently.
   *
   * `enrolled` is what `POST …/passkeys` returns — the created view, which is where the signing
   * note gets the credential's stored label from (the server trims and bounds it, so echoing back
   * what was typed would show a name the account does not actually hold).
   */
  function stubServer(enrolled: PasskeyView, initial: PasskeyView[] = []) {
    const json = (body: unknown) =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? 'GET';
      if (url.endsWith('/passkeys/options')) {
        return Promise.resolve(
          json({
            public_key: { challenge: 'AAAA', user: { id: 'BBBB' } },
            purpose: 'registration',
          }),
        );
      }
      if (method === 'POST' && url.endsWith('/passkeys')) return Promise.resolve(json(enrolled));
      if (method === 'PATCH') return Promise.resolve(json({ ...enrolled, name: 'Portátil' }));
      return Promise.resolve(
        json({ passkeys: initial, rp_id: 'example.pt', enrolment_available: true }),
      );
    });
    vi.stubGlobal('fetch', fetchMock);
    return fetchMock;
  }

  /** The first recorded request matching a method and (optionally) a path suffix. */
  function requestOf(
    fetchMock: ReturnType<typeof stubServer>,
    method: string,
    endsWith?: string,
  ): { url: string; body: Record<string, unknown> } | undefined {
    for (const [input, init] of fetchMock.mock.calls) {
      const url = String(input);
      if ((init?.method ?? 'GET') !== method) continue;
      if (endsWith && !url.endsWith(endsWith)) continue;
      return { url, body: JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown> };
    }
    return undefined;
  }

  it('runs the ceremony, trims the label, and posts what the browser produced', async () => {
    stubAuthenticator();
    const fetchMock = stubServer(passkey({ credential_id: 'bmV3', name: 'Portátil' }));
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    const field = await screen.findByLabelText(ptPT['users.passkeys.name.label']);
    fireEvent.change(field, { target: { value: '  Portátil do escritório  ' } });
    fireEvent.click(screen.getByRole('button', { name: ptPT['users.passkeys.add'] }));

    await waitFor(() => expect(requestOf(fetchMock, 'POST', '/passkeys')).toBeTruthy());
    const post = requestOf(fetchMock, 'POST', '/passkeys');
    expect(post?.body.name).toBe('Portátil do escritório');
    // The credential goes verbatim, in the shape the server's relaxed deserialiser parses:
    // `transports` inside `response`, extension results at the top level.
    const credential = post?.body.credential as Record<string, Record<string, unknown>>;
    expect(credential.response.transports).toEqual(['internal']);
    expect(credential.clientExtensionResults).toEqual({ prf: { enabled: true } });
  });

  it('says at enrolment that the password is still asked when no wrap is sealed', async () => {
    // The support incident this prevents is meeting it mid-attestation, at signing time. Here the
    // PRF-wrap ceremony does not complete (the stub authenticator's `get` returns nothing), so the
    // credential falls back and the note is the honest one — the password is still asked.
    stubAuthenticator();
    stubServer(passkey({ credential_id: 'bmV3', name: 'Chave de segurança', prf_capable: false }));
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.add'] }));
    await screen.findByText(ptPT['users.passkeys.signingNote.title']);
    expect(screen.getByText(/Chave de segurança/u)).toBeTruthy();
  });

  it('says the same fallback thing for a PRF-capable credential whose wrap did not complete', async () => {
    // Capability is not a wrap. A credential whose authenticator *could* provision PRF but whose
    // wrap ceremony did not finish falls back exactly like a non-PRF one — the copy follows the
    // wrap that exists, never the capability that might have. Keying it on `prf_capable` would
    // promise a passwordless signing path this credential does not have.
    stubAuthenticator();
    stubServer(passkey({ credential_id: 'bmV3', name: 'Telemóvel', prf_capable: true }));
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.add'] }));
    await screen.findByText(ptPT['users.passkeys.signingNote.title']);
    expect(screen.getByText(/Telemóvel/u)).toBeTruthy();
  });

  it('says «sem palavra-passe» when the PRF wrap completes at enrolment', async () => {
    // The passwordless path end to end: create() enrols, a second get() yields a PRF output, the
    // wrap seals, and the returned view reports `unlocks_without_password`. Only then is the
    // passwordless note true, and only then is it shown.
    stubPrfCapableAuthenticator();
    stubServerWithPrfWrap(
      passkey({ credential_id: 'bmV3', name: 'Telemóvel', prf_capable: true }),
      passkey({
        credential_id: 'bmV3',
        name: 'Telemóvel',
        prf_capable: true,
        unlocks_without_password: true,
      }),
    );
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.add'] }));
    await screen.findByText(ptPT['users.passkeys.passwordlessNote.title']);
    expect(screen.queryByText(ptPT['users.passkeys.signingNote.title'])).toBeNull();
  });

  it('names the credential the server stored, not the text that was typed', async () => {
    // The server trims and bounds the label, so echoing the typed value back would name a
    // credential the account does not hold.
    stubAuthenticator();
    const fetchMock = stubServer(passkey({ credential_id: 'bmV3', name: 'Portátil' }));
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.change(await screen.findByLabelText(ptPT['users.passkeys.name.label']), {
      target: { value: '   Portátil   ' },
    });
    fireEvent.click(screen.getByRole('button', { name: ptPT['users.passkeys.add'] }));
    await waitFor(() => expect(requestOf(fetchMock, 'POST', '/passkeys')).toBeTruthy());
    await screen.findByText(ptPT['users.passkeys.signingNote.title']);
    // The stored label, from the response — not `   Portátil   ` as typed.
    const notice = screen.getByRole('note');
    expect(notice.textContent).toContain('«Portátil»');
    expect(notice.textContent).not.toContain('   Portátil   ');
  });

  it('translates a browser refusal the server never saw', async () => {
    // A `SecurityError` is a mis-set `auth.passkeys.rp_id`: the request is never made, so without
    // this translation the only symptom of the feature's most expensive misconfiguration is a
    // button that appears to do nothing.
    stubFailingAuthenticator('SecurityError');
    stubServer(passkey());
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.add'] }));
    await screen.findByText(ptPT['users.passkeys.error.rpIdMismatch']);
  });

  it('reports an authenticator that already holds a credential for this account', async () => {
    // `excludeCredentials` did its job. "Use another device" is actionable; "failed" is not.
    stubFailingAuthenticator('InvalidStateError');
    stubServer(passkey(), [passkey()]);
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.add'] }));
    await screen.findByText(ptPT['users.passkeys.error.alreadyEnrolled']);
  });

  it('renames in place, addressing the credential by id in the path', async () => {
    stubAuthenticator();
    const fetchMock = stubServer(passkey(), [passkey()]);
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.rename'] }));
    // The in-row field is named by the COLUMN, not by the enrolment field: two identically-named
    // inputs on one screen would be indistinguishable to anyone navigating by accessible name.
    fireEvent.change(screen.getByLabelText(ptPT['users.passkeys.col.name']), {
      target: { value: '  Portátil  ' },
    });
    fireEvent.click(screen.getByRole('button', { name: ptPT['common.save'] }));

    await waitFor(() => expect(requestOf(fetchMock, 'PATCH')).toBeTruthy());
    const patch = requestOf(fetchMock, 'PATCH');
    expect(patch?.body).toEqual({ name: 'Portátil' });
    // In the path, so a rename can never address a credential other than the row it came from.
    expect(patch?.url).toContain('Y3JlZGVudGlhbA');
  });

  it('will not submit a rename that is blank or unchanged', async () => {
    // The server refuses a blank with `422 passkey_name_empty`; the form does not make the
    // operator discover that, and an unchanged label is not an edit at all.
    stubAuthenticator();
    stubServer(passkey(), [passkey()]);
    renderWithProviders(<PasskeySection user={USER} isSelf />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['users.passkeys.rename'] }));
    const save = () =>
      screen.getByRole('button', { name: ptPT['common.save'] }) as HTMLButtonElement;
    expect(save().disabled).toBe(true);

    fireEvent.change(screen.getByLabelText(ptPT['users.passkeys.col.name']), {
      target: { value: '   ' },
    });
    expect(save().disabled).toBe(true);

    fireEvent.change(screen.getByLabelText(ptPT['users.passkeys.col.name']), {
      target: { value: 'Portátil' },
    });
    expect(save().disabled).toBe(false);
  });
});
