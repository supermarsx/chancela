/**
 * Passkey sign-in (t10).
 *
 * The property this file exists for is **conditional mediation**, because it is the one thing that
 * can silently not happen: a browser that does not support it, an instance with no RP ID, or an
 * options request that fails all leave a working modal button and no visible difference. So the
 * tests distinguish "the conditional request was armed" from "the button worked", rather than
 * accepting either as passing.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';

const tauriMock = vi.hoisted(() => ({ isTauri: vi.fn(() => false) }));
vi.mock('../../desktop/tauri', () => tauriMock);

import { renderWithProviders } from '../../test/utils';
import { ptPT } from '../../i18n/locales/pt-PT';
import { PasskeySignIn } from './PasskeySignIn';
import { toBase64Url } from './webauthn';

/** A user-verified assertion — flags byte 0x05 is UP | UV. `prfFirst` models a PRF output. */
function assertion(prfFirst?: ArrayBuffer) {
  const authenticatorData = new Uint8Array(37);
  authenticatorData[32] = 0x05;
  return {
    id: 'Y3JlZA',
    rawId: new Uint8Array([1, 2]).buffer,
    type: 'public-key',
    getClientExtensionResults: () => (prfFirst ? { prf: { results: { first: prfFirst } } } : {}),
    response: {
      clientDataJSON: new Uint8Array([3]).buffer,
      authenticatorData: authenticatorData.buffer,
      signature: new Uint8Array([4]).buffer,
      userHandle: new Uint8Array([5]).buffer,
    },
  };
}

interface Harness {
  get: ReturnType<typeof vi.fn>;
  fetchMock: ReturnType<typeof vi.fn>;
}

/**
 * Stub the browser and the server.
 *
 * `conditional` decides whether `isConditionalMediationAvailable` resolves true; `optionsStatus`
 * lets a test make `POST /v1/session/passkey/options` fail the way an unconfigured instance does.
 */
function harness({
  conditional = true,
  optionsStatus = 200,
  pendingGet = false,
  prfFirst,
}: {
  conditional?: boolean;
  optionsStatus?: number;
  pendingGet?: boolean;
  prfFirst?: ArrayBuffer;
} = {}): Harness {
  const credential = assertion(prfFirst);
  // A conditional request stays pending until the operator picks a credential; `pendingGet` models
  // that, so a test can prove the modal path aborts it rather than racing it.
  const get = vi.fn(() => (pendingGet ? new Promise(() => {}) : Promise.resolve(credential)));

  const PublicKeyCredential = function PublicKeyCredential() {} as unknown as Record<
    string,
    unknown
  >;
  PublicKeyCredential.isConditionalMediationAvailable = () => Promise.resolve(conditional);
  vi.stubGlobal('PublicKeyCredential', PublicKeyCredential);
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { create: vi.fn(), get },
  });

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
  const fetchMock = vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith('/session/passkey/options')) {
      return Promise.resolve(
        optionsStatus === 200
          ? json({
              public_key: { challenge: toBase64Url(new Uint8Array([9])), rpId: 'example.pt' },
              purpose: 'sign_in',
            })
          : json({ error: 'unset', code: 'passkeys_rp_id_unset' }, optionsStatus),
      );
    }
    if (url.endsWith('/session/passkey')) {
      return Promise.resolve(
        json({
          token: 'tok',
          user: { id: 'u1', username: 'amelia.marques', display_name: 'Amélia Marques' },
        }),
      );
    }
    return Promise.resolve(
      json({ user: { id: 'u1', username: 'amelia.marques', display_name: 'Amélia Marques' } }),
    );
  });
  vi.stubGlobal('fetch', fetchMock);
  return { get, fetchMock };
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, 'credentials');
  tauriMock.isTauri.mockReturnValue(false);
});

describe('PasskeySignIn', () => {
  it('renders nothing in the desktop shell', async () => {
    // Not a disabled button, not an explanation on the sign-in screen — nothing. The desktop
    // shell's own security screen carries the one honest sentence; repeating it on the way in
    // would advertise a feature that can never work there.
    tauriMock.isTauri.mockReturnValue(true);
    harness();
    const { container } = renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);
    expect(container.textContent).toBe('');
  });

  it('renders nothing when the browser has no WebAuthn at all', () => {
    vi.stubGlobal('PublicKeyCredential', undefined);
    const { container } = renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);
    expect(container.textContent).toBe('');
  });

  it('arms a conditional request on mount and says the field can be used', async () => {
    // The designed flow: no modal, the passkey appears in the username field's autofill dropdown.
    // Asserted on the `mediation` argument rather than on the button, because a modal-only flow
    // would render exactly the same button.
    const { get } = harness({ conditional: true, pendingGet: true });
    renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);

    await waitFor(() => expect(get).toHaveBeenCalled());
    expect((get.mock.calls[0][0] as { mediation?: string }).mediation).toBe('conditional');
    await screen.findByText(ptPT['signin.passkey.hint.autofill']);
  });

  it('keeps the modal button when conditional mediation is unavailable, and says so', async () => {
    // A browser without autofill mediation still runs the modal ceremony perfectly well. Hiding
    // the button there would remove passkey sign-in from every such browser.
    const { get } = harness({ conditional: false });
    renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);

    const button = await screen.findByRole('button', { name: ptPT['signin.passkey.action'] });
    expect(button).toBeTruthy();
    await screen.findByText(ptPT['signin.passkey.hint']);
    expect(get).not.toHaveBeenCalled();
  });

  it('stays silent about an unconfigured instance rather than reporting its configuration', async () => {
    // A signed-out visitor learning how this deployment is configured is the same leak the typed
    // identifier and the dummy verifier exist to prevent, reached by a longer route.
    harness({ conditional: true, optionsStatus: 422 });
    renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);

    await screen.findByRole('button', { name: ptPT['signin.passkey.action'] });
    await waitFor(() => expect(screen.queryByText(/rp_id|passkeys_/u)).toBeNull());
    expect(screen.queryByText(ptPT['signin.passkey.hint.autofill'])).toBeNull();
  });

  it('completes a sign-in from the modal button and reports the user', async () => {
    const onSignedIn = vi.fn();
    const { fetchMock } = harness({ conditional: false });
    renderWithProviders(<PasskeySignIn onSignedIn={onSignedIn} />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['signin.passkey.action'] }));
    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());
    expect(onSignedIn.mock.calls[0][0].username).toBe('amelia.marques');

    // The finish request carries the credential and NO identifier: the browser resolved who this
    // is, and asking the server would rebuild the enumeration oracle discoverable credentials were
    // chosen to avoid.
    const post = fetchMock.mock.calls.find(([url]) => String(url).endsWith('/session/passkey'));
    const body = JSON.parse(String((post?.[1] as RequestInit | undefined)?.body ?? '{}'));
    expect(Object.keys(body)).toEqual(['credential']);
  });

  it('posts the PRF-derived secret when the credential produced a PRF output', async () => {
    // The passwordless path: the browser adds `prf`, the authenticator returns an output, and the
    // client derives the KEK and posts it so the server can unlock the attestation key with no
    // password. A credential with no output posts no `prf_secret` — the fallback the test above pins.
    const onSignedIn = vi.fn();
    const { fetchMock } = harness({
      conditional: false,
      prfFirst: new Uint8Array(32).fill(7).buffer,
    });
    renderWithProviders(<PasskeySignIn onSignedIn={onSignedIn} />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['signin.passkey.action'] }));
    await waitFor(() => expect(onSignedIn).toHaveBeenCalled());

    const post = fetchMock.mock.calls.find(([url]) => String(url).endsWith('/session/passkey'));
    const body = JSON.parse(String((post?.[1] as RequestInit | undefined)?.body ?? '{}'));
    expect(Object.keys(body).sort()).toEqual(['credential', 'prf_secret']);
    expect(typeof body.prf_secret).toBe('string');
    expect(body.prf_secret.length).toBeGreaterThan(0);
    // The raw PRF output never leaves the browser — only the derived KEK does.
    expect(JSON.stringify(body.credential)).not.toContain('results');
  });

  it('aborts the pending conditional request before opening the modal', async () => {
    // Two concurrent `navigator.credentials.get` calls are an `InvalidStateError`, which would
    // surface as "failed" for a flow that is merely already busy.
    const { get } = harness({ conditional: true, pendingGet: true });
    renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);

    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    const armed = (get.mock.calls[0][0] as { signal?: AbortSignal }).signal;
    expect(armed?.aborted).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: ptPT['signin.passkey.action'] }));
    await waitFor(() => expect(armed?.aborted).toBe(true));
  });

  it('names the RP ID misconfiguration the server never saw', async () => {
    harness({ conditional: false });
    const error = new Error('bad rp id');
    error.name = 'SecurityError';
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { create: vi.fn(), get: vi.fn(() => Promise.reject(error)) },
    });
    renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);

    fireEvent.click(await screen.findByRole('button', { name: ptPT['signin.passkey.action'] }));
    await screen.findByText(ptPT['signin.passkey.error.rpIdMismatch']);
  });

  it('says nothing when the operator dismisses the prompt', async () => {
    // Changing your mind is not an error, and toasting it would punish an ordinary act.
    harness({ conditional: false });
    const error = new Error('dismissed');
    error.name = 'NotAllowedError';
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { create: vi.fn(), get: vi.fn(() => Promise.reject(error)) },
    });
    renderWithProviders(<PasskeySignIn onSignedIn={vi.fn()} />);

    const button = await screen.findByRole('button', { name: ptPT['signin.passkey.action'] });
    fireEvent.click(button);
    await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.queryByText(ptPT['signin.passkey.error.failed'])).toBeNull();
  });
});
