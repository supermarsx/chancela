/**
 * The passkey arm of the shared step-up gate (t10).
 *
 * Kept in its own file rather than folded into `ConfirmActionModal.test.tsx`: that suite pins the
 * dialog's existing behaviour, and this one pins a proof kind that must not disturb it. The two
 * facts under test are the ones a regression would make invisible — the assertion is collected
 * from the **step-up** ceremony (a sign-in assertion is replayable into a factory reset if that
 * ever slips), and the arm is offered on browser capability alone rather than on whether the
 * account holds a passkey (which the gate cannot ask without building an oracle).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';

const tauriMock = vi.hoisted(() => ({ isTauri: vi.fn(() => false) }));
vi.mock('../desktop/tauri', () => tauriMock);

import { renderWithProviders } from '../test/utils';
import { ptPT } from '../i18n/locales/pt-PT';
import { ConfirmActionModal } from './ConfirmActionModal';
import type { ConfirmActionArgs } from './ConfirmActionModal';

/** A user-verified assertion — flags byte 0x05 is UP | UV. */
function assertion() {
  const authenticatorData = new Uint8Array(37);
  authenticatorData[32] = 0x05;
  return {
    id: 'Y3JlZA',
    rawId: new Uint8Array([1, 2]).buffer,
    type: 'public-key',
    getClientExtensionResults: () => ({}),
    response: {
      clientDataJSON: new Uint8Array([3]).buffer,
      authenticatorData: authenticatorData.buffer,
      signature: new Uint8Array([4]).buffer,
      userHandle: new Uint8Array([5]).buffer,
    },
  };
}

function stubBrowser(get: ReturnType<typeof vi.fn>): void {
  vi.stubGlobal('PublicKeyCredential', function PublicKeyCredential() {});
  Object.defineProperty(navigator, 'credentials', {
    configurable: true,
    value: { create: vi.fn(), get },
  });
}

function stubServer(): ReturnType<typeof vi.fn> {
  const fetchMock = vi.fn((input: RequestInfo | URL) =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          public_key: { challenge: 'CQ', rpId: 'example.pt' },
          purpose: String(input).includes('/reauth/') ? 'step_up' : 'sign_in',
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    ),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function renderDialog(onConfirm: (args: ConfirmActionArgs) => Promise<void>) {
  return renderWithProviders(
    <ConfirmActionModal
      open
      onClose={vi.fn()}
      title="Repor"
      intro={<p>Repor</p>}
      confirmLabel="Repor"
      pendingLabel="A repor…"
      requireReauth
      onConfirm={onConfirm}
    />,
  );
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(navigator, 'credentials');
  tauriMock.isTauri.mockReturnValue(false);
});

describe('the step-up gate’s passkey arm', () => {
  it('collects the assertion from the STEP-UP ceremony, never the sign-in one', async () => {
    // The single most important line in this file. `POST /v1/reauth/passkey/options` mints a
    // challenge bound to this session's user AND to the step-up purpose; a sign-in challenge is
    // not a weaker match, it is not a match. Reaching for the sign-in endpoint would compile, pass
    // a happy-path test, and make every destructive gate satisfiable by a replayed sign-in.
    const get = vi.fn(() => Promise.resolve(assertion()));
    stubBrowser(get);
    const fetchMock = stubServer();
    // Typed parameter, not a bare `vi.fn()`: the assertions below read `mock.calls[0][0]`, and an
    // untyped mock records a zero-length argument tuple that no index can be taken from.
    const onConfirm = vi.fn((_args: ConfirmActionArgs) => Promise.resolve());
    renderDialog(onConfirm);

    fireEvent.click(screen.getByRole('button', { name: ptPT['confirm.reauth.usePasskey'] }));
    fireEvent.click(
      await screen.findByRole('button', { name: ptPT['confirm.reauth.passkey.action'] }),
    );

    await screen.findByText(ptPT['confirm.reauth.passkey.ready']);
    const urls = fetchMock.mock.calls.map(([url]) => String(url));
    expect(urls.some((url) => url.endsWith('/v1/reauth/passkey/options'))).toBe(true);
    expect(urls.some((url) => url.includes('/v1/session/passkey'))).toBe(false);
  });

  it('hands the assertion to the caller under `reauth.passkey`', async () => {
    const get = vi.fn(() => Promise.resolve(assertion()));
    stubBrowser(get);
    stubServer();
    // Typed parameter, not a bare `vi.fn()`: the assertions below read `mock.calls[0][0]`, and an
    // untyped mock records a zero-length argument tuple that no index can be taken from.
    const onConfirm = vi.fn((_args: ConfirmActionArgs) => Promise.resolve());
    renderDialog(onConfirm);

    fireEvent.click(screen.getByRole('button', { name: ptPT['confirm.reauth.usePasskey'] }));
    fireEvent.click(
      await screen.findByRole('button', { name: ptPT['confirm.reauth.passkey.action'] }),
    );
    await screen.findByText(ptPT['confirm.reauth.passkey.ready']);
    fireEvent.click(screen.getByRole('button', { name: 'Repor' }));

    await waitFor(() => expect(onConfirm).toHaveBeenCalled());
    const { reauth } = onConfirm.mock.calls[0][0] as ConfirmActionArgs;
    expect(reauth.passkey?.credential).toBeTruthy();
    // One proof, not three: sending a password field the operator never filled would make the
    // server's uniform 403 ambiguous in the log.
    expect(reauth.password).toBeUndefined();
    expect(reauth.recovery_phrase).toBeUndefined();
  });

  it('does not let the action confirm until an assertion has actually been collected', async () => {
    // Switching to the passkey arm must not be enough on its own; that would be a gate satisfied
    // by clicking a link.
    stubBrowser(vi.fn(() => new Promise(() => {})));
    stubServer();
    renderDialog(vi.fn(() => Promise.resolve()));

    fireEvent.click(screen.getByRole('button', { name: ptPT['confirm.reauth.usePasskey'] }));
    await screen.findByRole('button', { name: ptPT['confirm.reauth.passkey.action'] });
    expect((screen.getByRole('button', { name: 'Repor' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it('discards a gathered assertion when the operator switches proof kind', async () => {
    // The proof kinds are alternatives, not an accumulation: carrying the assertion across a
    // switch would let a half-filled password field submit alongside it.
    const get = vi.fn(() => Promise.resolve(assertion()));
    stubBrowser(get);
    stubServer();
    // Typed parameter, not a bare `vi.fn()`: the assertions below read `mock.calls[0][0]`, and an
    // untyped mock records a zero-length argument tuple that no index can be taken from.
    const onConfirm = vi.fn((_args: ConfirmActionArgs) => Promise.resolve());
    renderDialog(onConfirm);

    fireEvent.click(screen.getByRole('button', { name: ptPT['confirm.reauth.usePasskey'] }));
    fireEvent.click(
      await screen.findByRole('button', { name: ptPT['confirm.reauth.passkey.action'] }),
    );
    await screen.findByText(ptPT['confirm.reauth.passkey.ready']);

    fireEvent.click(screen.getByRole('button', { name: ptPT['confirm.reauth.usePassword'] }));
    expect((screen.getByRole('button', { name: 'Repor' }) as HTMLButtonElement).disabled).toBe(
      true,
    );

    fireEvent.change(screen.getByLabelText(ptPT['confirm.reauth.password']), {
      target: { value: 'palavra-passe' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Repor' }));
    await waitFor(() => expect(onConfirm).toHaveBeenCalled());
    const { reauth } = onConfirm.mock.calls[0][0] as ConfirmActionArgs;
    expect(reauth.password).toBe('palavra-passe');
    expect(reauth.passkey).toBeUndefined();
  });

  it('reports a refused ceremony inline and leaves the gate ready to retry', async () => {
    const error = new Error('nope');
    error.name = 'NotSupportedError';
    stubBrowser(vi.fn(() => Promise.reject(error)));
    stubServer();
    renderDialog(vi.fn(() => Promise.resolve()));

    fireEvent.click(screen.getByRole('button', { name: ptPT['confirm.reauth.usePasskey'] }));
    fireEvent.click(
      await screen.findByRole('button', { name: ptPT['confirm.reauth.passkey.action'] }),
    );
    await screen.findByText(ptPT['confirm.reauth.passkey.failed']);
    expect((screen.getByRole('button', { name: 'Repor' }) as HTMLButtonElement).disabled).toBe(
      true,
    );
  });

  it('is absent where a passkey ceremony cannot run', async () => {
    // Offered on browser capability, never on account state — and therefore absent in the desktop
    // shell and in a browser without WebAuthn, where the button could only throw. The password and
    // recovery-phrase arms are untouched.
    tauriMock.isTauri.mockReturnValue(true);
    stubBrowser(vi.fn());
    stubServer();
    renderDialog(vi.fn(() => Promise.resolve()));

    expect(screen.queryByRole('button', { name: ptPT['confirm.reauth.usePasskey'] })).toBeNull();
    expect(screen.getByRole('button', { name: ptPT['confirm.reauth.useRecovery'] })).toBeTruthy();
    expect(screen.getByLabelText(ptPT['confirm.reauth.password'])).toBeTruthy();
  });
});
