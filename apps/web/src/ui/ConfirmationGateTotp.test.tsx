/**
 * The TOTP arm of the shared step-up gate (t10 follow-on).
 *
 * Two facts a regression would make invisible:
 *  - the arm is offered ONLY when the acting account holds a confirmed second factor (`has_totp`),
 *    the held-state `UserView` already publishes — unlike the passkey arm, offered on browser
 *    capability alone because asking whether an account holds one is an enumeration oracle;
 *  - the step-up method PREFERENCE selects which arm the gate opens on, even when the preference
 *    finishes loading after the dialog is already open, and a live code is handed to the caller
 *    under `reauth.totp_code`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';

const tauriMock = vi.hoisted(() => ({ isTauri: vi.fn(() => false) }));
vi.mock('../desktop/tauri', () => tauriMock);

import { renderWithProviders, fetchTable } from '../test/utils';
import { ptPT } from '../i18n/locales/pt-PT';
import { ConfirmActionModal } from './ConfirmActionModal';
import type { ConfirmActionArgs } from './ConfirmActionModal';
import type { StepUpMethodPreference } from '../api/types';

function stubSession(hasTotp: boolean, method: StepUpMethodPreference | null) {
  vi.stubGlobal(
    'fetch',
    fetchTable([
      {
        match: '/v1/session',
        body: {
          user: {
            id: 'u1',
            username: 'amelia.marques',
            display_name: 'Amélia Marques',
            has_totp: hasTotp,
            has_secret: true,
          },
          permissions: [],
        },
      },
      {
        match: '/v1/me/preferences',
        body: {
          table_columns: {},
          ...(method ? { step_up_method: method } : {}),
        },
      },
    ]),
  );
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
});

describe('the step-up gate’s TOTP arm', () => {
  it('opens on the TOTP arm when that is the preference, and hands the code to the caller', async () => {
    stubSession(true, 'totp_code');
    const onConfirm = vi.fn((_args: ConfirmActionArgs) => Promise.resolve());
    renderDialog(onConfirm);

    // The preference loads after the dialog is already open; the arm still lands on TOTP.
    const input = await screen.findByLabelText(ptPT['confirm.reauth.totp']);
    fireEvent.change(input, { target: { value: '123456' } });
    fireEvent.click(screen.getByRole('button', { name: 'Repor' }));

    await waitFor(() => expect(onConfirm).toHaveBeenCalled());
    const { reauth } = onConfirm.mock.calls[0][0] as ConfirmActionArgs;
    expect(reauth.totp_code).toBe('123456');
    // One proof, not several — a stray password/passkey field would make the server's uniform 403
    // ambiguous in the log.
    expect(reauth.password).toBeUndefined();
    expect(reauth.passkey).toBeUndefined();
  });

  it('offers a switch to the TOTP arm when the account holds a confirmed factor', async () => {
    stubSession(true, null);
    renderDialog(vi.fn(() => Promise.resolve()));
    // No preference → opens on password, but the TOTP method is reachable because `has_totp` is true.
    expect(
      await screen.findByRole('button', { name: ptPT['confirm.reauth.useTotp'] }),
    ).toBeTruthy();
  });

  it('never offers the TOTP arm to an account with no confirmed factor', async () => {
    stubSession(false, null);
    renderDialog(vi.fn(() => Promise.resolve()));
    // The password arm is present; the TOTP switch is not, and no read ever asked "do you have one?".
    await screen.findByLabelText(ptPT['confirm.reauth.password']);
    expect(screen.queryByRole('button', { name: ptPT['confirm.reauth.useTotp'] })).toBeNull();
  });
});
