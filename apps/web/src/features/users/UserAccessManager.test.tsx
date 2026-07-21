/**
 * A rejected credential proof must NOT sign the operator out (t6).
 *
 * The self-service secret/recovery/attestation-key endpoints answer a wrong or missing
 * `current_password` with a 401 (`verify_current` → `ApiError::Unauthorized`). Before the
 * `isCredentialProofPath` guard in `api/client.ts`, that 401 was indistinguishable from an
 * expired session: the token was cleared and a mere typo ejected the operator from the app,
 * so the inline-refusal branch here could never run. These cases pin the corrected outcome —
 * a field-level error, a session that stays live.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, screen, waitFor } from '@testing-library/react';
import { renderWithProviders } from '../../test/utils';
import { UserAccessManager } from './UserAccessManager';
import { clearSessionToken, getSessionToken, setSessionToken } from '../../api/session';
import type { UserView } from '../../api/types';

/** The signed-in operator, editing their OWN access (self-service → the 401 path). */
const AMELIA: UserView = {
  id: 'u1',
  username: 'amelia.marques',
  display_name: 'Amélia Marques',
  created_at: '2026-07-07T12:00:00Z',
  active: true,
  has_secret: true,
  has_attestation_key: false,
  has_recovery_phrase: false,
  language: 'auto',
};

const WRONG_PASSWORD = 'palavra-passe atual incorreta';

/** Resolve the session as AMELIA herself and refuse the given endpoint with the 401. */
function stubSelfServiceRefusal(endpoint: string): typeof fetch {
  return ((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.endsWith('/v1/session')) {
      return Promise.resolve(
        new Response(JSON.stringify({ user: AMELIA }), {
          headers: { 'Content-Type': 'application/json' },
        }),
      );
    }
    const status = url.includes(endpoint) && (init?.method ?? 'GET') !== 'GET' ? 401 : 200;
    return Promise.resolve(
      new Response(JSON.stringify(status === 401 ? { error: WRONG_PASSWORD } : AMELIA), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as typeof fetch;
}

/** The current-password input of a specific block (several share the same label). */
function passwordFieldOf(id: string): HTMLInputElement {
  const field = screen
    .getAllByLabelText('Palavra-passe atual')
    .find((el) => (el as HTMLInputElement).id === id);
  if (!field) throw new Error(`no current-password field ${id}`);
  return field as HTMLInputElement;
}

afterEach(() => {
  cleanup();
  clearSessionToken();
  vi.restoreAllMocks();
});

describe('UserAccessManager — a wrong current password is a field error, not a sign-out', () => {
  it('refuses a self-service recovery issuance inline and keeps the session', async () => {
    vi.stubGlobal('fetch', stubSelfServiceRefusal('/recovery'));
    setSessionToken('live-session');

    renderWithProviders(<UserAccessManager user={AMELIA} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Gerar frase de recuperação' }));
    fireEvent.change(passwordFieldOf('rec-cur-u1'), { target: { value: 'errada' } });
    fireEvent.click(screen.getByRole('button', { name: 'Gerar frase' }));

    // Inline, next to the field — and the field stays present so the operator can retry.
    expect(await screen.findByText('Palavra-passe incorreta.')).toBeTruthy();
    expect(passwordFieldOf('rec-cur-u1')).toBeTruthy();
    // The server's PT message still surfaces as a toast.
    expect(await screen.findByText(new RegExp(WRONG_PASSWORD))).toBeTruthy();
    // The whole point: the operator is still signed in.
    expect(getSessionToken()).toBe('live-session');
  });

  it('refuses a self-service password change inline and keeps the session', async () => {
    vi.stubGlobal('fetch', stubSelfServiceRefusal('/secret'));
    setSessionToken('live-session');

    renderWithProviders(<UserAccessManager user={AMELIA} />);

    fireEvent.click(await screen.findByRole('button', { name: 'Alterar' }));
    fireEvent.change(passwordFieldOf('sec-cur-u1'), { target: { value: 'errada' } });
    fireEvent.change(screen.getByLabelText('Nova palavra-passe'), {
      target: { value: 'novapalavra1' },
    });
    fireEvent.change(screen.getByLabelText('Confirmar palavra-passe'), {
      target: { value: 'novapalavra1' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Guardar' }));

    expect(await screen.findByText('Palavra-passe incorreta.')).toBeTruthy();
    await waitFor(() => expect(getSessionToken()).toBe('live-session'));
  });
});
