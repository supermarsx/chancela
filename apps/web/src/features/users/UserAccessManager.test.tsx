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
  has_totp: false,
  two_factor_required: false,
  language: 'auto',
  role_assignments: [],
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

/**
 * t92 — rotation is no longer destructive: the server retains the superseded key's PUBLIC half, so
 * attestations it signed keep verifying (`rotating_the_key_keeps_attestations_the_old_key_signed_
 * verifiable` in `chancela-api`). So there is deliberately NO confirm dialog here — it would be
 * theatre. What must not disappear with it is the explanation: the rotate control has to say what
 * it does, and say it where a screen reader reaches it.
 */
describe('UserAccessManager — the rotate control explains itself', () => {
  /** AMÉLIA with a key already in place, so the rotate/remove affordances render. */
  const KEYED: UserView = {
    ...AMELIA,
    has_attestation_key: true,
    attestation_key_fingerprint: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  };

  /** Record every non-GET request so the test can assert nothing fired before confirmation. */
  function stubRecording(calls: string[]): typeof fetch {
    return ((input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === 'string' ? input : input.toString();
      const method = init?.method ?? 'GET';
      if (method !== 'GET') calls.push(`${method} ${url}`);
      const body = url.endsWith('/v1/session') ? { user: KEYED } : KEYED;
      return Promise.resolve(
        new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } }),
      );
    }) as typeof fetch;
  }

  it('describes the rotate button with copy that matches the retained-key behaviour', async () => {
    const calls: string[] = [];
    vi.stubGlobal('fetch', stubRecording(calls));
    setSessionToken('live-session');

    renderWithProviders(<UserAccessManager user={KEYED} />);

    const rotate = await screen.findByRole('button', { name: 'Rodar chave' });
    // The note is the button's accessible description, not decoration next to it.
    const noteId = rotate.getAttribute('aria-describedby');
    expect(noteId).toBe('key-note-u1');
    const note = document.getElementById(noteId!);
    expect(note?.textContent).toContain('continuam verificáveis');
    expect(note?.textContent).toContain('não permite assinar');

    // And rotating is a single deliberate submit — no dialog, because nothing is destroyed.
    fireEvent.change(passwordFieldOf('key-cur-u1'), { target: { value: 'Segur0-Chave7!' } });
    fireEvent.click(rotate);
    await waitFor(() => expect(calls).toEqual(['POST /v1/users/u1/attestation-key']));
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('offers no rotation note to a user who has no key yet', async () => {
    vi.stubGlobal('fetch', stubRecording([]));
    setSessionToken('live-session');

    renderWithProviders(<UserAccessManager user={AMELIA} />);

    // Nothing has been signed, so there is nothing to explain about superseding it.
    expect(await screen.findByRole('button', { name: 'Gerar chave' })).toBeTruthy();
    expect(document.getElementById('key-note-u1')).toBeNull();
  });
});
