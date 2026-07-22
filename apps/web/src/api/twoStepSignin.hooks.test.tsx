/**
 * t21-e1 — the two-step sign-in contract on the client: `useCreateSession`'s challenge-vs-token
 * branch, `useCompleteChallenge`, and the walls' private i18n resolver.
 *
 * The load-bearing behaviour under test is the fix for the web lockout: `POST /v1/session` is a union
 * (`SessionResult` with a `token`, or `{ two_factor_challenge }`), and the hook must NOT establish a
 * session on the challenge arm — it has no token yet — while still resolving with the challenge so the
 * caller can prompt for the second factor. `useCompleteChallenge` then establishes the session exactly
 * as a one-step sign-in, priming `keys.session` (so any `required_action` lands in the wall).
 */
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, renderHook } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { api } from './client';
import type { CreateSessionOutcome, SessionResult, SessionView, UserView } from './types';
import { keys, useCompleteChallenge, useCreateSession } from './hooks';
import { clearSessionToken, getSessionToken } from './session';
import { i18nStore } from '../i18n/store';
import { authWallEnglish, authWallPtPT, useAuthWallT } from '../features/session/authWallCopy';

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  clearSessionToken();
  i18nStore.setActiveLocale('pt-PT');
});

function harness() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return { qc, wrapper };
}

const USER = { id: 'u-1', username: 'amelia.marques', display_name: 'Amélia Marques' } as UserView;

const AUTHENTICATED: SessionResult = { token: 'tok-live', user: USER };
const WALLED: SessionResult = {
  token: 'tok-walled',
  user: USER,
  required_action: 'change_password',
};
const CHALLENGE: CreateSessionOutcome = {
  two_factor_challenge: {
    challenge_id: 'ch-1',
    methods: ['totp', 'backup_code'],
    expires_at: '2026-07-22T10:20:00Z',
  },
};
const SESSION_VIEW: SessionView = { user: USER, permissions: [] };

describe('useCreateSession — challenge-vs-token branch', () => {
  it('establishes the session on the authenticated (token) arm', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'createSession').mockResolvedValue(AUTHENTICATED);
    const getSession = vi.spyOn(api, 'getSession').mockResolvedValue(SESSION_VIEW);
    const invalidate = vi.spyOn(qc, 'invalidateQueries');

    const { result } = renderHook(() => useCreateSession(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ username: 'amelia.marques', password: 'pw' });
    });

    expect(getSessionToken()).toBe('tok-live');
    expect(getSession).toHaveBeenCalledTimes(1);
    expect(qc.getQueryData<SessionView>(keys.session)).toEqual(SESSION_VIEW);
    expect(invalidate).toHaveBeenCalledWith({ queryKey: keys.users });
  });

  it('does NOT establish a session on the challenge arm, and resolves with the challenge', async () => {
    const { qc, wrapper } = harness();
    vi.spyOn(api, 'createSession').mockResolvedValue(CHALLENGE);
    const getSession = vi.spyOn(api, 'getSession').mockResolvedValue(SESSION_VIEW);

    const { result } = renderHook(() => useCreateSession(), { wrapper });
    let outcome: CreateSessionOutcome | undefined;
    await act(async () => {
      outcome = await result.current.mutateAsync({ username: 'amelia.marques', password: 'pw' });
    });

    // The bug this fixes: a challenge must not be treated as a completed sign-in.
    expect(getSessionToken()).toBeNull();
    expect(getSession).not.toHaveBeenCalled();
    expect(qc.getQueryData(keys.session)).toBeUndefined();
    // The caller (SignIn) reads the challenge off the resolved mutation to drive the code entry.
    expect(outcome).toBe(CHALLENGE);
    expect(outcome && 'two_factor_challenge' in outcome).toBe(true);
  });
});

describe('useCompleteChallenge', () => {
  it('establishes the session and primes keys.session (so required_action lands in the wall)', async () => {
    const { qc, wrapper } = harness();
    const complete = vi.spyOn(api, 'completeChallenge').mockResolvedValue(WALLED);
    const walledView: SessionView = {
      user: USER,
      permissions: [],
      required_action: 'change_password',
    };
    vi.spyOn(api, 'getSession').mockResolvedValue(walledView);

    const { result } = renderHook(() => useCompleteChallenge(), { wrapper });
    await act(async () => {
      await result.current.mutateAsync({ challenge_id: 'ch-1', code: '123456' });
    });

    expect(complete).toHaveBeenCalledWith({ challenge_id: 'ch-1', code: '123456' });
    expect(getSessionToken()).toBe('tok-walled');
    expect(qc.getQueryData<SessionView>(keys.session)?.required_action).toBe('change_password');
  });
});

describe('auth-wall pane i18n resolver', () => {
  it('keeps the pt-PT source and English fallback in lockstep on keys', () => {
    expect(Object.keys(authWallEnglish).sort()).toEqual(Object.keys(authWallPtPT).sort());
  });

  it('serves pt-PT source copy and the English fallback for every other locale', () => {
    i18nStore.setActiveLocale('pt-PT');
    const pt = renderHook(() => useAuthWallT());
    expect(pt.result.current('signin.challenge.title')).toBe('Verificação em dois passos');
    cleanup();

    i18nStore.setActiveLocale('en-US');
    const en = renderHook(() => useAuthWallT());
    expect(en.result.current('signin.challenge.title')).toBe('Two-step verification');
  });
});
