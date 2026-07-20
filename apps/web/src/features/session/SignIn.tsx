/**
 * Sign-in surface (plan t44 §3, R2; reworked by t33) — the "who are you?" screen the
 * {@link AuthGate} shows whenever users exist but no one is signed in (a fresh boot, a
 * sign-out, or a mid-session 401 that dropped the token).
 *
 * ## The identifier is TYPED, never picked (t33)
 * This screen used to render the instance's whole roster as a list of buttons. That is
 * **user enumeration**: an unauthenticated visitor learned every real username, which is
 * precisely the input a credential-stuffing or spear-phishing attempt needs. The username
 * is now typed into a plain `<input name="username" autocomplete="username">` — a real
 * text field, not a disguised select, so password managers and browser autofill work.
 *
 * The only names shown back are the ones that have **successfully signed in on this
 * device**, kept in localStorage by {@link recentAccounts} and removable one at a time.
 * They are a convenience, never a requirement: typing works with the list empty, absent,
 * or storage disabled.
 *
 * ## The server resolves the identifier (t33-e2 — the gap t33 reported is CLOSED)
 * `POST /v1/session` now takes `{username, password}` and resolves the identifier itself,
 * answering one opaque `401 "credenciais inválidas"` for an unknown username, an inactive
 * user and a wrong password alike — same wording and the same argon2 work, so neither the
 * body nor the timing distinguishes them. This screen therefore does **no** client-side
 * identifier→id lookup, and `GET /v1/session/roster` no longer returns any user data at
 * all (just `onboarding_required`), so `curl`ing it enumerates nothing.
 *
 * A failed sign-in and an unknown username produce the SAME message
 * (`signin.badCredentials`) — distinguishing them would hand back the enumeration oracle
 * the typed field just removed. A no-password legacy account (409) and a backoff (429)
 * still surface the server's own PT message. A raw 401 is never rendered.
 *
 * ## "Criar novo utilizador" from the entry screen (plan t50 W3)
 * Unchanged: `POST /v1/users` is bootstrap-only when signed out (allowed unauthenticated
 * ONLY while zero users exist, otherwise it 401s "sessão requerida", t41), so an empty
 * roster offers the genuine bootstrap create and a populated one routes honestly back to
 * sign-in rather than faking a create that would 401.
 */
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../../api/client';
import type { UserView } from '../../api/types';
import { keys, useCreateSession, useSessionRoster } from '../../api/hooks';
import { setSessionToken } from '../../api/session';
import { useT } from '../../i18n';
import { Button, Field, Icon, Input, InlineWarning, Loading, Toggle } from '../../ui';
import { useToast } from '../../ui';
import { UserCreateForm } from '../users/UserCreateForm';
import { forgetAccount, readRecentAccounts, rememberAccount } from './recentAccounts';

/**
 * `form` — the typed sign-in form (default); `create` — the bootstrap create form (empty
 * roster only); `blocked` — honest "sign in first" copy for the has-users signed-out case.
 */
type Mode = 'form' | 'create' | 'blocked';

export function SignIn() {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const roster = useSessionRoster();
  const signIn = useCreateSession();

  const [mode, setMode] = useState<Mode>('form');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [failed, setFailed] = useState(false);
  const [remember, setRemember] = useState(true);
  const [recents, setRecents] = useState(() => readRecentAccounts());
  const [bootstrapping, setBootstrapping] = useState(false);

  const busy = signIn.isPending;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setFailed(false);
    const identifier = username.trim();
    if (identifier.length === 0 || password.length === 0) return;

    // The identifier goes to the server as typed (it matches case-insensitively). No
    // client-side existence check: there is no list to check against any more, and the
    // server's failure is identical whether or not the account exists.
    signIn.mutate(
      { username: identifier, password },
      {
        onSuccess: (result) => {
          // ONLY here — a failed attempt must never be recorded, or the recents list
          // becomes an "is this a real username" oracle. `remember` is the shared/kiosk
          // opt-out. The display name comes from the sign-in response, i.e. only after
          // the password proved out.
          if (remember) {
            setRecents(
              rememberAccount({
                username: result.user.username,
                displayName: result.user.display_name,
              }),
            );
          }
          toast.success(t('toast.signin.success'));
        },
        onError: (err) => {
          // 401 → wrong credentials (inline, deliberately ambiguous); anything else
          // (409 no-password account, 429 backoff…) → the server's PT message via toast.
          // Never surface a raw 401.
          if (err instanceof ApiError && err.status === 401) {
            setFailed(true);
          } else {
            toast.error(err);
          }
        },
      },
    );
  }

  /** Fill the field from a remembered identifier — a shortcut for typing, not a picker. */
  function fillFrom(identifier: string) {
    setUsername(identifier);
    setFailed(false);
    document.getElementById('signin-pw')?.focus();
  }

  /**
   * The bootstrap handshake, run after {@link UserCreateForm} creates the first user
   * (empty-roster case only). It signs in with the just-submitted creation password, primes
   * the `['session']` cache so the AuthGate flips to the app without a refetch round-trip,
   * and invalidates the roster/users. No navigation is needed — the AuthGate re-renders the
   * app chrome as soon as the session is present.
   */
  async function bootstrapSignIn(user: UserView, createdPassword: string) {
    setBootstrapping(true);
    try {
      const result = await api.createSession({ user_id: user.id, password: createdPassword });
      setSessionToken(result.token);
      qc.setQueryData(keys.session, await api.getSession());
      void qc.invalidateQueries({ queryKey: keys.roster });
      void qc.invalidateQueries({ queryKey: keys.users });
      if (remember) {
        setRecents(rememberAccount({ username: user.username, displayName: user.display_name }));
      }
      toast.success(t('toast.signin.bootstrap'));
    } catch (e) {
      // If the roster raced (a user now exists) surface the server's PT message rather than
      // a raw error.
      toast.error(e);
    } finally {
      setBootstrapping(false);
    }
  }

  const title =
    mode === 'create'
      ? t('signin.bootstrap.title')
      : mode === 'blocked'
        ? t('signin.blocked.title')
        : t('signin.title');
  const subtitle =
    mode === 'create'
      ? t('signin.bootstrap.body')
      : mode === 'blocked'
        ? t('signin.blocked.body')
        : t('signin.subtitle');

  return (
    <div className="signin">
      <div className="signin__card">
        <p className="signin__brand">{t('common.brand')}</p>
        <h1 className="signin__title">{title}</h1>
        <p className="signin__subtitle">{subtitle}</p>

        {roster.isLoading ? (
          <Loading />
        ) : mode === 'create' ? (
          // Bootstrap create (empty roster). The form owns validation + the inline 409; the
          // host owns success → `bootstrapSignIn`. `POST /v1/users` is genuinely
          // unauthenticated here because the roster is empty.
          <div className="signin__form">
            <UserCreateForm
              autoFocus
              submitLabel={t('signin.bootstrap.submit')}
              onCreated={(user, createdPassword) => void bootstrapSignIn(user, createdPassword)}
            />
            <div className="signin__actions">
              <Button
                type="button"
                variant="ghost"
                disabled={bootstrapping}
                onClick={() => setMode('form')}
              >
                {t('signin.create.back')}
              </Button>
            </div>
          </div>
        ) : mode === 'blocked' ? (
          // Roster present, signed out: creating would 401. Honest routing back to sign-in —
          // no faked create, no raw 401. The subtitle above carries the explanation.
          <div className="signin__form">
            <div className="signin__actions">
              <Button type="button" variant="primary" onClick={() => setMode('form')}>
                {t('signin.blocked.action')}
              </Button>
            </div>
          </div>
        ) : roster.data?.onboarding_required ? (
          // No user exists yet — no dead-end: offer the bootstrap create (the primary win).
          <div className="signin__form">
            <InlineWarning tone="info">{t('signin.empty')}</InlineWarning>
            <div className="signin__alt">
              <Button
                type="button"
                variant="primary"
                icon={<Icon.Plus />}
                onClick={() => setMode('create')}
              >
                {t('signin.createUser')}
              </Button>
            </div>
          </div>
        ) : (
          <>
            <form className="signin__form" onSubmit={submit}>
              <Field label={t('signin.username.label')} htmlFor="signin-user">
                <Input
                  id="signin-user"
                  name="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t('signin.username.placeholder')}
                  autoComplete="username"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  autoFocus
                />
              </Field>
              <Field
                label={t('signin.password.label')}
                htmlFor="signin-pw"
                error={failed ? t('signin.badCredentials') : null}
              >
                <Input
                  id="signin-pw"
                  name="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t('signin.password.placeholder')}
                  autoComplete="current-password"
                />
              </Field>
              <Toggle
                checked={remember}
                onChange={setRemember}
                label={t('signin.remember.label')}
                disabled={busy}
              />
              {busy ? (
                // Sign-in in flight: suppress the action and spin a nice ring in its place
                // until the mutation settles (success lands in the app; an error restores
                // the control below). The label reuses the existing "a entrar…" string.
                <div className="signin__pending" role="status" aria-label={t('signin.submitting')}>
                  <span className="signin__spinner" aria-hidden="true" />
                </div>
              ) : (
                <div className="signin__actions signin__actions--single">
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={username.trim().length === 0 || password.length === 0}
                  >
                    {t('signin.submit')}
                  </Button>
                </div>
              )}
            </form>

            {recents.length > 0 ? (
              // Device-local shortcuts, NOT the instance roster: only accounts that have
              // signed in successfully in this browser. Each row's ✕ is a real focusable
              // button with a spoken name.
              <div className="signin__recents">
                <h2 className="signin__recents-title">{t('signin.recent.title')}</h2>
                <ul className="signin__list">
                  {recents.map((r) => (
                    <li key={r.username} className="signin__recent">
                      <button
                        type="button"
                        className="signin__user"
                        disabled={busy}
                        onClick={() => fillFrom(r.username)}
                      >
                        <span className="signin__user-avatar" aria-hidden="true">
                          {(r.displayName ?? r.username).charAt(0).toUpperCase()}
                        </span>
                        <span className="signin__user-text">
                          {r.displayName ? (
                            <span className="signin__user-name">{r.displayName}</span>
                          ) : null}
                          <code className="mono signin__user-username">{r.username}</code>
                        </span>
                      </button>
                      <button
                        type="button"
                        className="signin__recent-remove"
                        aria-label={t('signin.recent.remove', { username: r.username })}
                        disabled={busy}
                        onClick={() => setRecents(forgetAccount(r.username))}
                      >
                        <Icon.Close />
                      </button>
                    </li>
                  ))}
                </ul>
                <p className="signin__recents-note">{t('signin.recent.note')}</p>
              </div>
            ) : null}

            <div className="signin__alt">
              <Button
                type="button"
                variant="ghost"
                icon={<Icon.Plus />}
                onClick={() => setMode('blocked')}
              >
                {t('signin.createUser')}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
