/**
 * Sign-in surface (plan t44 §3, R2) — the roster-driven "who are you?" screen the
 * {@link AuthGate} shows whenever users exist but no one is signed in (a fresh boot, a
 * sign-out, or a mid-session 401 that dropped the token). It reads the UNAUTHENTICATED
 * roster (`GET /v1/session/roster`, t45-e1), NOT the auth-gated `GET /v1/users` — that is
 * the whole point: the signed-out roster breaks the chicken-and-egg lockout the t43 audit
 * flagged.
 *
 * Picking a user reveals a password prompt. A wrong password is a **401** (shown inline
 * as "palavra-passe incorreta"); a legacy no-password account is a **409** and a backoff
 * is a **429**, both surfaced as the server message. A raw 401 is never rendered.
 *
 * ## "Criar novo utilizador" from the entry screen (plan t50 W3)
 * The entry screen offers a create affordance whose honesty depends on the roster — because
 * `POST /v1/users` is **bootstrap-only when signed out** (allowed unauthenticated ONLY while
 * zero users exist; otherwise it 401s "sessão requerida", t41):
 *
 *  - **Empty roster (bootstrap):** the affordance mounts the shared {@link UserCreateForm}
 *    and creates the first user unauthenticated with a password, then signs in with that
 *    password (`createSession` → prime the session cache → invalidate the roster/users)
 *    so the operator lands straight in the app. This is the genuine
 *    unauthenticated win — it replaces the old empty-roster dead-end. (The full onboarding
 *    wizard remains the guided first-run path; this is the lighter "just make a user"
 *    alternative — the two coexist; no wizard logic is duplicated, only its proven sequence
 *    of `api` calls is reused.)
 *  - **Roster present (signed out):** creating a user here would 401, so we do NOT fake it.
 *    The affordance shows honest copy — a new account is created from *within* the app
 *    (Utilizadores › Novo) once signed in — and routes the operator back to sign in first.
 */
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api, ApiError } from '../../api/client';
import type { RosterUser, UserView } from '../../api/types';
import { keys, useCreateSession, useSessionRoster } from '../../api/hooks';
import { setSessionToken } from '../../api/session';
import { useT } from '../../i18n';
import { Button, Field, Icon, Input, InlineWarning, Loading } from '../../ui';
import { useToast } from '../../ui';
import { UserCreateForm } from '../users/UserCreateForm';

/**
 * `roster` — pick an existing user (default); `create` — the bootstrap create form (empty
 * roster only); `blocked` — honest "sign in first" copy for the has-users signed-out case.
 */
type Mode = 'roster' | 'create' | 'blocked';

export function SignIn() {
  const t = useT();
  const toast = useToast();
  const qc = useQueryClient();
  const roster = useSessionRoster();
  const signIn = useCreateSession();

  const [mode, setMode] = useState<Mode>('roster');
  const [selected, setSelected] = useState<RosterUser | null>(null);
  const [password, setPassword] = useState('');
  const [wrongPassword, setWrongPassword] = useState(false);
  const [bootstrapping, setBootstrapping] = useState(false);

  const users = roster.data?.users ?? [];
  const busy = signIn.isPending;

  function attempt(user: RosterUser, secret: string) {
    setWrongPassword(false);
    signIn.mutate(
      { userId: user.id, password: secret },
      {
        onSuccess: () => {
          toast.success(t('toast.signin.success'));
        },
        onError: (e) => {
          // 401 → wrong/missing password (inline); anything else (429 backoff, etc.) →
          // the server's PT message via toast. Never surface a raw 401.
          if (e instanceof ApiError && e.status === 401) {
            setWrongPassword(true);
          } else {
            toast.error(e);
          }
        },
      },
    );
  }

  function pick(user: RosterUser) {
    setSelected(user);
    setPassword('');
    setWrongPassword(false);
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
                onClick={() => setMode('roster')}
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
              <Button type="button" variant="primary" onClick={() => setMode('roster')}>
                {t('signin.blocked.action')}
              </Button>
            </div>
          </div>
        ) : selected ? (
          <form
            className="signin__form"
            onSubmit={(e) => {
              e.preventDefault();
              attempt(selected, password);
            }}
          >
            <p className="signin__as">
              <span className="signin__as-avatar" aria-hidden="true">
                {selected.display_name.charAt(0).toUpperCase()}
              </span>
              <span>
                <strong>{selected.display_name}</strong>
                <code className="mono signin__as-user">{selected.username}</code>
              </span>
            </p>
            <Field
              label={t('signin.password.label')}
              htmlFor="signin-pw"
              error={wrongPassword ? t('signin.wrongPassword') : null}
            >
              <Input
                id="signin-pw"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={t('signin.password.placeholder')}
                autoComplete="current-password"
                autoFocus
              />
            </Field>
            <div className="signin__actions">
              <Button
                type="button"
                variant="ghost"
                disabled={busy}
                onClick={() => setSelected(null)}
              >
                {t('signin.back')}
              </Button>
              <Button type="submit" variant="primary" disabled={busy || password.length === 0}>
                {busy ? t('signin.submitting') : t('signin.submit')}
              </Button>
            </div>
          </form>
        ) : users.length === 0 ? (
          // Empty roster — no dead-end: offer the bootstrap create (the primary win).
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
            <div className="signin__list" role="list">
              {users.map((u) => (
                <button
                  key={u.id}
                  type="button"
                  role="listitem"
                  className="signin__user"
                  disabled={busy}
                  onClick={() => pick(u)}
                >
                  <span className="signin__user-avatar" aria-hidden="true">
                    {u.display_name.charAt(0).toUpperCase()}
                  </span>
                  <span className="signin__user-text">
                    <span className="signin__user-name">{u.display_name}</span>
                    <code className="mono signin__user-username">{u.username}</code>
                  </span>
                  <span className="signin__user-lock" title={t('signin.requiresPassword')}>
                    <Icon.Seal />
                    <span className="sr-only">{t('signin.requiresPassword')}</span>
                  </span>
                </button>
              ))}
            </div>
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
