/**
 * Sign-in surface (plan t44 §3, R2) — the roster-driven "who are you?" screen the
 * {@link AuthGate} shows whenever users exist but no one is signed in (a fresh boot, a
 * sign-out, or a mid-session 401 that dropped the token). It reads the UNAUTHENTICATED
 * roster (`GET /v1/session/roster`, t45-e1), NOT the auth-gated `GET /v1/users` — that is
 * the whole point: the signed-out roster breaks the chicken-and-egg lockout the t43 audit
 * flagged.
 *
 * Passwordless users sign in with a single click; a `has_secret` user reveals a password
 * prompt. A wrong password is a **401** (shown inline as "palavra-passe incorreta"); a
 * backoff is a **429** whose server message (with the countdown) is surfaced as a toast.
 * A raw 401 is never rendered.
 */
import { useState } from 'react';
import { ApiError } from '../../api/client';
import type { RosterUser } from '../../api/types';
import { useCreateSession, useSessionRoster } from '../../api/hooks';
import { useT } from '../../i18n';
import { Button, Field, Icon, Input, InlineWarning, Loading } from '../../ui';
import { useToast } from '../../ui';

export function SignIn() {
  const t = useT();
  const toast = useToast();
  const roster = useSessionRoster();
  const signIn = useCreateSession();

  const [selected, setSelected] = useState<RosterUser | null>(null);
  const [password, setPassword] = useState('');
  const [wrongPassword, setWrongPassword] = useState(false);

  const users = roster.data?.users ?? [];
  const busy = signIn.isPending;

  function attempt(user: RosterUser, secret?: string) {
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
    if (user.has_secret) {
      setSelected(user);
      setPassword('');
      setWrongPassword(false);
    } else {
      attempt(user);
    }
  }

  return (
    <div className="signin">
      <div className="signin__card">
        <p className="signin__brand">{t('common.brand')}</p>
        <h1 className="signin__title">{t('signin.title')}</h1>
        <p className="signin__subtitle">{t('signin.subtitle')}</p>

        {roster.isLoading ? (
          <Loading />
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
          <InlineWarning tone="info">{t('signin.empty')}</InlineWarning>
        ) : (
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
                {u.has_secret ? (
                  <span className="signin__user-lock" title={t('signin.requiresPassword')}>
                    <Icon.Seal />
                    <span className="sr-only">{t('signin.requiresPassword')}</span>
                  </span>
                ) : null}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
